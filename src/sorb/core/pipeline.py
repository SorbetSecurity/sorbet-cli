"""Scan pipeline orchestration — deliberately simple single-process execution.

acquire → walk → detect → ingest → reconcile → drift → finalize. Every stage
feeds the progress bus; detector failures degrade to `analysis-gap`
annotations, never a dead scan.

Container targets (image:/oci-dir:/docker-archive:/docker:/podman:/
containerd:/container://) are dispatched to `sorb.core.container_scan`;
directory and file targets run the flow below.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from sorb import __version__
from sorb.catalogers.base import CatalogerContext, dispatch, registered
from sorb.core.config import Config
from sorb.core.detect_cache import CachedDetect, DetectCache, build_detect_cache
from sorb.core.events import (
    FindingCount,
    ProgressBus,
    ScanStarted,
    StageCompleted,
    StageProgress,
    WarningRaised,
)
from sorb.core.reconcile import ReconcileStats, reconcile
from sorb.core.workspace import new_run_id, register_run, results_dir_for
from sorb.errors import DetectorFailure
from sorb.graph.store import GraphStore
from sorb.model import EdgeType, Finding, ProjectClaim
from sorb.source import open_target
from sorb.source.base import Entry, Source


@dataclass
class ScanResult:
    store_path: Path
    run_id: str
    subject: str
    serial: str
    stats: ReconcileStats
    files_walked: int = 0
    findings: int = 0
    warnings: list[tuple[str, str]] = field(default_factory=list)
    gaps: int = 0
    profile: dict[str, float] = field(default_factory=dict)

    @property
    def had_scan_errors(self) -> bool:
        return self.gaps > 0


def detectors_fingerprint() -> str:
    return ",".join(sorted(c.detector for c in registered()))


def register_configured_plugins(target: Path) -> list[tuple[str, str]]:
    """Register the out-of-process plugin tiers a project's sorb.toml declares.

    Entry-point plugins arrive by installation; WASM and gRPC catalogers are
    only run when the project asked for them by name.
    """
    from sorb.catalogers.base import register
    from sorb.plugin.config import load_configured_plugins

    catalogers, warnings = load_configured_plugins(target)
    for cataloger in catalogers:
        register(cataloger)
    return warnings


def follow_images(store: GraphStore, config: Config) -> tuple[int, list[tuple[str, str]]]:
    """Chase image refs discovered by IaC catalogers into container scans.

    For each distinct ``follow-target`` image, acquire + scan it and graft its
    components as CONTAINS children of the image component. Unreachable images
    (offline / private registry) degrade to an annotation, never a failure.
    """
    import tempfile

    from sorb.container import parse_container_spec
    from sorb.core.container_scan import run_container_scan
    from sorb.errors import SorbError

    targets: dict[str, int] = {}  # image ref → image component id
    for comp in store.components():
        ref = comp.attrs.get("follow-target")
        if ref and comp.attrs.get("ecosystem") == "oci" and not comp.attrs.get("excluded"):
            targets.setdefault(str(ref), comp.id)

    followed = 0
    warnings: list[tuple[str, str]] = []
    for ref, image_cid in sorted(targets.items()):
        spec = parse_container_spec(f"image:{ref}")
        if spec is None:
            continue
        try:
            with tempfile.TemporaryDirectory(prefix="sorb-follow-") as tmp:
                sub_bus = ProgressBus()
                result = run_container_scan(
                    spec, config, sub_bus, store_path=Path(tmp) / "follow.sorb.db"
                )
                sub = GraphStore.open_readonly(result.store_path)
                try:
                    for c in sub.components():
                        if c.attrs.get("excluded") or c.ctype == "resource":
                            continue
                        new_cid = store.add_component(
                            purl=c.purl, ctype=c.ctype, name=c.name, version=c.version,
                            qualifiers=c.qualifiers, hashes=c.hashes, confidence=c.confidence,
                            tier_cap=c.tier_cap,
                            attrs={**c.attrs, "from_followed_image": ref},
                        )
                        store.add_edge(EdgeType.CONTAINS, image_cid, new_cid)
                finally:
                    sub.close()
            followed += 1
        except SorbError as e:
            store.add_annotation(
                "component", image_cid, "follow-image-unreachable",
                f"--follow-images: {ref} could not be scanned ({e})",
            )
            warnings.append(("SORB-W062", f"--follow-images: {ref} unreachable: {e}"))
    store.commit()
    return followed, warnings


def run_native_resolution(
    target_path: Path,
    source_id: str,
    config: Config,
    bus: ProgressBus,
) -> tuple[list[Finding], list[tuple[str, str]]]:
    """Run the applicable native driver (sandboxed) and bridge its output to
    locked-tier Findings. Degrades to no findings + a warning when the sandbox
    or toolchain is unavailable — never a guess."""
    import tempfile

    from sorb.dynamic.drivers import driver_for, run_native_driver
    from sorb.dynamic.drivers.bridge import native_resolution_to_findings
    from sorb.errors import SorbError

    driver = driver_for(target_path)
    if driver is None:
        return [], [("SORB-W015", f"--resolve=native: no native driver matches {target_path}")]
    warnings: list[tuple[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="sorb-native-") as tmp:
        try:
            resolution = run_native_driver(
                driver,
                target_path,
                scratch_home=Path(tmp) / "home",
                allow_net_hosts=config.allow_net,
                dangerously_no_sandbox=config.dangerously_no_sandbox,
            )
        except SorbError as e:
            return [], [("SORB-W015", f"--resolve=native ({driver.id}): {e}")]
        for w in resolution.warnings:
            warnings.append(("SORB-W015", w))
        findings = native_resolution_to_findings(resolution, ".", source_id)
    return findings, warnings


@dataclass
class EntryDetectResult:
    """Everything one entry produced: findings, warnings, analysis gaps."""

    findings: list[Finding] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)  # human detail strings


def detect_entry(
    source: Source,
    entry: Entry,
    blob: bytes,
    config: Config,
    projects: list[ProjectClaim],
    cache: DetectCache | None = None,
    blob_digest: str | None = None,
) -> EntryDetectResult:
    """Run every matching cataloger over one entry (shared by all flows).

    Failures are contained per file/detector: they land as gap
    details on the result, never as exceptions. With an incremental `cache`, an
    unchanged entry replays its cached findings and skips the parse.
    """
    dispatched = dispatch(entry)
    cache_key: str | None = None
    if cache is not None and blob_digest is not None and dispatched:
        cache_key = cache.key(
            entry.path, blob_digest, [c.detector for c in dispatched], config.fingerprint()
        )
        cached = cache.get(cache_key)
        if cached is not None:
            hit = EntryDetectResult()
            hit.findings = list(cached.findings)
            hit.warnings = list(cached.warnings)
            hit.gaps = list(cached.gaps)
            return hit

    result = EntryDetectResult()
    projects_before = len(projects)
    for cataloger in dispatched:
        ctx = CatalogerContext(
            source=source,
            detector=cataloger.detector,
            env_matrix=config.env_matrix,
            evidence_level=config.evidence,
            projects=projects,
        )
        try:
            result.findings.extend(cataloger.parse(ctx, entry, blob))
        except DetectorFailure as e:
            result.gaps.append(f"{entry.path}: {cataloger.detector} failed: {e}")
            result.warnings.append(("SORB-W001", f"{entry.path}: {cataloger.detector} failed"))
        except Exception as e:  # containment: one file, one detector (R4)
            result.gaps.append(
                f"{entry.path}: {cataloger.detector} crashed: {type(e).__name__}: {e}"
            )
            result.warnings.append(("SORB-W001", f"{entry.path}: {cataloger.detector} crashed"))
        result.warnings.extend(ctx.warnings)

    # Only cache when the parse had no un-replayable side effect (project
    # declaration): a cache hit skips parse, so it must not have declared one.
    if cache is not None and cache_key is not None and len(projects) == projects_before:
        cache.put(cache_key, CachedDetect(
            findings=list(result.findings), warnings=list(result.warnings), gaps=list(result.gaps),
        ))
    return result


def init_store(
    store_path: Path,
    *,
    source_id: str,
    source_kind: str,
    source_ref: str,
    provenance_facts: dict[str, str],
    subject: str,
    target_spec: str,
    config: Config,
    run_id: str,
) -> GraphStore:
    store = GraphStore.create(store_path)
    store.add_source(source_id, source_kind, source_ref, dict(provenance_facts))
    store.set_meta("subject", subject)
    store.set_meta("target", target_spec)
    store.set_meta("sorb_version", __version__)
    store.set_meta("config_fingerprint", config.fingerprint())
    store.set_meta("detectors", json.dumps(sorted(c.detector for c in registered())))
    store.set_meta("run_id", run_id)
    return store


def finalize_store(
    store: GraphStore,
    *,
    results_dir: Path,
    subject: str,
    run_id: str,
    config: Config,
    profile: dict[str, float],
) -> str:
    """Serial + lineage + meta, shared by every flow. Returns the serial."""
    from sorb.emit.canonical import content_serial

    serial = content_serial(store)
    reason, superseded, doc_version = register_run(
        results_dir, subject, run_id, serial, detectors_fingerprint()
    )
    store.set_meta("serial", serial)
    # An identical re-scan IS the same document (same serial) — its emitted
    # metadata must be identical too; the lineage registry keeps the rescan fact.
    store.set_meta(
        "reissue_reason", "initial" if reason.startswith("identical") else reason
    )
    store.set_meta("doc_version", str(doc_version))
    if superseded:
        store.set_meta("supersedes_serial", superseded)
    if config.profile:
        store.set_meta("profile", json.dumps(profile, sort_keys=True))
    store.commit()
    return serial


def run_scan(
    target_spec: str,
    config: Config,
    bus: ProgressBus | None = None,
    base: Path | None = None,
    store_path: Path | None = None,
) -> ScanResult:
    bus = bus or ProgressBus()

    # Select the native-acceleration tier for this scan. The pure-Python
    # reference always produces byte-identical output; `--no-accel` forces it.
    from sorb.accel import load_accelerator, set_accelerator

    set_accelerator(load_accelerator(no_accel=config.no_accel))

    from sorb.container import parse_container_spec

    container = parse_container_spec(target_spec)
    if container is not None:
        from sorb.core.container_scan import run_container_scan

        return run_container_scan(container, config, bus, store_path=store_path)

    return _run_dir_scan(target_spec, config, bus, base=base, store_path=store_path)


def _run_dir_scan(
    target_spec: str,
    config: Config,
    bus: ProgressBus,
    base: Path | None = None,
    store_path: Path | None = None,
) -> ScanResult:
    t0 = time.monotonic()
    profile: dict[str, float] = {}

    source = open_target(target_spec, base=base)
    src_ref = source.root()
    provenance = source.provenance()
    subject = provenance.subject
    bus.emit(ScanStarted(target=target_spec, subject=subject))

    target_path = Path(src_ref.ref)
    plugin_warnings = register_configured_plugins(target_path)
    results_dir = results_dir_for(target_path if src_ref.kind == "dir" else None)
    run_id = new_run_id()
    if store_path is None:
        store_path = results_dir / f"{run_id}.sorb.db"
    store = init_store(
        Path(store_path),
        source_id=src_ref.id,
        source_kind=src_ref.kind,
        source_ref=src_ref.ref,
        provenance_facts=dict(provenance.facts),
        subject=subject,
        target_spec=target_spec,
        config=config,
        run_id=run_id,
    )

    # ---- walk + detect --------------------------------------------------------
    t_walk = time.monotonic()
    findings: list[tuple[int, Finding]] = []
    projects: list[ProjectClaim] = []
    warnings: list[tuple[str, str]] = list(plugin_warnings)
    for code, message in plugin_warnings:
        bus.emit(WarningRaised(code=code, message=message))
    files_walked = 0
    gaps = 0
    ecosystems: set[str] = set()
    cache = build_detect_cache(
        enabled=config.cache, remote_url=config.remote_cache, offline=config.offline
    )

    for entry in source.walk():
        files_walked += 1
        if files_walked % 500 == 0:
            bus.emit(FindingCount(files_walked=files_walked, findings=len(findings)))
        if not dispatch(entry):
            continue
        try:
            blob = source.open(entry.path)
        except OSError as e:
            gaps += 1
            store.add_annotation("run", 0, "analysis-gap", f"{entry.path}: unreadable ({e})")
            continue
        digest = source.digest(entry.path)
        store.add_file(src_ref.id, entry.path, digest, entry.size, entry.role)
        result = detect_entry(source, entry, blob, config, projects, cache=cache, blob_digest=digest)
        for finding in result.findings:
            fid = store.add_finding(finding)
            findings.append((fid, finding))
            if finding.claim.ecosystem:
                ecosystems.add(finding.claim.ecosystem)
        for detail in result.gaps:
            gaps += 1
            store.add_annotation("run", 0, "analysis-gap", detail)
            bus.emit(
                WarningRaised(
                    code="SORB-W001",
                    message=f"{detail.split(':', 1)[0]} could not be fully analysed",
                )
            )
        for code, message in result.warnings:
            warnings.append((code, message))
            if code != "SORB-W001":
                bus.emit(WarningRaised(code=code, message=message))
    store.commit()
    profile["walk_detect_s"] = round(time.monotonic() - t_walk, 3)
    bus.emit(
        StageCompleted(
            stage="walk",
            duration_s=profile["walk_detect_s"],
            detail=f"{files_walked:,} files walked · {len(ecosystems)} ecosystems found "
            f"({', '.join(sorted(ecosystems))})" if ecosystems else f"{files_walked:,} files walked",
        )
    )
    if cache is not None:
        cs = cache.stats()
        store.set_meta("cache_stats", json.dumps(cs))
        if cache.remote is not None and not cache.remote.healthy:
            msg = "remote cache unreachable within budget — proceeded without it"
            warnings.append(("SORB-W063", msg))
            bus.emit(WarningRaised(code="SORB-W063", message=msg))  # fail-open, not a failure
        if cs["hits"]:
            bus.emit(StageCompleted(
                stage="cache", duration_s=0.0,
                detail=f"{cs['hits']} detector cache hit(s) "
                f"({cs['remote_hits']} from remote), {cs['stores']} stored",
            ))

    # ---- native resolution (--resolve=native) ----------------------------------
    if config.resolve == "native":
        t_native = time.monotonic()
        native_findings, native_warnings = run_native_resolution(
            target_path, src_ref.id, config, bus
        )
        for finding in native_findings:
            fid = store.add_finding(finding)
            findings.append((fid, finding))
            if finding.claim.ecosystem:
                ecosystems.add(finding.claim.ecosystem)
        for code, message in native_warnings:
            warnings.append((code, message))
            bus.emit(WarningRaised(code=code, message=message))
        store.commit()
        profile["native_resolve_s"] = round(time.monotonic() - t_native, 3)
        if native_findings:
            bus.emit(
                StageCompleted(
                    stage="resolve",
                    duration_s=profile["native_resolve_s"],
                    detail=f"native mode resolved {len(native_findings)} dependencies "
                    "(locked tier)",
                )
            )

    # ---- reconcile ------------------------------------------------------------
    t_rec = time.monotonic()
    bus.emit(StageProgress(stage="reconcile", count=len(findings)))
    stats = reconcile(
        store,
        findings,
        projects,
        src_ref.id,
        min_confidence=config.min_confidence,
        paranoid=config.paranoid,
        scope_filter=config.scope,
    )
    warnings.extend(stats.warnings)
    for code, message in stats.warnings:
        bus.emit(WarningRaised(code=code, message=message))
    profile["reconcile_s"] = round(time.monotonic() - t_rec, 3)

    # ---- project corrections (sorb.corrections.json) --------------------------
    root = Path(target_spec)
    if root.is_dir():
        from sorb.core.corrections import apply_corrections, load_corrections

        entries = load_corrections(root.resolve())
        if entries:
            t_cor = time.monotonic()
            fps, asserted = apply_corrections(store, entries)
            bus.emit(StageCompleted(
                stage="corrections", duration_s=round(time.monotonic() - t_cor, 3),
                detail=f"{fps} false positive(s) excluded · "
                f"{asserted} asserted component(s) added",
            ))

    counters = store.counters()
    bus.emit(
        StageCompleted(
            stage="reconcile",
            duration_s=profile["reconcile_s"],
            detail=f"{counters['components']} components "
            f"({counters['high_confidence']} high confidence)",
        )
    )

    # ---- live-host augmentation: sub-targets + runtime observation --------------
    if src_ref.kind == "host":
        from sorb.core.host_augment import augment_host
        from sorb.source.host import LiveHostSource

        if isinstance(source, LiveHostSource):
            augment_host(store, source, config, bus)
            # A host walk skips whatever it cannot open. Saying so is the
            # difference between "this machine has 13 packages" and "13 is all
            # I was allowed to see".
            if source.unreadable_count:
                message = (
                    f"host inventory is partial: {source.unreadable_count} location(s) "
                    "could not be read (run with more privilege, or capture the disk "
                    "and scan it with disk://)"
                )
                warnings.append(("SORB-W017", message))
                bus.emit(WarningRaised(code="SORB-W017", message=message))
                store.add_annotation("run", 0, "host-inventory-partial", message)

    # ---- follow images: chase IaC-referenced images into scans -----------------
    if config.follow_images:
        t_follow = time.monotonic()
        n_followed, follow_warnings = follow_images(store, config)
        for code, message in follow_warnings:
            warnings.append((code, message))
            bus.emit(WarningRaised(code=code, message=message))
        profile["follow_images_s"] = round(time.monotonic() - t_follow, 3)
        if n_followed:
            bus.emit(
                StageCompleted(
                    stage="follow-images",
                    duration_s=profile["follow_images_s"],
                    detail=f"followed {n_followed} referenced image(s) into container scans",
                )
            )

    # ---- resolver verify + optional enrichment ----------------------------------
    from sorb.core.enrich import enrich_components, verify_npm_lock_ranges

    for code, message in verify_npm_lock_ranges(store, findings):
        warnings.append((code, message))
        bus.emit(WarningRaised(code=code, message=message))
    if config.enrich and not config.offline:
        from sorb.resolve.provider import RegistryMetadataProvider

        t_enrich = time.monotonic()
        provider = RegistryMetadataProvider(offline=config.offline)
        try:
            n_enriched, enrich_warnings = enrich_components(store, provider)
        finally:
            provider.close()
        for code, message in enrich_warnings:
            warnings.append((code, message))
            bus.emit(WarningRaised(code=code, message=message))
        profile["enrich_s"] = round(time.monotonic() - t_enrich, 3)
        if n_enriched:
            bus.emit(
                StageCompleted(
                    stage="enrich",
                    duration_s=profile["enrich_s"],
                    detail=f"{n_enriched} components annotated from registry metadata",
                )
            )

    serial = finalize_store(
        store,
        results_dir=results_dir,
        subject=subject,
        run_id=run_id,
        config=config,
        profile=profile,
    )
    store.close()

    profile["total_s"] = round(time.monotonic() - t0, 3)
    return ScanResult(
        store_path=Path(store_path),
        run_id=run_id,
        subject=subject,
        serial=serial,
        stats=stats,
        files_walked=files_walked,
        findings=len(findings),
        warnings=warnings,
        gaps=gaps,
        profile=profile,
    )
