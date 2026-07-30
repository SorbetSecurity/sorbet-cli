"""Container scan flow.

acquire → layer index → squash walk+detect (layer-keyed CAS caching) →
package-DB time travel → reconcile → layer attribution (INTRODUCED_BY) →
base-image split → attestation cross-check → runtime observation → finalize.

Layer identity note: everything user-visible (layers table, evidence
coordinates, attribution attrs) uses the **diff_id** (uncompressed digest)
when the config provides it — diff_ids are identical across acquisition paths
(registry / docker-archive / OCI layout), which is what makes the
"identical SBOM across paths" guarantee hold; compressed blob digests are recorded as
acquisition facts only.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from sorb.cache import Cas
from sorb.catalogers.base import dispatch
from sorb.container import ContainerTarget, acquire_image
from sorb.container.attest import AttestedComponent, cross_check
from sorb.container.baseimage import identify_base
from sorb.container.history import LayerHistory, link_dockerfile, link_history
from sorb.container.image import ResolvedImage
from sorb.container.layers import LayerStack, SquashView
from sorb.container.pkgdb_timeline import (
    FamilyKey,
    Snapshot,
    TimelineEvent,
    diff_timeline,
    first_seen,
)
from sorb.core.config import Config
from sorb.core.events import (
    ProgressBus,
    ScanStarted,
    StageCompleted,
    StageProgress,
    WarningRaised,
)
from sorb.core.pipeline import (
    ScanResult,
    detect_entry,
    detectors_fingerprint,
    finalize_store,
    init_store,
)
from sorb.core.reconcile import reconcile
from sorb.core.workspace import new_run_id, results_dir_for
from sorb.graph.store import Component, GraphStore
from sorb.model import (
    EdgeType,
    EvidenceRecord,
    Finding,
    Tier,
    finding_from_dict,
    finding_to_dict,
)

_SOURCE_ID = "s1"


def _layer_identity(image: ResolvedImage, ordinal: int) -> str:
    layer = image.layers[ordinal]
    return layer.diff_id or layer.digest


def run_container_scan(
    target: ContainerTarget,
    config: Config,
    bus: ProgressBus,
    *,
    store_path: Path | None = None,
    cas: Cas | None = None,
    transport: Any | None = None,
) -> ScanResult:
    t0 = time.monotonic()
    profile: dict[str, float] = {}
    warnings: list[tuple[str, str]] = []
    cas = cas if cas is not None else Cas()

    # ---- acquire -----------------------------------------------------------------
    t_acq = time.monotonic()
    image = acquire_image(
        target,
        platform=config.platform,
        offline=config.offline,
        cas=cas,
        transport=transport,
    )
    bus.emit(
        StageProgress(
            stage="pull",
            detail=f"Pulling {image.ref} ({image.platform}, {len(image.layers)} layers)…",
        )
    )
    stack = LayerStack(image)
    squash = SquashView(stack, source_id=_SOURCE_ID)
    profile["acquire_s"] = round(time.monotonic() - t_acq, 3)

    subject = image.subject()
    bus.emit(ScanStarted(target=target.raw, subject=subject))

    results_dir = results_dir_for(None)
    run_id = new_run_id()
    if store_path is None:
        store_path = results_dir / f"{run_id}.sorb.db"
    provenance = squash.provenance()
    store = init_store(
        Path(store_path),
        source_id=_SOURCE_ID,
        source_kind=target.kind,
        source_ref=image.ref,
        provenance_facts=dict(provenance.facts),
        subject=subject,
        target_spec=target.raw,
        config=config,
        run_id=run_id,
    )

    # ---- layers, history, transition log --------------------------------------------
    history = link_history(image.config, len(image.layers))
    dockerfile_text = _load_dockerfile(target, config)
    if dockerfile_text:
        history = link_dockerfile(history, dockerfile_text)
    history_by_ordinal = {h.ordinal: h for h in history}
    for layer in image.layers:
        store.add_layer(
            _layer_identity(image, layer.ordinal),
            _SOURCE_ID,
            layer.ordinal,
            history_by_ordinal[layer.ordinal].created_by or None,
        )
    for t in stack.transitions:
        store.add_file_state(
            _SOURCE_ID,
            t.path,
            _layer_identity(image, t.ordinal),
            t.ordinal,
            t.state,
        )

    # ---- walk + detect over the squash, layer-keyed caching -------------------------
    t_walk = time.monotonic()
    findings: list[tuple[int, Finding]] = []
    files_walked = 0
    gaps = 0
    ecosystems: set[str] = set()
    layer_cache_hits = 0
    layer_cache_misses = 0

    by_layer: dict[int, list[str]] = {}
    for path, ordinal in sorted(squash.owners().items()):
        by_layer.setdefault(ordinal, []).append(path)

    detectors_fp = detectors_fingerprint()
    config_fp = config.fingerprint()

    for ordinal in sorted(by_layer):
        paths = by_layer[ordinal]
        identity = _layer_identity(image, ordinal)
        visibility = hashlib.sha256("\n".join(paths).encode()).hexdigest()[:16]
        cache_key = f"layer-findings:{identity}:{visibility}:{detectors_fp}:{config_fp}"
        cached = cas.get(cache_key)
        if cached is not None:
            layer_cache_hits += 1
            payload = json.loads(cached)
            for row in payload["files"]:
                store.add_file(
                    _SOURCE_ID, row["path"], row["digest"], row["size"], row["role"]
                )
                files_walked += 1
            for fdict in payload["findings"]:
                finding = finding_from_dict(fdict)
                fid = store.add_finding(finding)
                findings.append((fid, finding))
                if finding.claim.ecosystem:
                    ecosystems.add(finding.claim.ecosystem)
            for detail in payload.get("gaps", []):
                gaps += 1
                store.add_annotation("run", 0, "analysis-gap", detail)
            continue

        layer_cache_misses += 1
        payload_files: list[dict[str, Any]] = []
        payload_findings: list[dict[str, Any]] = []
        payload_gaps: list[str] = []
        for path in paths:
            entry = stack.views[ordinal].entry_for(path)
            if entry is None:
                continue
            files_walked += 1
            if not dispatch(entry):
                continue
            try:
                blob = squash.open(path)
            except Exception as e:  # noqa: BLE001 — budget/read failures degrade
                gaps += 1
                detail = f"{path}: unreadable ({e})"
                payload_gaps.append(detail)
                store.add_annotation("run", 0, "analysis-gap", detail)
                continue
            digest = squash.digest(path)
            store.add_file(_SOURCE_ID, path, digest, entry.size, entry.role)
            payload_files.append(
                {"path": path, "digest": digest, "size": entry.size, "role": entry.role}
            )
            result = detect_entry(squash, entry, blob, config, projects=[])
            for finding in result.findings:
                fid = store.add_finding(finding)
                findings.append((fid, finding))
                payload_findings.append(finding_to_dict(finding))
                if finding.claim.ecosystem:
                    ecosystems.add(finding.claim.ecosystem)
            for detail in result.gaps:
                gaps += 1
                payload_gaps.append(detail)
                store.add_annotation("run", 0, "analysis-gap", detail)
                bus.emit(
                    WarningRaised(
                        code="SORB-W001",
                        message=f"{detail.split(':', 1)[0]} could not be fully analysed",
                    )
                )
            for code, message in result.warnings:
                warnings.append((code, message))
        cas.put(
            cache_key,
            json.dumps(
                {"files": payload_files, "findings": payload_findings, "gaps": payload_gaps},
                sort_keys=True,
            ).encode(),
        )

    for reason in stack.budget.exhausted_reasons:
        gaps += 1
        store.add_annotation("run", 0, "analysis-gap", f"archive budget: {reason}")
        warnings.append(("SORB-W001", f"archive budget: {reason}"))

    store.commit()
    profile["walk_detect_s"] = round(time.monotonic() - t_walk, 3)
    profile["layer_cache_hits"] = layer_cache_hits
    profile["layer_cache_misses"] = layer_cache_misses
    bus.emit(
        StageCompleted(
            stage="walk",
            duration_s=profile["walk_detect_s"],
            detail=f"{files_walked:,} files across {len(image.layers)} layers"
            + (f" · {len(ecosystems)} ecosystems ({', '.join(sorted(ecosystems))})" if ecosystems else ""),
        )
    )

    # ---- package-DB time travel: parse DBs as of each layer --------------------------
    t_tt = time.monotonic()
    db_states, old_findings = _pkgdb_states(stack, config)
    profile["pkgdb_timetravel_s"] = round(time.monotonic() - t_tt, 3)

    # ---- reconcile -------------------------------------------------------------------
    t_rec = time.monotonic()
    stats = reconcile(
        store,
        findings,
        [],
        _SOURCE_ID,
        min_confidence=config.min_confidence,
        paranoid=config.paranoid,
        scope_filter=config.scope,
    )
    warnings.extend(stats.warnings)
    for code, message in stats.warnings:
        bus.emit(WarningRaised(code=code, message=message))
    profile["reconcile_s"] = round(time.monotonic() - t_rec, 3)

    # ---- post-reconcile container passes ------------------------------------------------
    components = store.components()

    # layer attribution first (timeline refines pkgdb components below)
    merged_states = _merge_states(db_states)
    _attribute_layers(store, components, squash, image, history_by_ordinal, merged_states)

    timeline_events = _apply_timeline(
        store, components, db_states, old_findings, image, history_by_ordinal, config, warnings
    )

    base = identify_base(
        [_layer_identity(image, i) for i in range(len(image.layers))],
        {**image.annotations, **_config_annotations(image)},
        packs_dir=cas.packs_dir,
    )
    n_base = n_added = 0
    if base is not None:
        store.set_meta("base_image", base.name)
        store.set_meta("base_image_method", base.method)
        if base.digest:
            store.set_meta("base_image_digest", base.digest)
        if base.boundary is not None:
            store.set_meta("base_image_boundary", str(base.boundary))
            n_base, n_added = _split_base_components(store, base.name, base.boundary)
            bus.emit(
                StageCompleted(
                    stage="base-image",
                    duration_s=0.0,
                    detail=f"base image identified: {base.name} "
                    f"(layers 1–{base.boundary})",
                )
            )
        else:
            bus.emit(
                StageCompleted(
                    stage="base-image",
                    duration_s=0.0,
                    detail=f"base image declared by annotation: {base.name} (boundary unknown)",
                )
            )

    n_attest = _cross_check_attestations(store, image, bus, warnings)
    if n_attest:
        store.set_meta("attestations_checked", str(n_attest))

    _observe_running_processes(store, image, bus)

    counters = store.counters()
    summary = f"{counters['components']} components"
    if n_base or n_added:
        summary += f": {n_base} from base image, {n_added} added on top"
    else:
        summary += f" ({counters['high_confidence']} high confidence)"
    bus.emit(StageCompleted(stage="reconcile", duration_s=profile["reconcile_s"], detail=summary))
    if timeline_events:
        for ev in timeline_events:
            if ev.kind == "upgraded":
                bus.emit(
                    WarningRaised(
                        code="SORB-W034",
                        message=f"{ev.name} upgraded {ev.old_version} → {ev.new_version} "
                        f"(layer {ev.old_ordinal + 1} → {ev.new_ordinal + 1})",
                    )
                )
            else:
                bus.emit(
                    WarningRaised(
                        code="SORB-W034",
                        message=f"{ev.name} {ev.old_version} installed in layer "
                        f"{ev.old_ordinal + 1}, deleted in layer {ev.new_ordinal + 1}",
                    )
                )

    profile["cache_hits"] = float(cas.hits)
    profile["cache_misses"] = float(cas.misses)
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


# -- helpers ---------------------------------------------------------------------------


def _load_dockerfile(target: ContainerTarget, config: Config) -> str | None:
    if config.dockerfile:
        p = Path(config.dockerfile)
        if p.is_file():
            return p.read_text(encoding="utf-8", errors="replace")
        return None
    # co-located Dockerfile next to a local archive/layout target
    if target.kind in ("docker-archive", "oci-layout"):
        candidate = Path(target.ref.partition("#")[0]).resolve().parent / "Dockerfile"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8", errors="replace")
    return None


def _config_annotations(image: ResolvedImage) -> dict[str, str]:
    cfg = image.config.get("config") or {}
    labels = cfg.get("Labels") or {}
    return {str(k): str(v) for k, v in labels.items()} if isinstance(labels, dict) else {}


def _pkgdb_states(
    stack: LayerStack, config: Config
) -> tuple[dict[str, dict[int, Snapshot]], dict[tuple[str, FamilyKey, str], Finding]]:
    """Parse every package-DB path as of each layer that wrote it.

    Returns (states per DB path, retained Findings for non-final versions keyed
    by (db_path, family, version)).
    """
    states: dict[str, dict[int, Snapshot]] = {}
    old_findings: dict[tuple[str, FamilyKey, str], Finding] = {}
    db_paths: dict[str, list[int]] = {}
    for t in stack.transitions:
        if t.state in ("added", "modified"):
            entry = stack.views[t.ordinal].entry_for(t.path)
            if entry is None:
                continue
            if any(c.id.startswith("os/") for c in dispatch(entry)):
                db_paths.setdefault(t.path, []).append(t.ordinal)
        elif t.path in db_paths:
            db_paths[t.path].append(-t.ordinal)  # negative marks a removal point

    for path, ordinals in sorted(db_paths.items()):
        writes = [o for o in ordinals if o >= 0]
        removals = [-o for o in ordinals if o < 0]
        if len(writes) <= 1 and not removals:
            continue  # DB written once and never removed: no history to travel
        per_layer: dict[int, Snapshot] = {}
        for ordinal in writes:
            view = stack.views[ordinal]
            entry = view.entry_for(path)
            if entry is None:
                continue
            point_in_time = SquashView(stack, source_id=_SOURCE_ID, upto=ordinal)
            try:
                blob = view.open(path)
            except Exception:  # noqa: BLE001 — budget/read failure = no snapshot
                continue
            result = detect_entry(point_in_time, entry, blob, config, projects=[])
            snapshot: Snapshot = {}
            for finding in result.findings:
                claim = finding.claim
                if claim.ctype != "os-package" or not claim.version:
                    continue
                eco = claim.ecosystem or "os"
                fam: FamilyKey = (eco, claim.name)
                snapshot[fam] = claim.version
                old_findings.setdefault((path, fam, claim.version), finding)
            per_layer[ordinal] = snapshot
        for removed_at in removals:
            per_layer.setdefault(removed_at, {})
        if per_layer:
            states[path] = per_layer
    return states, old_findings


def _merge_states(db_states: dict[str, dict[int, Snapshot]]) -> dict[int, Snapshot]:
    merged: dict[int, Snapshot] = {}
    for per_layer in db_states.values():
        for ordinal, snap in per_layer.items():
            merged.setdefault(ordinal, {}).update(snap)
    return merged


def _attribute_layers(
    store: GraphStore,
    components: list[Component],
    squash: SquashView,
    image: ResolvedImage,
    history_by_ordinal: dict[int, LayerHistory],
    merged_states: dict[int, Snapshot],
) -> None:
    """INTRODUCED_BY → Layer edges + attribution attrs."""
    for comp in components:
        ordinal = _introducing_ordinal(store, comp, squash, merged_states)
        if ordinal is None:
            continue
        attrs = dict(comp.attrs)
        attrs["layer_ordinal"] = ordinal
        attrs["layer"] = _layer_identity(image, ordinal)
        h = history_by_ordinal.get(ordinal)
        if h is not None and h.command:
            attrs["introduced_by"] = h.command
            if h.dockerfile_line is not None:
                attrs["dockerfile_line"] = h.dockerfile_line
        store.update_component_attrs(comp.id, attrs)
        store.add_edge(
            EdgeType.INTRODUCED_BY,
            comp.id,
            store.layer_node_id(ordinal),
            {"ordinal": ordinal},
        )


def _introducing_ordinal(
    store: GraphStore,
    comp: Component,
    squash: SquashView,
    merged_states: dict[int, Snapshot],
) -> int | None:
    # package-DB components: the first layer whose DB carries the final version
    eco = str(comp.attrs.get("ecosystem", ""))
    if comp.ctype == "os-package" and comp.version and merged_states:
        seen = first_seen(merged_states, (eco, comp.name), comp.version)
        if seen is not None:
            return seen
    # otherwise: the earliest layer owning any evidence file of this component
    ordinals: list[int] = []
    for ev in store.evidence_for_component(comp.id):
        path = ev.get("location", {}).get("path")
        if path:
            o = squash.owner_ordinal(str(path))
            if o is not None:
                ordinals.append(o)
    return min(ordinals) if ordinals else None


def _apply_timeline(
    store: GraphStore,
    components: list[Component],
    db_states: dict[str, dict[int, Snapshot]],
    old_findings: dict[tuple[str, FamilyKey, str], Finding],
    image: ResolvedImage,
    history_by_ordinal: dict[int, LayerHistory],
    config: Config,
    warnings: list[tuple[str, str]],
) -> list[TimelineEvent]:
    """Upgrade/removal events → SUPERSEDES chains + state:removed components."""
    all_events: list[TimelineEvent] = []
    by_family: dict[tuple[str, str], Component] = {}
    for comp in components:
        eco = str(comp.attrs.get("ecosystem", ""))
        by_family.setdefault((eco, comp.name), comp)

    for path, per_layer in sorted(db_states.items()):
        for ev in diff_timeline(per_layer):
            all_events.append(ev)
            fam: FamilyKey = (ev.eco, ev.name)
            old_finding = old_findings.get((path, fam, ev.old_version))
            old_cid = _add_historical_component(
                store,
                old_finding,
                ev,
                image,
                config,
            )
            final_comp = by_family.get(fam)
            if ev.kind == "upgraded" and final_comp is not None:
                detail = (
                    f"{ev.old_version} (layer {ev.old_ordinal + 1}) → "
                    f"{ev.new_version} (layer {ev.new_ordinal + 1})"
                )
                store.add_annotation("component", final_comp.id, "pkgdb-upgraded", detail)
                if old_cid is not None:
                    store.add_edge(
                        EdgeType.SUPERSEDES,
                        final_comp.id,
                        old_cid,
                        {"reason": "pkgdb-upgrade", "layer": ev.new_ordinal},
                    )
                warnings.append(("SORB-W034", f"{ev.name}: {detail}"))
            elif ev.kind == "removed" and old_cid is not None:
                h = history_by_ordinal.get(ev.new_ordinal)
                detail = (
                    f"installed in layer {ev.old_ordinal + 1}, deleted in layer "
                    f"{ev.new_ordinal + 1}"
                    + (f" ({h.command})" if h is not None and h.command else "")
                )
                store.add_annotation("component", old_cid, "pkgdb-removed", detail)
                warnings.append(("SORB-W034", f"{ev.name} {ev.old_version}: {detail}"))
    return all_events


def _add_historical_component(
    store: GraphStore,
    finding: Finding | None,
    ev: TimelineEvent,
    image: ResolvedImage,
    config: Config,
) -> int | None:
    """A superseded/removed package version becomes a real, evidence-backed
    component — retained in the graph, excluded from SBOM emission unless
    ``--include-removed`` is set."""
    if finding is None:
        return None
    claim = finding.claim
    state = "removed" if ev.kind == "removed" else "superseded"
    attrs: dict[str, Any] = {
        "ecosystem": claim.ecosystem or ev.eco,
        "state": state,
        "layer_ordinal": ev.old_ordinal,
        "layer": _layer_identity(image, min(ev.old_ordinal, len(image.layers) - 1)),
        "removed_in_layer": ev.new_ordinal,
        "tiers": ["installed"],
        "scope": "runtime",
    }
    if not config.include_removed:
        attrs["excluded"] = f"{state} during image build (--include-removed to emit)"
    confidence = min(
        1.0 - _product_of_disbelief(finding.evidence),
        0.98,
    )
    cid = store.add_component(
        purl=claim.purl,
        ctype=claim.ctype,
        name=claim.name,
        version=claim.version,
        qualifiers=dict(claim.qualifiers),
        hashes=dict(claim.hashes),
        confidence=round(confidence, 4),
        tier_cap=int(Tier.INSTALLED),
        attrs=attrs,
    )
    fid = store.add_finding(finding)
    store.link_finding(fid, cid)
    store.add_edge(
        EdgeType.INTRODUCED_BY,
        cid,
        store.layer_node_id(ev.old_ordinal),
        {"ordinal": ev.old_ordinal},
    )
    return cid


def _product_of_disbelief(evidence: tuple[EvidenceRecord, ...]) -> float:
    prod = 1.0
    for e in evidence:
        prod *= 1.0 - max(0.0, min(1.0, e.confidence))
    return prod


def _split_base_components(store: GraphStore, base_name: str, boundary: int) -> tuple[int, int]:
    """Tag components inherited-from-base vs added. Returns (base, added)."""
    n_base = n_added = 0
    for comp in store.components():
        if comp.attrs.get("excluded"):
            continue
        attrs = dict(comp.attrs)
        ordinal = attrs.get("layer_ordinal")
        if ordinal is None:
            continue
        if int(ordinal) < boundary:
            attrs["from_base_image"] = base_name
            n_base += 1
        else:
            n_added += 1
        store.update_component_attrs(comp.id, attrs)
    return n_base, n_added


def _cross_check_attestations(
    store: GraphStore,
    image: ResolvedImage,
    bus: ProgressBus,
    warnings: list[tuple[str, str]],
) -> int:
    """Verify-ingest of attached SBOM attestations: agreement is
    corroboration, disagreement is a drift finding — never blended results."""
    sbom_docs = [a for a in image.attestations if a.get("kind") in ("cyclonedx", "spdx")]
    if not sbom_docs:
        return 0
    scanned = [
        (c.name, c.version, c.purl)
        for c in store.components()
        if not c.attrs.get("excluded") and not c.attrs.get("state")
    ]
    by_name = {c.name: c for c in store.components()}
    for doc in sbom_docs:
        attested = [
            AttestedComponent(
                name=str(a["name"]),
                version=a.get("version"),
                purl=a.get("purl"),
            )
            for a in doc.get("components", [])
        ]
        result = cross_check(attested, scanned)
        source = str(doc.get("source", "attestation"))
        for claim, scanned_name, scanned_version in result.version_mismatches:
            comp = by_name.get(scanned_name)
            detail = (
                f"attestation ({source}) says {claim.name} {claim.version}, "
                f"image contains {scanned_version}"
            )
            if comp is not None:
                store.add_annotation("component", comp.id, "drift:attestation-mismatch", detail)
            else:
                store.add_annotation("run", 0, "drift:attestation-mismatch", detail)
            warnings.append(("SORB-W033", detail))
            bus.emit(WarningRaised(code="SORB-W033", message=f"drift: {detail}"))
        for claim in result.claimed_not_found:
            version = f"@{claim.version}" if claim.version else ""
            detail = (
                f"attestation ({source}) claims {claim.name}{version} "
                "but the scan found no trace of it in the image"
            )
            store.add_annotation("run", 0, "drift:attestation-mismatch", detail)
            warnings.append(("SORB-W033", detail))
            bus.emit(WarningRaised(code="SORB-W033", message=f"drift: {detail}"))
        for _claim, scanned_name in result.corroborated:
            comp = by_name.get(scanned_name)
            if comp is not None:
                store.add_annotation(
                    "component",
                    comp.id,
                    "attestation-corroborated",
                    f"publisher attestation ({source}) agrees",
                )
        if result.found_not_claimed:
            store.add_annotation(
                "run",
                0,
                "attestation-incomplete",
                f"{len(result.found_not_claimed)} scanned components missing from "
                f"attestation ({source}): "
                + ", ".join(result.found_not_claimed[:10])
                + ("…" if len(result.found_not_claimed) > 10 else ""),
            )
    return len(sbom_docs)


def _observe_running_processes(store: GraphStore, image: ResolvedImage, bus: ProgressBus) -> None:
    """Running containers: live process list → OBSERVED_IN on in-image binaries."""
    facts = image.provenance_facts
    if facts.get("acquisition") != "running-container":
        return
    processes: list[str] = json.loads(facts.get("processes", "[]"))
    entrypoint: list[str] = json.loads(facts.get("entrypoint", "[]"))
    observed_paths: set[str] = set()
    cmdlines = processes + ([" ".join(entrypoint)] if entrypoint else [])
    for cmdline in cmdlines:
        if not cmdline:
            continue
        exe = cmdline.split()[0]
        observed_paths.add(exe.lstrip("/"))
        observed_paths.add(exe.rsplit("/", 1)[-1])

    for comp in store.components():
        evidence = store.evidence_for_component(comp.id)
        paths = {str(ev.get("location", {}).get("path", "")) for ev in evidence}
        paths |= {str(p) for p in comp.attrs.get("instance_paths", [])}
        hit = None
        for p in paths:
            if p in observed_paths or p.rsplit("/", 1)[-1] in {
                o.rsplit("/", 1)[-1] for o in observed_paths
            }:
                hit = p
                break
        if hit is None or comp.ctype not in ("application", "library"):
            continue
        attrs = dict(comp.attrs)
        attrs["scope"] = "runtime-observed"
        store.update_component_attrs(comp.id, attrs)
        store._conn.execute(
            "UPDATE components SET tier_cap=?, confidence=? WHERE id=?",
            (int(Tier.OBSERVED), min(1.0, comp.confidence + 0.01), comp.id),
        )
        store.add_annotation(
            "component",
            comp.id,
            "runtime-observed",
            f"binary {hit} is running in the container right now",
        )
        store.add_edge(EdgeType.OBSERVED_IN, comp.id, store.source_node_id(0), {"via": "process-list"})
