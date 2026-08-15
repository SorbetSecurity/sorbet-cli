"""Native-binary cataloger.

Runs the format adapters over every binary and emits the cheap, near-perfect
embedded ground truth: PE VS_VERSIONINFO identity, an embedded SBOM section
(marked for cross-verification, never blindly trusted), and a frozen-app
marker. Binaries that yield no confident identity land in the **unidentified
inventory** rather than being force-matched — the worklist for the
fingerprint engines and signature-DB growth.
"""

from __future__ import annotations

from collections.abc import Iterable

from sorb.binary.analyze import analyze_binary
from sorb.binary.embedded.extractors import (
    detect_frozen_app,
    extract_embedded_sbom,
    versioninfo_identity,
)
from sorb.binary.formats import ELF_MAGIC, PE_MZ, WASM_MAGIC
from sorb.binary.sigdb import SignatureDB, default_sigdb_path
from sorb.cache import default_cache_dir
from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.catalogers.common import ref_file
from sorb.ident import make_purl
from sorb.model import (
    Annotation,
    ComponentClaim,
    EdgeClaim,
    EdgeType,
    Finding,
    Tier,
)
from sorb.source.base import Entry

_MACHO = (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe")

_SIGDB_LOADED = False
_SIGDB: SignatureDB | None = None


def _sigdb() -> SignatureDB | None:
    """Lazily open the installed signatures pack (None when none installed)."""
    global _SIGDB_LOADED, _SIGDB
    if not _SIGDB_LOADED:
        _SIGDB_LOADED = True
        db_path = default_sigdb_path(default_cache_dir() / "packs")
        if db_path is not None:
            try:
                _SIGDB = SignatureDB.open(db_path)
            except Exception:  # noqa: BLE001 — a bad pack must not break scans
                _SIGDB = None
    return _SIGDB


class NativeBinaryCataloger(Cataloger):
    id = "binary/native"
    version = 1
    matchers = [
        Matcher(magic=ELF_MAGIC),
        Matcher(magic=PE_MZ),
        Matcher(magic=WASM_MAGIC),
        *[Matcher(magic=m) for m in dict.fromkeys(_MACHO)],
    ]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        info = analyze_binary(blob)
        if info is None:
            return
        for warning in info.warnings:
            ctx.warn("SORB-W001", f"{entry.path}: {warning}")

        identified = False

        # 1. PE VS_VERSIONINFO → a real component identity (installed tier)
        identity = versioninfo_identity(info)
        if identity is not None:
            name, version, vendor = identity
            purl = make_purl("generic", name.replace(" ", "-").lower(), version)
            yield Finding(
                claim=ComponentClaim(
                    ctype="application" if info.kind == "exe" else "library",
                    name=name,
                    version=version,
                    purl=purl,
                    ecosystem="generic",
                    attrs=(("vendor", vendor),) if vendor else (),
                ),
                evidence=(
                    ctx.evidence(
                        "binary-versioninfo",
                        Tier.INSTALLED,
                        entry,
                        captured=f"VS_VERSIONINFO: {name} {version}"
                        + (f" ({vendor})" if vendor else ""),
                    ),
                ),
                edges=(
                    EdgeClaim(kind=EdgeType.INSTANCE_OF, src=ref_file(entry.path), dst=f"purl:{purl}"),
                ),
            )
            identified = True

        # 2. embedded SBOM section — ingest for cross-verification, don't trust
        sbom = extract_embedded_sbom(blob, info)
        if sbom is not None:
            yield Finding(
                claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:embedded-sbom"),
                evidence=(
                    ctx.evidence(
                        "embedded-sbom",
                        Tier.DECLARED,
                        entry,
                        captured=f"embedded SBOM in section {sbom.section} "
                        f"({len(sbom.data)} bytes)",
                    ),
                ),
                annotations=(
                    Annotation(
                        code="embedded-sbom-present",
                        subject=ref_file(entry.path),
                        detail=f"{entry.path} carries an embedded SBOM in {sbom.section}; "
                        "cross-verify against scanned findings (trust-but-verify)",
                    ),
                ),
            )

        # 3. frozen-app marker → the bundled inventory should be recovered
        frozen = detect_frozen_app(blob)
        if frozen is not None:
            yield Finding(
                claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:frozen"),
                evidence=(
                    ctx.evidence("frozen-app", Tier.INFERRED, entry, captured=frozen.detail),
                ),
                annotations=(
                    Annotation(
                        code="frozen-app",
                        subject=ref_file(entry.path),
                        detail=f"{entry.path}: {frozen.detail} — bundled dependencies are "
                        "recoverable (full extraction lands with the installer unpackers)",
                    ),
                ),
            )
            identified = True

        # 4. fingerprint identification — only when a signatures pack is
        # installed; every match is inferred-tier with its matched evidence.
        db = _sigdb()
        if db is not None:
            from sorb.binary.fingerprint import match_constants, match_functions, match_symbols

            fp_matches = match_constants(blob, db)
            fp_matches += match_symbols(info, db)
            fp_matches += match_functions(blob, info, db)
            seen_libs: set[int] = set()
            for m in fp_matches:
                if m.library_id in seen_libs:
                    continue
                seen_libs.add(m.library_id)
                yield Finding(
                    claim=ComponentClaim(
                        ctype="library",
                        name=m.name,
                        version=m.version,
                        purl=m.purl,
                        ecosystem=m.ecosystem,
                        attrs=(("modified", "true"),) if m.modified else (),
                    ),
                    evidence=(
                        ctx.evidence(
                            f"fn-fingerprint-{m.technique}",
                            Tier.INFERRED,
                            entry,
                            captured=f"{m.name} {m.version} via {m.technique}: "
                            + "; ".join(m.evidence),
                            extra_modifiers=(f"fingerprint-{m.technique} vote {m.match_ratio}",)
                            if m.match_ratio else (),
                        ),
                    ),
                    edges=(
                        EdgeClaim(
                            kind=EdgeType.CONTAINS,
                            src=ref_file(entry.path),
                            dst=f"purl:{m.purl}" if m.purl else f"claim:{m.ecosystem}/{m.name}@{m.version}",
                        ),
                    ),
                )
                identified = True

        # 5. unidentified inventory: honest, never force-matched.
        # Binaries whose embedded truth other catalogers own (Go buildinfo,
        # cargo-auditable, .NET CLR) are theirs — never double-claimed here.
        owned_elsewhere = (
            info.has_clr
            or b"\xff Go buildinf:" in blob[:1 << 16] or b"\xff Go buildinf:" in blob
            or info.section(".dep-v0") is not None
        )
        if not identified and not owned_elsewhere and info.kind not in ("object", "core") and info.fmt != "wasm":
            hints = []
            if info.soname:
                hints.append(f"soname={info.soname}")
            if info.needed:
                hints.append(f"needs={','.join(info.needed[:3])}")
            if info.build_id:
                hints.append(f"build-id={info.build_id[:16]}")
            yield Finding(
                claim=ComponentClaim(
                    ctype="file",
                    name=entry.path.rsplit("/", 1)[-1],
                    ecosystem="binary",
                    attrs=(("format", info.fmt), ("arch", info.arch),
                           ("unidentified", "true")),
                ),
                evidence=(
                    ctx.evidence(
                        "binary-unidentified",
                        Tier.INFERRED,
                        entry,
                        captured=f"{info.fmt}/{info.arch} {info.kind}; "
                        + ("; ".join(hints) if hints else "no embedded identity"),
                    ),
                ),
                annotations=(
                    Annotation(
                        code="unidentified-binaries",
                        subject=ref_file(entry.path),
                        detail=f"{entry.path}: {info.fmt}/{info.arch} could not be identified "
                        "from embedded metadata (fingerprinting may identify it)",
                    ),
                ),
            )


register(NativeBinaryCataloger())
