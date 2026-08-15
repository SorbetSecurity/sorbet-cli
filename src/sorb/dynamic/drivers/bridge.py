"""NativeResolution → Findings bridge.

Turns a driver's `NativeResolution` into locked-tier Findings that are
**indistinguishable downstream** from any other locked-tier evidence: same
`ComponentClaim`/`EdgeClaim` shapes, same reconcile treatment. The evidence
technique records that native mode produced them (for audit), but the tier and
graph are identical — which is what makes the "downstream can't tell which mode
ran" contract hold.
"""

from __future__ import annotations

import tomllib
from importlib import resources

from sorb.dynamic.drivers.base import NativeResolution, ResolvedDep
from sorb.ident import make_purl
from sorb.model import (
    ComponentClaim,
    Coordinates,
    EdgeClaim,
    EdgeType,
    EvidenceRecord,
    Finding,
    Scope,
    Tier,
)

_SCOPE_MAP = {
    "runtime": Scope.RUNTIME,
    "dev": Scope.DEV,
    "test": Scope.TEST,
    "build": Scope.BUILD,
    "provided": Scope.PROVIDED,
}


def _native_rate() -> float:
    raw = tomllib.loads(
        (resources.files("sorb") / "data" / "base_rates.toml").read_text(encoding="utf-8")
    )
    return float(raw.get("base_rates", {}).get("native-resolution", 0.95))


_NATIVE_CONFIDENCE = _native_rate()


# reference-string grammar (shared with reconcile; inlined here so the
# dynamic package needn't import the catalogers toolkit)
def _ref_purl(purl: str) -> str:
    return f"purl:{purl}"


def _ref_family(eco: str, name: str) -> str:
    return f"family:{eco}/{name}"


def _ref_project(path: str) -> str:
    return f"project:{path}"


def _purl_for(dep: ResolvedDep) -> str:
    ptype = dep.purl_type or dep.ecosystem
    return make_purl(ptype, dep.name.rsplit(":", 1)[-1] if ":" in dep.name else dep.name,
                     dep.version, namespace=dep.namespace)


def native_resolution_to_findings(
    resolution: NativeResolution, project_path: str, source_id: str
) -> list[Finding]:
    """Locked-tier Findings from a native resolution (empty if it failed)."""
    if not resolution.raw_ok and not resolution.deps:
        return []
    findings: list[Finding] = []
    proj_ref = _ref_project(project_path)
    location = Coordinates(source_id=source_id, path=project_path)
    detector = f"native/{resolution.driver_id}@1"

    for dep in resolution.deps:
        purl = _purl_for(dep)
        eco = dep.purl_type or dep.ecosystem
        claim = ComponentClaim(
            ctype="library",
            name=dep.name,
            version=dep.version,
            purl=purl,
            ecosystem=eco,
            namespace=dep.namespace,
            requested=dep.requested,
        )
        scope = _SCOPE_MAP.get(dep.scope, Scope.RUNTIME)
        src = proj_ref if dep.direct or not dep.parent else _parent_ref(dep, eco)
        edge = EdgeClaim(
            kind=EdgeType.DEPENDS_ON,
            src=src,
            dst=_ref_purl(purl),
            scope=scope,
            direct=dep.direct,
            requested=dep.requested,
        )
        evidence = EvidenceRecord(
            technique="native-resolution",
            tier=Tier.LOCKED,
            detector=detector,
            location=location,
            captured=f"{resolution.driver_id}: {dep.name} {dep.version} ({dep.scope})",
            confidence=_NATIVE_CONFIDENCE,
        )
        findings.append(Finding(claim=claim, evidence=(evidence,), edges=(edge,)))
    return findings


def _parent_ref(dep: ResolvedDep, eco: str) -> str:
    """The dependent's reference for a transitive edge."""
    parent = dep.parent or ""
    if ":" in parent and eco == "maven":
        ns, _, name = parent.rpartition(":")
        return _ref_family("maven", name) if not ns else f"family:maven/{name}"
    return _ref_family(eco, parent)
