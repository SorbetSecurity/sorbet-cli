"""Core domain model.

Frozen, slotted dataclasses — pure data, no IO, no imports above L1. This is
the vocabulary shared by workers, catalogers, plugins, and serializers.

``Component`` (the canonical post-reconcile entity) deliberately does NOT live
here: detectors cannot construct one, which enforces "no component without
reconciliation" at the type level.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Any

SCHEMA_VERSION = 1


class Tier(IntEnum):
    """Technique trust tiers. Higher value = closer to ground truth."""

    INFERRED = 1
    DECLARED = 2
    LOCKED = 3
    INSTALLED = 4
    OBSERVED = 5

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_label(cls, label: str) -> Tier:
        return cls[label.upper()]


#: Confidence caps by highest evidence tier present.
TIER_CONFIDENCE_CAP: dict[Tier, float] = {
    Tier.OBSERVED: 1.00,
    Tier.INSTALLED: 0.98,
    Tier.LOCKED: 0.95,
    Tier.DECLARED: 0.90,
    Tier.INFERRED: 0.85,
}


class Scope(StrEnum):
    RUNTIME = "runtime"
    DEV = "dev"
    BUILD = "build"
    TEST = "test"
    OPTIONAL = "optional"
    PROVIDED = "provided"


class EdgeType(StrEnum):
    """Typed edges. All edges carry evidence references."""

    DEPENDS_ON = "DEPENDS_ON"
    CONTAINS = "CONTAINS"
    DESCRIBES = "DESCRIBES"
    INSTANCE_OF = "INSTANCE_OF"
    INTRODUCED_BY = "INTRODUCED_BY"
    DECLARES = "DECLARES"
    RESOLVED_FROM = "RESOLVED_FROM"
    RUNS = "RUNS"
    OBSERVED_IN = "OBSERVED_IN"
    SUPERSEDES = "SUPERSEDES"


@dataclass(frozen=True, slots=True)
class Coordinates:
    """Physical location, chainable through nested Sources."""

    source_id: str
    path: str  # normalized POSIX-style within the source
    layer_digest: str | None = None
    span: tuple[int, int] | None = None  # (startLine, endLine), 1-based
    byte_range: tuple[int, int] | None = None
    parent: Coordinates | None = None

    def physical_path(self) -> str:
        """Flatten the parent chain into one physical path string."""
        parts: list[str] = []
        node: Coordinates | None = self
        while node is not None:
            parts.append(node.path)
            node = node.parent
        return "!".join(reversed(parts))


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """One replayable proof. Timestamps live on the Run, not here."""

    technique: str  # "lockfile-parse", "manifest-parse", "installed-state", …
    tier: Tier
    detector: str  # "js/npm-lock@1" — id@parser-version
    location: Coordinates
    captured: str | None = None  # size-capped verbatim snippet (masked)
    confidence: float = 0.0  # base(technique) × context modifiers
    modifiers: tuple[str, ...] = ()  # recorded reasons for each modifier applied


@dataclass(frozen=True, slots=True)
class ComponentClaim:
    """What a detector *believes* exists. Never emitted directly — reconciled first."""

    ctype: str  # "library" | "application" | "os-package" | "build-tool" | …
    name: str
    version: str | None = None
    purl: str | None = None  # canonicalized by sorb.ident before storage
    ecosystem: str | None = None  # purl type when purl absent (identity fallback)
    namespace: str | None = None
    qualifiers: tuple[tuple[str, str], ...] = ()
    hashes: tuple[tuple[str, str], ...] = ()  # (algo, hex)
    licenses_declared: str | None = None  # SPDX expression
    requested: str | None = None  # declared range when version is unresolved
    attrs: tuple[tuple[str, str], ...] = ()

    def ref(self) -> str:
        """Stable in-scan reference string for edge claims."""
        if self.purl:
            return f"purl:{self.purl}"
        eco = self.ecosystem or self.ctype
        ver = self.version or ""
        return f"claim:{eco}/{self.name}@{ver}"


@dataclass(frozen=True, slots=True)
class EdgeClaim:
    """A typed edge proposed by a detector. src/dst are reference strings:

    ``purl:<purl>`` · ``claim:<eco>/<name>@<ver>`` · ``project:<path>`` ·
    ``source:<id>`` · ``file:<path>``
    """

    kind: EdgeType
    src: str
    dst: str
    scope: Scope | None = None
    direct: bool | None = None
    requested: str | None = None  # the range asked for
    marker: str | None = None  # environment marker, when conditional
    attrs: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class Annotation:
    """Machine-readable flag on a subject (drift, conflicts, gaps, roles)."""

    code: str  # kebab-case, mapped to SORB-W codes in sorb.warnings
    subject: str  # reference string, same grammar as EdgeClaim src/dst
    detail: str = ""
    attrs: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class ProjectClaim:
    """A workspace member / build unit inside a monorepo."""

    path: str  # source-relative POSIX path of the project root
    name: str
    kind: str  # "npm-workspace" | "go-module" | "python" | …

    def ref(self) -> str:
        return f"project:{self.path}"


@dataclass(frozen=True, slots=True)
class Finding:
    """A raw detection: 'cataloger X believes Y exists because of Z'."""

    claim: ComponentClaim
    evidence: tuple[EvidenceRecord, ...]
    edges: tuple[EdgeClaim, ...] = ()
    annotations: tuple[Annotation, ...] = ()


@dataclass(frozen=True, slots=True)
class Warning_:
    """A user-facing warning event, carrying a stable code."""

    code: str
    message: str
    path: str | None = None


# --------------------------------------------------------------------------
# Serialization (JSON; schema-version tagged). msgpack can be layered on the
# same dict shapes later — the dict projection is the contract.
# --------------------------------------------------------------------------


def _coords_to_dict(c: Coordinates) -> dict[str, Any]:
    d: dict[str, Any] = {"source_id": c.source_id, "path": c.path}
    if c.layer_digest:
        d["layer_digest"] = c.layer_digest
    if c.span:
        d["span"] = list(c.span)
    if c.byte_range:
        d["byte_range"] = list(c.byte_range)
    if c.parent:
        d["parent"] = _coords_to_dict(c.parent)
    return d


def _coords_from_dict(d: dict[str, Any]) -> Coordinates:
    return Coordinates(
        source_id=d["source_id"],
        path=d["path"],
        layer_digest=d.get("layer_digest"),
        span=tuple(d["span"][:2]) if d.get("span") else None,
        byte_range=tuple(d["byte_range"][:2]) if d.get("byte_range") else None,
        parent=_coords_from_dict(d["parent"]) if d.get("parent") else None,
    )


def evidence_to_dict(e: EvidenceRecord) -> dict[str, Any]:
    return {
        "technique": e.technique,
        "tier": e.tier.label,
        "detector": e.detector,
        "location": _coords_to_dict(e.location),
        "captured": e.captured,
        "confidence": e.confidence,
        "modifiers": list(e.modifiers),
    }


def evidence_from_dict(d: dict[str, Any]) -> EvidenceRecord:
    return EvidenceRecord(
        technique=d["technique"],
        tier=Tier.from_label(d["tier"]),
        detector=d["detector"],
        location=_coords_from_dict(d["location"]),
        captured=d.get("captured"),
        confidence=float(d.get("confidence", 0.0)),
        modifiers=tuple(d.get("modifiers", ())),
    )


def claim_to_dict(c: ComponentClaim) -> dict[str, Any]:
    return {
        "ctype": c.ctype,
        "name": c.name,
        "version": c.version,
        "purl": c.purl,
        "ecosystem": c.ecosystem,
        "namespace": c.namespace,
        "qualifiers": dict(c.qualifiers),
        "hashes": dict(c.hashes),
        "licenses_declared": c.licenses_declared,
        "requested": c.requested,
        "attrs": dict(c.attrs),
    }


def claim_from_dict(d: dict[str, Any]) -> ComponentClaim:
    return ComponentClaim(
        ctype=d["ctype"],
        name=d["name"],
        version=d.get("version"),
        purl=d.get("purl"),
        ecosystem=d.get("ecosystem"),
        namespace=d.get("namespace"),
        qualifiers=tuple(sorted(d.get("qualifiers", {}).items())),
        hashes=tuple(sorted(d.get("hashes", {}).items())),
        licenses_declared=d.get("licenses_declared"),
        requested=d.get("requested"),
        attrs=tuple(sorted(d.get("attrs", {}).items())),
    )


def edge_to_dict(e: EdgeClaim) -> dict[str, Any]:
    return {
        "kind": e.kind.value,
        "src": e.src,
        "dst": e.dst,
        "scope": e.scope.value if e.scope else None,
        "direct": e.direct,
        "requested": e.requested,
        "marker": e.marker,
        "attrs": dict(e.attrs),
    }


def edge_from_dict(d: dict[str, Any]) -> EdgeClaim:
    return EdgeClaim(
        kind=EdgeType(d["kind"]),
        src=d["src"],
        dst=d["dst"],
        scope=Scope(d["scope"]) if d.get("scope") else None,
        direct=d.get("direct"),
        requested=d.get("requested"),
        marker=d.get("marker"),
        attrs=tuple(sorted(d.get("attrs", {}).items())),
    )


def annotation_to_dict(a: Annotation) -> dict[str, Any]:
    return {"code": a.code, "subject": a.subject, "detail": a.detail, "attrs": dict(a.attrs)}


def annotation_from_dict(d: dict[str, Any]) -> Annotation:
    return Annotation(
        code=d["code"],
        subject=d["subject"],
        detail=d.get("detail", ""),
        attrs=tuple(sorted(d.get("attrs", {}).items())),
    )


def finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "claim": claim_to_dict(f.claim),
        "evidence": [evidence_to_dict(e) for e in f.evidence],
        "edges": [edge_to_dict(e) for e in f.edges],
        "annotations": [annotation_to_dict(a) for a in f.annotations],
    }


def finding_from_dict(d: dict[str, Any]) -> Finding:
    return Finding(
        claim=claim_from_dict(d["claim"]),
        evidence=tuple(evidence_from_dict(e) for e in d.get("evidence", ())),
        edges=tuple(edge_from_dict(e) for e in d.get("edges", ())),
        annotations=tuple(annotation_from_dict(a) for a in d.get("annotations", ())),
    )


def finding_to_json(f: Finding) -> str:
    return json.dumps(finding_to_dict(f), sort_keys=True, separators=(",", ":"))


def finding_from_json(s: str) -> Finding:
    return finding_from_dict(json.loads(s))
