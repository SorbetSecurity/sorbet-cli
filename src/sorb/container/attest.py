"""Attestation discovery & verify-ingest.

Existing SBOM/provenance attestations attached to an image (cosign, in-toto,
BuildKit provenance) are discovered via the referrers API, parsed, and
**cross-checked against our own findings** — never blindly trusted. An
attestation that disagrees with the filesystem is itself a security finding
(``drift:attestation-mismatch``).

The CycloneDX reader here is a deliberately minimal subset behind the importer
seam.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

_DSSE_PAYLOAD_TYPES = ("application/vnd.in-toto+json",)


@dataclass(frozen=True, slots=True)
class AttestedComponent:
    name: str
    version: str | None
    purl: str | None


@dataclass
class AttestationDoc:
    """One parsed attestation: its kind and the component claims it makes."""

    kind: str  # "cyclonedx" | "spdx" | "provenance" | "unknown"
    source: str  # where it came from (referrer digest / tag)
    components: list[AttestedComponent] = field(default_factory=list)
    predicate_type: str | None = None


def parse_envelope(raw: bytes, source: str) -> AttestationDoc | None:
    """Parse a DSSE/in-toto envelope or a bare SBOM document."""
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return None
    # DSSE envelope: {payloadType, payload(b64), signatures}
    if "payload" in doc and "payloadType" in doc:
        if doc["payloadType"] not in _DSSE_PAYLOAD_TYPES:
            return AttestationDoc(kind="unknown", source=source)
        try:
            inner = json.loads(base64.b64decode(doc["payload"]))
        except (ValueError, json.JSONDecodeError):
            return None
        return _parse_statement(inner, source)
    # in-toto statement without envelope
    if doc.get("_type", "").startswith("https://in-toto.io/Statement"):
        return _parse_statement(doc, source)
    # bare SBOM
    if doc.get("bomFormat") == "CycloneDX":
        return _parse_cyclonedx(doc, source)
    if str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        return _parse_spdx(doc, source)
    return AttestationDoc(kind="unknown", source=source)


def _parse_statement(statement: dict[str, Any], source: str) -> AttestationDoc:
    predicate_type = str(statement.get("predicateType", ""))
    predicate = statement.get("predicate")
    if isinstance(predicate, dict):
        if "cyclonedx" in predicate_type.lower() or predicate.get("bomFormat") == "CycloneDX":
            parsed = _parse_cyclonedx(predicate, source)
            return AttestationDoc(
                kind="cyclonedx",
                source=source,
                components=parsed.components,
                predicate_type=predicate_type,
            )
        if "spdx" in predicate_type.lower():
            parsed = _parse_spdx(predicate, source)
            return AttestationDoc(
                kind="spdx",
                source=source,
                components=parsed.components,
                predicate_type=predicate_type,
            )
        if "slsa" in predicate_type.lower() or "provenance" in predicate_type.lower():
            return AttestationDoc(kind="provenance", source=source, predicate_type=predicate_type)
    return AttestationDoc(kind="unknown", source=source, predicate_type=predicate_type)


def _parse_cyclonedx(doc: dict[str, Any], source: str) -> AttestationDoc:
    """Minimal CycloneDX JSON component ingest (importer seam)."""
    components: list[AttestedComponent] = []
    for comp in doc.get("components", []) or []:
        if not isinstance(comp, dict) or not comp.get("name"):
            continue
        components.append(
            AttestedComponent(
                name=str(comp["name"]),
                version=str(comp["version"]) if comp.get("version") else None,
                purl=str(comp["purl"]) if comp.get("purl") else None,
            )
        )
    return AttestationDoc(kind="cyclonedx", source=source, components=components)


def _parse_spdx(doc: dict[str, Any], source: str) -> AttestationDoc:
    components: list[AttestedComponent] = []
    for pkg in doc.get("packages", []) or []:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        purl = None
        for ref in pkg.get("externalRefs", []) or []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = str(ref.get("referenceLocator"))
                break
        version = pkg.get("versionInfo")
        components.append(
            AttestedComponent(
                name=str(pkg["name"]),
                version=str(version) if version else None,
                purl=purl,
            )
        )
    return AttestationDoc(kind="spdx", source=source, components=components)


@dataclass
class CrossCheckResult:
    """Attestation vs scan: agreement raises trust, disagreement is a finding."""

    corroborated: list[tuple[AttestedComponent, str]] = field(default_factory=list)
    version_mismatches: list[tuple[AttestedComponent, str, str]] = field(default_factory=list)
    claimed_not_found: list[AttestedComponent] = field(default_factory=list)
    found_not_claimed: list[str] = field(default_factory=list)


def _family(name: str, purl: str | None) -> str:
    if purl and purl.startswith("pkg:"):
        base = purl.split("@", 1)[0]
        return base.lower()
    return name.lower()


def cross_check(
    attested: list[AttestedComponent],
    scanned: list[tuple[str, str | None, str | None]],  # (name, version, purl)
) -> CrossCheckResult:
    """Compare attested claims with scanned components by family identity."""
    result = CrossCheckResult()
    scanned_by_family: dict[str, tuple[str, str | None]] = {}
    for name, version, purl in scanned:
        scanned_by_family.setdefault(_family(name, purl), (name, version))
    claimed_families: set[str] = set()
    for claim in attested:
        fam = _family(claim.name, claim.purl)
        claimed_families.add(fam)
        hit = scanned_by_family.get(fam)
        if hit is None:
            result.claimed_not_found.append(claim)
        else:
            scanned_name, scanned_version = hit
            if claim.version and scanned_version and claim.version != scanned_version:
                result.version_mismatches.append((claim, scanned_name, scanned_version))
            else:
                result.corroborated.append((claim, scanned_name))
    for fam, (name, _version) in sorted(scanned_by_family.items()):
        if fam not in claimed_families:
            result.found_not_claimed.append(name)
    return result
