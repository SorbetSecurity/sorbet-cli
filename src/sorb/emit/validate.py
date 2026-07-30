"""Implementation of `sorb validate`.

Structural validation per format/version plus NTIA minimum-elements and BSI
TR-03183-2 checks, reported machine-readably with stable SORB-W codes.
Structural checks are hand-rolled against the specs (full JSON-Schema
validation is deferred until the schemas are vendored).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from sorb.emit.importers import sniff_sbom_format


@dataclass
class ValidationReport:
    format: str
    schema_errors: list[str] = field(default_factory=list)  # SORB-W070
    ntia_findings: list[str] = field(default_factory=list)  # SORB-W071
    tr03183_findings: list[str] = field(default_factory=list)  # SORB-W072

    @property
    def structurally_valid(self) -> bool:
        return not self.schema_errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "structurally_valid": self.structurally_valid,
            "SORB-W070": self.schema_errors,
            "SORB-W071": self.ntia_findings,
            "SORB-W072": self.tr03183_findings,
        }


_CDX_VERSIONS = {"1.4", "1.5", "1.6"}
_SERIAL_RE = re.compile(r"^urn:uuid:[0-9a-fA-F-]{36}$")


def validate_sbom(data: bytes) -> ValidationReport:
    fmt = sniff_sbom_format(data)
    if fmt is None:
        report = ValidationReport(format="unknown")
        report.schema_errors.append("not a recognized SBOM format (CycloneDX/SPDX/sorb)")
        return report
    if fmt == "cyclonedx-json":
        return _validate_cyclonedx(json.loads(data))
    if fmt == "spdx-json":
        return _validate_spdx(json.loads(data))
    report = ValidationReport(format=fmt)
    if fmt in ("cyclonedx-xml", "spdx-tv"):
        report.ntia_findings.append(
            f"{fmt}: NTIA/TR-03183 checks currently run on the JSON forms — "
            "convert first (`sorb convert`)"
        )
    return report


def _validate_cyclonedx(doc: dict[str, Any]) -> ValidationReport:
    r = ValidationReport(format="cyclonedx-json")
    spec = str(doc.get("specVersion", ""))
    if spec not in _CDX_VERSIONS:
        r.schema_errors.append(f"specVersion {spec!r} not in supported set {sorted(_CDX_VERSIONS)}")
    if not isinstance(doc.get("version", 1), int):
        r.schema_errors.append("version must be an integer")
    serial = doc.get("serialNumber")
    if serial is not None and not _SERIAL_RE.match(str(serial)):
        r.schema_errors.append(f"serialNumber {serial!r} is not urn:uuid:<uuid>")
    components = doc.get("components")
    if components is not None and not isinstance(components, list):
        r.schema_errors.append("components must be an array")
        components = []
    refs = {"sorb:subject"}
    for i, comp in enumerate(components or []):
        where = f"components[{i}]"
        if not isinstance(comp, dict):
            r.schema_errors.append(f"{where}: must be an object")
            continue
        if not comp.get("name"):
            r.schema_errors.append(f"{where}: missing required field 'name'")
        if not comp.get("type"):
            r.schema_errors.append(f"{where}: missing required field 'type'")
        if comp.get("bom-ref"):
            refs.add(str(comp["bom-ref"]))
    for i, dep in enumerate(doc.get("dependencies") or []):
        if isinstance(dep, dict) and dep.get("ref") not in refs:
            r.schema_errors.append(f"dependencies[{i}]: ref {dep.get('ref')!r} not a component bom-ref")

    # NTIA minimum elements (author, timestamp; per component: supplier, name,
    # version, unique id; relationships)
    metadata = doc.get("metadata") or {}
    has_author = bool(metadata.get("tools") or metadata.get("authors") or metadata.get("author"))
    if not has_author:
        r.ntia_findings.append("author of SBOM data missing (metadata.tools/authors)")
    if not metadata.get("timestamp"):
        r.ntia_findings.append("timestamp missing (metadata.timestamp)")
    if doc.get("dependencies") is None:
        r.ntia_findings.append("dependency relationships missing (dependencies)")
    for comp in components or []:
        if not isinstance(comp, dict) or not comp.get("name"):
            continue
        cname = comp.get("name")
        if not comp.get("supplier") and not comp.get("publisher") and not comp.get("author"):
            r.ntia_findings.append(f"supplier missing for component {cname!r}")
        if not comp.get("version"):
            r.ntia_findings.append(f"version missing for component {cname!r}")
        if not (comp.get("purl") or comp.get("cpe") or comp.get("swid") or comp.get("bom-ref")):
            r.ntia_findings.append(f"unique identifier missing for component {cname!r}")

    # BSI TR-03183-2 essentials: creator tooling, licenses, hashes
    if not metadata.get("tools"):
        r.tr03183_findings.append("SBOM creator tooling missing (metadata.tools)")
    for comp in components or []:
        if not isinstance(comp, dict) or not comp.get("name"):
            continue
        if not comp.get("licenses"):
            r.tr03183_findings.append(f"license missing for component {comp.get('name')!r}")
        if not comp.get("hashes"):
            r.tr03183_findings.append(f"hash missing for component {comp.get('name')!r}")
    return r


def _validate_spdx(doc: dict[str, Any]) -> ValidationReport:
    r = ValidationReport(format="spdx-json")
    version = str(doc.get("spdxVersion", ""))
    if version not in ("SPDX-2.2", "SPDX-2.3"):
        r.schema_errors.append(f"spdxVersion {version!r} not in supported set (SPDX-2.2, SPDX-2.3)")
    for required in ("SPDXID", "name", "documentNamespace", "creationInfo"):
        if not doc.get(required):
            r.schema_errors.append(f"missing required document field {required!r}")
    creation = doc.get("creationInfo") or {}
    if creation and not creation.get("created"):
        r.schema_errors.append("creationInfo.created missing")
    if creation and not creation.get("creators"):
        r.schema_errors.append("creationInfo.creators missing")
    ids = {"SPDXRef-DOCUMENT"}
    for i, pkg in enumerate(doc.get("packages") or []):
        where = f"packages[{i}]"
        if not isinstance(pkg, dict):
            r.schema_errors.append(f"{where}: must be an object")
            continue
        for required in ("name", "SPDXID", "downloadLocation"):
            if not pkg.get(required):
                r.schema_errors.append(f"{where}: missing required field {required!r}")
        if pkg.get("SPDXID"):
            ids.add(str(pkg["SPDXID"]))
    for i, rel in enumerate(doc.get("relationships") or []):
        if not isinstance(rel, dict):
            continue
        for end in ("spdxElementId", "relatedSpdxElement"):
            if rel.get(end) and str(rel[end]) not in ids and str(rel[end]) != "NOASSERTION":
                r.schema_errors.append(f"relationships[{i}]: {end} {rel[end]!r} is not a known SPDXID")

    if not creation.get("creators"):
        r.ntia_findings.append("author of SBOM data missing (creationInfo.creators)")
    if not creation.get("created"):
        r.ntia_findings.append("timestamp missing (creationInfo.created)")
    if not doc.get("relationships"):
        r.ntia_findings.append("dependency relationships missing (relationships)")
    for pkg in doc.get("packages") or []:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        pname = pkg.get("name")
        if not pkg.get("supplier"):
            r.ntia_findings.append(f"supplier missing for package {pname!r}")
        if not pkg.get("versionInfo"):
            r.ntia_findings.append(f"version missing for package {pname!r}")
        has_id = any(
            ref.get("referenceType") in ("purl", "cpe22Type", "cpe23Type")
            for ref in pkg.get("externalRefs") or []
            if isinstance(ref, dict)
        )
        if not has_id:
            r.ntia_findings.append(f"unique identifier missing for package {pname!r}")
        if not pkg.get("licenseDeclared") and not pkg.get("licenseConcluded"):
            r.tr03183_findings.append(f"license missing for package {pname!r}")
        if not pkg.get("checksums"):
            r.tr03183_findings.append(f"hash missing for package {pname!r}")
    if not creation.get("creators"):
        r.tr03183_findings.append("SBOM creator missing (creationInfo.creators)")
    return r
