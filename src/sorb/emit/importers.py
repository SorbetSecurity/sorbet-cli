"""SBOM importers.

Readers for CycloneDX 1.4–1.6 (JSON, XML) and SPDX 2.2/2.3 (JSON, tag-value)
into the evidence graph. Every imported component carries an evidence record
of technique ``imported-sbom`` (declared tier) naming the source document —
imported *claims* are never confusable with scanned *findings*. Fields we
don't model ride in a properties bag for round-tripping.

Protobuf CycloneDX is not yet supported (needs a protobuf dependency).
"""

from __future__ import annotations

import json
import tomllib
import xml.etree.ElementTree as ET
from importlib import resources
from pathlib import Path
from typing import Any

from sorb.graph.store import GraphStore
from sorb.model import (
    ComponentClaim,
    Coordinates,
    EdgeType,
    EvidenceRecord,
    Finding,
    Tier,
)


def _imported_rate() -> float:
    raw = tomllib.loads(
        (resources.files("sorb") / "data" / "base_rates.toml").read_text(encoding="utf-8")
    )
    return float(raw.get("base_rates", {}).get("imported-sbom", 0.8))


_HASH_ALG_REVERSE = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
    "SHA1": "sha1",
    "SHA256": "sha256",
    "SHA512": "sha512",
    "BLAKE3": "blake3",
}

_SPDX_REL_MAP = {
    "DEPENDS_ON": EdgeType.DEPENDS_ON,
    "DEPENDENCY_OF": EdgeType.DEPENDS_ON,  # reversed below
    "CONTAINS": EdgeType.CONTAINS,
    "CONTAINED_BY": EdgeType.CONTAINS,  # reversed below
    "DESCRIBES": EdgeType.DESCRIBES,
}


def sniff_sbom_format(data: bytes) -> str | None:
    """'cyclonedx-json' | 'cyclonedx-xml' | 'spdx-json' | 'spdx-tv' | 'sorb' | None."""
    head = data.lstrip()[:4096]
    if head.startswith(b"<"):
        return "cyclonedx-xml" if b"<bom" in head else None
    if head.startswith(b"{"):
        try:
            doc = json.loads(data)
        except json.JSONDecodeError:
            return None
        if doc.get("bomFormat") == "CycloneDX":
            return "cyclonedx-json"
        if str(doc.get("spdxVersion", "")).startswith("SPDX-"):
            return "spdx-json"
        from sorb.emit.spdx3 import is_spdx3

        if is_spdx3(doc):
            return "spdx3-json"
        if doc.get("format") == "sorb":
            return "sorb"
        return None
    if b"SPDXVersion:" in head:
        return "spdx-tv"
    return None


def import_sbom(data: bytes, db_path: str | Path, source_name: str = "sbom") -> GraphStore:
    """Import any supported SBOM into a fresh run store."""
    fmt = sniff_sbom_format(data)
    if fmt == "sorb":
        from sorb.emit.native import import_native

        return import_native(data, db_path)
    if fmt == "cyclonedx-json":
        return _import_cyclonedx(json.loads(data), db_path, source_name)
    if fmt == "cyclonedx-xml":
        return _import_cyclonedx(_cyclonedx_xml_to_dict(data), db_path, source_name)
    if fmt == "spdx-json":
        return _import_spdx(json.loads(data), db_path, source_name)
    if fmt == "spdx3-json":
        from sorb.emit.spdx3 import import_spdx3

        return import_spdx3(json.loads(data), str(db_path), source_name)
    if fmt == "spdx-tv":
        return _import_spdx(_spdx_tagvalue_to_dict(data), db_path, source_name)
    raise ValueError(
        f"{source_name}: not a recognized SBOM (CycloneDX JSON/XML, SPDX JSON/tag-value, sorb)"
    )


# -- shared ingestion --------------------------------------------------------------------


class _Ingest:
    def __init__(self, db_path: str | Path, source_name: str, doc_kind: str):
        self.store = GraphStore.create(db_path)
        self.source_name = source_name
        self.rate = _imported_rate()
        self.store.add_source("s1", "sbom", source_name, {"format": doc_kind})
        self.refs: dict[str, int] = {}  # foreign ref → component id

    def add(
        self,
        *,
        ref: str | None,
        ctype: str,
        name: str,
        version: str | None,
        purl: str | None,
        hashes: dict[str, str],
        licenses: str | None,
        extra: dict[str, Any],
        captured: str,
        ecosystem: str | None = None,
    ) -> int:
        if purl and purl.startswith("pkg:"):
            ecosystem = purl[4:].split("/", 1)[0]
        claim = ComponentClaim(
            ctype=ctype,
            name=name,
            version=version,
            purl=purl,
            ecosystem=ecosystem,
            hashes=tuple(sorted(hashes.items())),
            licenses_declared=licenses,
        )
        evidence = EvidenceRecord(
            technique="imported-sbom",
            tier=Tier.DECLARED,
            detector="import/sbom@1",
            location=Coordinates(source_id="s1", path=self.source_name),
            captured=captured[:500],
            confidence=self.rate,
        )
        fid = self.store.add_finding(Finding(claim=claim, evidence=(evidence,)))
        attrs: dict[str, Any] = {"imported_from": self.source_name}
        if claim.ecosystem:
            attrs["ecosystem"] = claim.ecosystem
        if licenses:
            attrs["licenses_declared"] = licenses
        if extra:
            attrs["properties"] = extra  # round-trip bag
        cid = self.store.add_component(
            purl=purl,
            ctype=ctype,
            name=name,
            version=version,
            qualifiers={},
            hashes=hashes,
            confidence=self.rate,
            tier_cap=int(Tier.DECLARED),
            attrs=attrs,
        )
        self.store.link_finding(fid, cid)
        if ref:
            self.refs[ref] = cid
        return cid

    def edge(self, kind: EdgeType, src_ref: str, dst_ref: str) -> None:
        src, dst = self.refs.get(src_ref), self.refs.get(dst_ref)
        if src is not None and dst is not None and src != dst:
            self.store.add_edge(kind, src, dst)

    def finish(self, meta: dict[str, str]) -> GraphStore:
        for key, value in meta.items():
            self.store.set_meta(key, value)
        self.store.commit()
        return self.store


# -- CycloneDX ---------------------------------------------------------------------------

_CDX_TYPE_MAP = {"library": "library", "application": "application", "framework": "library",
                 "container": "application", "operating-system": "os-package", "file": "file"}


def _import_cyclonedx(doc: dict[str, Any], db_path: str | Path, source_name: str) -> GraphStore:
    ingest = _Ingest(db_path, source_name, "cyclonedx")
    for comp in doc.get("components") or []:
        if not isinstance(comp, dict) or not comp.get("name"):
            continue
        hashes = {}
        for h in comp.get("hashes") or []:
            algo = _HASH_ALG_REVERSE.get(str(h.get("alg", "")))
            if algo and h.get("content"):
                hashes[algo] = str(h["content"])
        licenses = None
        for lic in comp.get("licenses") or []:
            inner = lic.get("license") if isinstance(lic, dict) else None
            if isinstance(inner, dict):
                licenses = str(inner.get("id") or inner.get("name") or "") or None
            elif isinstance(lic, dict) and lic.get("expression"):
                licenses = str(lic["expression"])
            if licenses:
                break
        extra = {
            k: v
            for k, v in comp.items()
            if k not in ("type", "bom-ref", "name", "version", "purl", "hashes",
                          "licenses", "evidence", "properties", "cpe")
        }
        props = {
            str(p.get("name")): str(p.get("value"))
            for p in comp.get("properties") or []
            if isinstance(p, dict) and p.get("name")
        }
        if props:
            extra["properties"] = props
        ingest.add(
            ref=str(comp.get("bom-ref")) if comp.get("bom-ref") else None,
            ctype=_CDX_TYPE_MAP.get(str(comp.get("type", "library")), "library"),
            name=str(comp["name"]),
            version=str(comp["version"]) if comp.get("version") else None,
            purl=str(comp["purl"]) if comp.get("purl") else None,
            hashes=hashes,
            licenses=licenses,
            extra=extra,
            ecosystem=props.get("sorb:ecosystem"),
            captured=json.dumps({k: comp.get(k) for k in ("name", "version", "purl")}),
        )
    for dep in doc.get("dependencies") or []:
        src = str(dep.get("ref", ""))
        for dst in dep.get("dependsOn") or []:
            ingest.edge(EdgeType.DEPENDS_ON, src, str(dst))
    metadata = doc.get("metadata") or {}
    subject = ((metadata.get("component") or {}).get("name")) or source_name
    return ingest.finish(
        {
            "subject": f"imported:{subject}",
            "imported_format": f"cyclonedx-{doc.get('specVersion', '?')}",
            "imported_serial": str(doc.get("serialNumber", "")),
            "target": source_name,
        }
    )


def _cyclonedx_xml_to_dict(data: bytes) -> dict[str, Any]:
    root = ET.fromstring(data.decode("utf-8", errors="replace"))

    def strip(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    def text_of(el: ET.Element, name: str) -> str | None:
        for child in el:
            if strip(child.tag) == name:
                return (child.text or "").strip() or None
        return None

    components = []
    dependencies = []
    for el in root.iter():
        if strip(el.tag) == "component":
            comp: dict[str, Any] = {
                "type": el.get("type", "library"),
                "bom-ref": el.get("bom-ref"),
                "name": text_of(el, "name"),
                "version": text_of(el, "version"),
                "purl": text_of(el, "purl"),
            }
            components.append(comp)
        elif strip(el.tag) == "dependency" and el.get("ref"):
            entry = {"ref": el.get("ref"), "dependsOn": [c.get("ref") for c in el if c.get("ref")]}
            dependencies.append(entry)
    version = root.get("version") or "1"
    spec = (root.tag.split("}")[0].strip("{").rsplit("/", 1)[-1]) if "}" in root.tag else "?"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "version": version,
        "serialNumber": root.get("serialNumber", ""),
        "components": [c for c in components if c.get("name")],
        "dependencies": dependencies,
    }


# -- SPDX ---------------------------------------------------------------------------------


def _sorb_fact(comment: str, key: str) -> str | None:
    """Read one `sorb:<key>=<value>` fact out of an SPDX package comment."""
    for part in comment.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name == f"sorb:{key}":
            return value.strip() or None
    return None


def _import_spdx(doc: dict[str, Any], db_path: str | Path, source_name: str) -> GraphStore:
    ingest = _Ingest(db_path, source_name, "spdx")
    for pkg in doc.get("packages") or []:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        purl = None
        for ref in pkg.get("externalRefs") or []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = str(ref.get("referenceLocator"))
                break
        hashes = {}
        for chk in pkg.get("checksums") or []:
            algo = _HASH_ALG_REVERSE.get(str(chk.get("algorithm", "")))
            if algo and chk.get("checksumValue"):
                hashes[algo] = str(chk["checksumValue"])
        licenses = pkg.get("licenseDeclared") or pkg.get("licenseConcluded")
        if licenses in ("NOASSERTION", "NONE"):
            licenses = None
        extra = {
            k: v
            for k, v in pkg.items()
            if k not in ("SPDXID", "name", "versionInfo", "externalRefs", "checksums",
                          "licenseDeclared", "licenseConcluded", "downloadLocation")
        }
        ingest.add(
            ref=str(pkg.get("SPDXID")) if pkg.get("SPDXID") else None,
            ctype="library",
            name=str(pkg["name"]),
            version=str(pkg["versionInfo"]) if pkg.get("versionInfo") else None,
            purl=purl,
            hashes=hashes,
            licenses=str(licenses) if licenses else None,
            extra=extra,
            ecosystem=_sorb_fact(str(pkg.get("comment") or ""), "ecosystem"),
            captured=json.dumps({"name": pkg.get("name"), "versionInfo": pkg.get("versionInfo")}),
        )
    for rel in doc.get("relationships") or []:
        rtype = str(rel.get("relationshipType", ""))
        kind = _SPDX_REL_MAP.get(rtype)
        if kind is None:
            continue
        a, b = str(rel.get("spdxElementId", "")), str(rel.get("relatedSpdxElement", ""))
        if rtype in ("DEPENDENCY_OF", "CONTAINED_BY"):
            a, b = b, a
        ingest.edge(kind, a, b)
    return ingest.finish(
        {
            "subject": f"imported:{doc.get('name', source_name)}",
            "imported_format": str(doc.get("spdxVersion", "SPDX-?")).lower(),
            "imported_serial": str(doc.get("documentNamespace", "")),
            "target": source_name,
        }
    )


def _spdx_tagvalue_to_dict(data: bytes) -> dict[str, Any]:
    """Tag-value → the JSON shape `_import_spdx` reads."""
    doc: dict[str, Any] = {"packages": [], "relationships": []}
    package: dict[str, Any] | None = None
    for raw_line in data.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tag, sep, value = line.partition(":")
        if not sep:
            continue
        tag, value = tag.strip(), value.strip()
        if tag == "SPDXVersion":
            doc["spdxVersion"] = value
        elif tag == "DocumentName":
            doc["name"] = value
        elif tag == "DocumentNamespace":
            doc["documentNamespace"] = value
        elif tag == "PackageName":
            package = {"name": value}
            doc["packages"].append(package)
        elif package is not None and tag == "SPDXID":
            package.setdefault("SPDXID", value)
        elif tag == "SPDXID":
            doc.setdefault("SPDXID", value)
        elif package is not None and tag == "PackageVersion":
            package["versionInfo"] = value
        elif package is not None and tag == "PackageLicenseDeclared":
            package["licenseDeclared"] = value
        elif package is not None and tag == "PackageChecksum":
            algo, _, hexval = value.partition(":")
            package.setdefault("checksums", []).append(
                {"algorithm": algo.strip(), "checksumValue": hexval.strip()}
            )
        elif package is not None and tag == "ExternalRef":
            parts = value.split()
            if len(parts) == 3 and parts[1] == "purl":
                package.setdefault("externalRefs", []).append(
                    {"referenceCategory": parts[0], "referenceType": "purl",
                     "referenceLocator": parts[2]}
                )
        elif tag == "Relationship":
            parts = value.split()
            if len(parts) == 3:
                doc["relationships"].append(
                    {"spdxElementId": parts[0], "relationshipType": parts[1],
                     "relatedSpdxElement": parts[2]}
                )
    return doc
