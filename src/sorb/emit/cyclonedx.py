"""CycloneDX 1.6 JSON emitter.

Full use of ``components[].evidence`` — identity techniques + confidence +
occurrences map natively onto our evidence records. Deterministic output via
the canonical serializer.
"""

from __future__ import annotations

from typing import Any

from sorb.emit.canonical import (
    canonical_json,
    content_serial,
    emitted_components,
    run_timestamp,
    tools_metadata,
)
from sorb.graph.store import Component, GraphStore

_HASH_ALG_MAP = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "blake2b": "BLAKE2b-256",
    "blake3": "BLAKE3",
}

_TECHNIQUE_MAP = {
    "manifest-parse": "manifest-analysis",
    "lockfile-parse": "manifest-analysis",
    "installed-state": "manifest-analysis",
    "os-package-db": "manifest-analysis",
    "binary-buildinfo": "binary-analysis",
    "imported-sbom": "attestation",
    "file-fingerprint": "hash-comparison",
}

_CTYPE_MAP = {
    "library": "library",
    "application": "application",
    "os-package": "library",
    "build-tool": "application",
    "framework": "framework",
    "cryptographic-asset": "cryptographic-asset",  # CBOM
    "machine-learning-model": "machine-learning-model",  # ML-BOM
    "operating-system": "operating-system",
    "windows-service": "application",
}


def _bom_ref(c: Component) -> str:
    return c.purl or f"component:{c.name}@{c.version or 'unversioned'}:{c.id}"


def emit_cyclonedx(store: GraphStore, *, reproducible: bool = False, bom_version: int = 1) -> bytes:
    components = emitted_components(store)
    serial = content_serial(store)
    refs = {c.id: _bom_ref(c) for c in components}

    out_components: list[dict[str, Any]] = []
    for c in components:
        entry: dict[str, Any] = {
            "type": _CTYPE_MAP.get(c.ctype, "library"),
            "bom-ref": refs[c.id],
            "name": c.name,
        }
        if c.version:
            entry["version"] = c.version
        if c.purl:
            entry["purl"] = c.purl
        if c.attrs.get("cpe"):
            entry["cpe"] = c.attrs["cpe"]
        hashes = [
            {"alg": _HASH_ALG_MAP[algo], "content": value}
            for algo, value in sorted(c.hashes.items())
            if algo in _HASH_ALG_MAP
        ]
        if hashes:
            entry["hashes"] = hashes
        # scope: CycloneDX allows required|optional|excluded
        scope = c.attrs.get("scope")
        if scope == "dev":
            entry["scope"] = "optional"

        detail = store.component_detail(c.id)
        evidence_records = detail.evidence if detail else []
        identity_methods = []
        occurrences = []
        seen_occ = set()
        for ev in evidence_records:
            technique = _TECHNIQUE_MAP.get(ev["technique"], "other")
            identity_methods.append(
                {
                    "technique": technique,
                    "confidence": round(ev["confidence"], 4),
                    "value": f"{ev['detector']}: {ev['location'].get('path', '')}",
                }
            )
            loc = ev["location"]
            occ_key = (loc.get("path"), tuple(loc.get("span") or ()))
            if loc.get("path") and occ_key not in seen_occ:
                seen_occ.add(occ_key)
                occ = {"location": loc["path"]}
                if loc.get("span"):
                    occ["line"] = loc["span"][0]
                occurrences.append(occ)
        if identity_methods:
            entry["evidence"] = {
                "identity": [
                    {
                        "field": "purl" if c.purl else "name",
                        "confidence": round(c.confidence, 4),
                        "methods": identity_methods,
                    }
                ],
            }
            if occurrences:
                entry["evidence"]["occurrences"] = occurrences
        if c.attrs.get("licenses_declared"):
            entry["licenses"] = [{"license": {"name": c.attrs["licenses_declared"]}}]

        properties = [
            {"name": "sorb:confidence", "value": f"{c.confidence:.4f}"},
            {"name": "sorb:tier", "value": c.tier.label},
        ]
        if not c.purl and c.attrs.get("ecosystem"):
            # Without a purl the ecosystem has nowhere else to live, and losing
            # it breaks identity on re-import.
            properties.append({"name": "sorb:ecosystem", "value": str(c.attrs["ecosystem"])})
        if scope:
            properties.append({"name": "sorb:scope", "value": scope})
        # container layer attribution
        if c.attrs.get("layer") is not None:
            properties.append({"name": "sorb:layer", "value": str(c.attrs["layer"])})
        if c.attrs.get("layer_ordinal") is not None:
            properties.append(
                {"name": "sorb:layer-ordinal", "value": str(c.attrs["layer_ordinal"])}
            )
        if c.attrs.get("introduced_by"):
            properties.append(
                {"name": "sorb:introduced-by", "value": str(c.attrs["introduced_by"])}
            )
        if c.attrs.get("from_base_image"):
            properties.append(
                {"name": "sorb:from-base-image", "value": str(c.attrs["from_base_image"])}
            )
        if c.attrs.get("state"):
            properties.append({"name": "sorb:state", "value": str(c.attrs["state"])})
        for algo, value in sorted(c.hashes.items()):
            if algo not in _HASH_ALG_MAP:
                properties.append({"name": f"sorb:hash:{algo}", "value": value})
        if c.attrs.get("source-package"):
            properties.append(
                {"name": "sorb:source-package", "value": c.attrs["source-package"]}
            )
        if c.attrs.get("requested"):
            properties.append({"name": "sorb:requested", "value": c.attrs["requested"]})
        annotations = detail.annotations if detail else []
        for ann in annotations:
            properties.append({"name": f"sorb:annotation:{ann['code']}", "value": ann["detail"] or "true"})
        entry["properties"] = properties
        # extended BOM properties (CycloneDX 1.6): crypto assets + ML models
        if c.ctype == "cryptographic-asset":
            crypto = _crypto_properties(c.attrs)
            if crypto:
                entry["cryptoProperties"] = crypto
        elif c.ctype == "machine-learning-model":
            entry["modelCard"] = _model_card(c.attrs)
        out_components.append(entry)

    # dependency graph
    dep_map: dict[str, set[str]] = {}
    project_direct: set[str] = set()
    for e in store.edges():
        if e["kind"] != "DEPENDS_ON":
            continue
        src, dst = e["src"], e["dst"]
        if dst not in refs:
            continue
        if src in refs:
            dep_map.setdefault(refs[src], set()).add(refs[dst])
        elif src < 0:  # project/source roots aggregate onto the BOM subject
            project_direct.add(refs[dst])

    subject_ref = "sorb:subject"
    dependencies = [{"ref": subject_ref, "dependsOn": sorted(project_direct)}]
    for ref in sorted(dep_map):
        dependencies.append({"ref": ref, "dependsOn": sorted(dep_map[ref])})
    known_refs = {refs[c.id] for c in components} | {subject_ref}
    for entry in dependencies:
        entry["dependsOn"] = [r for r in entry["dependsOn"] if r in known_refs]

    gaps = [a for a in store.all_annotations() if a["code"] == "analysis-gap"]
    compositions = [
        {
            "aggregate": "incomplete" if gaps else "complete",
            "dependencies": [subject_ref],
        }
    ]

    metadata: dict[str, Any] = {
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "sorb",
                    "version": tools_metadata(store)["version"],
                }
            ]
        },
        "component": {
            "type": "application",
            "bom-ref": subject_ref,
            "name": store.get_meta("subject") or "unknown-subject",
        },
        "properties": [
            {"name": "sorb:config_fingerprint", "value": store.get_meta("config_fingerprint") or ""},
            {"name": "sorb:detectors", "value": store.get_meta("detectors") or "[]"},
            {"name": "sorb:reissue_reason", "value": store.get_meta("reissue_reason") or "initial"},
        ],
    }
    ts = run_timestamp(reproducible)
    if ts:
        metadata["timestamp"] = ts
    doc_version = int(store.get_meta("doc_version") or bom_version)
    superseded = store.get_meta("supersedes_serial")
    if superseded:
        # lineage: BOM-Link to the superseded document
        metadata["properties"].append(
            {"name": "sorb:supersedes", "value": f"urn:cdx:{superseded}/{max(doc_version - 1, 1)}"}
        )

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": doc_version,
        "metadata": metadata,
        "components": out_components,
        "dependencies": dependencies,
        "compositions": compositions,
    }
    return canonical_json(doc)


def _crypto_properties(attrs: dict[str, Any]) -> dict[str, Any] | None:
    """CycloneDX 1.6 cryptoProperties for a certificate asset."""
    if attrs.get("asset_type") == "certificate":
        cert: dict[str, Any] = {}
        if attrs.get("subject"):
            cert["subjectName"] = attrs["subject"]
        if attrs.get("issuer"):
            cert["issuerName"] = attrs["issuer"]
        if attrs.get("not_before"):
            cert["notValidBefore"] = attrs["not_before"]
        if attrs.get("not_after"):
            cert["notValidAfter"] = attrs["not_after"]
        if attrs.get("signature_algorithm"):
            cert["signatureAlgorithmRef"] = attrs["signature_algorithm"]
        if attrs.get("fingerprint_sha256"):
            cert["certificateFingerprint"] = attrs["fingerprint_sha256"]
        return {"assetType": "certificate", "certificateProperties": cert}
    if attrs.get("asset_type") == "private-key":
        return {"assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {"type": "private-key"}}
    return None


def _model_card(attrs: dict[str, Any]) -> dict[str, Any]:
    """CycloneDX 1.6 modelCard for an ML model."""
    params: dict[str, Any] = {}
    if attrs.get("model_format"):
        params["approach"] = {"type": "supervised"}  # unknown; format recorded below
    considerations = {}
    if attrs.get("pickle_risk") == "true":
        considerations = {"technicalLimitations": [
            "contains executable pickle data — deserialization is a code-execution risk"]}
    card: dict[str, Any] = {"modelParameters": {}}
    if attrs.get("architecture"):
        card["modelParameters"]["architectureFamily"] = attrs["architecture"]
    if attrs.get("model_format"):
        card["properties"] = [{"name": "sorb:model-format", "value": attrs["model_format"]}]
    if considerations:
        card["considerations"] = considerations
    return card
