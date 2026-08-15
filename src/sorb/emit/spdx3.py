"""SPDX 3.0 JSON-LD emitter + importer.

SPDX 3.0 is a different model from 2.3: one flat `@graph` of typed Elements
(`software_Package`, `Relationship`, `CreationInfo`, `Tool`) with namespaced
properties, not a document with nested package/relationship arrays. This pair
emits the core + software profiles and imports them back, so the round-trip is a
fixpoint. Deterministic via the canonical serializer.
"""

from __future__ import annotations

import re
from typing import Any

from sorb.emit.canonical import (
    canonical_json,
    content_serial,
    emitted_components,
    run_timestamp,
    tools_metadata,
)
from sorb.graph.store import Component, GraphStore

_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
_ID_SAFE = re.compile(r"[^A-Za-z0-9.\-]+")
_HASH_ALGOS = {"sha1": "sha1", "sha256": "sha256", "sha384": "sha384",
               "sha512": "sha512", "md5": "md5", "blake3": "blake3"}
_REL_MAP = {"DEPENDS_ON": "dependsOn", "CONTAINS": "contains", "RESOLVED_FROM": "generates"}
_REL_INVERSE = {v: k for k, v in _REL_MAP.items()}


def _base(serial: str) -> str:
    return f"https://sorbet.invalid/spdx3/{serial}"


def _elem_id(serial: str, c: Component) -> str:
    base = c.purl or f"{c.name}-{c.version or 'unversioned'}"
    return f"{_base(serial)}/Package/{_ID_SAFE.sub('-', base)}-{c.id}"


def emit_spdx3(store: GraphStore, *, reproducible: bool = False) -> bytes:
    components = emitted_components(store)
    serial = content_serial(store)
    subject = store.get_meta("subject") or "unknown-subject"
    created = run_timestamp(reproducible) or "1970-01-01T00:00:00Z"
    ids = {c.id: _elem_id(serial, c) for c in components}

    graph: list[dict[str, Any]] = []
    creation_info = {
        "type": "CreationInfo", "@id": "_:creationinfo", "specVersion": "3.0.1",
        "created": created, "createdBy": ["_:sorb"], "createdUsing": ["_:sorb"],
    }
    graph.append(creation_info)
    graph.append({
        "type": "Tool", "spdxId": "_:sorb", "creationInfo": "_:creationinfo",
        "name": f"sorb-{tools_metadata(store)['version']}",
    })

    for c in components:
        pkg: dict[str, Any] = {
            "type": "software_Package", "spdxId": ids[c.id],
            "creationInfo": "_:creationinfo", "name": c.name,
        }
        if c.version:
            pkg["software_packageVersion"] = c.version
        if c.purl:
            pkg["software_packageUrl"] = c.purl
        verified = [
            {"type": "Hash", "algorithm": _HASH_ALGOS[a], "hashValue": v}
            for a, v in sorted(c.hashes.items()) if a in _HASH_ALGOS
        ]
        if verified:
            pkg["verifiedUsing"] = verified
        comment = [f"sorb:tier={c.tier.label}", f"sorb:confidence={c.confidence:.4f}",
                   f"sorb:ctype={c.ctype}"]
        if c.attrs.get("ecosystem"):
            comment.append(f"sorb:ecosystem={c.attrs['ecosystem']}")
        if c.attrs.get("licenses_declared"):
            comment.append(f"sorb:license={c.attrs['licenses_declared']}")
        pkg["comment"] = "; ".join(comment)
        graph.append(pkg)

    for e in store.edges():
        rel = _REL_MAP.get(e["kind"])
        if rel is None or e["src"] not in ids or e["dst"] not in ids:
            continue
        graph.append({
            "type": "Relationship",
            "spdxId": f"{_base(serial)}/Relationship/{e['id']}",
            "creationInfo": "_:creationinfo",
            "from": ids[e["src"]], "relationshipType": rel, "to": [ids[e["dst"]]],
        })

    graph.append({
        "type": "SpdxDocument", "spdxId": f"{_base(serial)}/document",
        "creationInfo": "_:creationinfo",
        "name": f"sorb-sbom-{_ID_SAFE.sub('-', subject)}",
        "profileConformance": ["core", "software"],
        "rootElement": [f"{_base(serial)}/document"],
        "element": [ids[c.id] for c in components],
    })

    return canonical_json({"@context": _CONTEXT, "@graph": graph})


# -- importer ----------------------------------------------------------------------------


def is_spdx3(doc: dict[str, Any]) -> bool:
    ctx = doc.get("@context", "")
    ctx_str = ctx if isinstance(ctx, str) else " ".join(str(x) for x in ctx)
    return "@graph" in doc and "spdx.org/rdf/3." in ctx_str


def import_spdx3(doc: dict[str, Any], db_path: str, source_name: str = "sbom") -> GraphStore:
    from sorb.emit.importers import _Ingest

    ingest = _Ingest(db_path, source_name, "spdx3")
    graph = doc.get("@graph") or []
    for elem in graph:
        if not isinstance(elem, dict) or elem.get("type") != "software_Package":
            continue
        name = elem.get("name")
        if not name:
            continue
        hashes = {}
        for h in elem.get("verifiedUsing") or []:
            if isinstance(h, dict) and h.get("algorithm") and h.get("hashValue"):
                hashes[str(h["algorithm"]).lower()] = h["hashValue"]
        attrs = _parse_comment(elem.get("comment", ""))
        ingest.add(
            ref=elem.get("spdxId"), ctype=attrs.get("ctype", "library"), name=name,
            version=elem.get("software_packageVersion"),
            purl=elem.get("software_packageUrl"), hashes=hashes,
            licenses=attrs.get("license"),
            extra={"spdx3_type": "software_Package"}, captured=f"SPDX3 {name}",
        )

    from sorb.model import EdgeType

    for elem in graph:
        if not isinstance(elem, dict) or elem.get("type") != "Relationship":
            continue
        kind = _REL_INVERSE.get(elem.get("relationshipType", ""))
        if kind is None:
            continue
        for to in elem.get("to") or []:
            ingest.edge(EdgeType(kind), str(elem.get("from")), str(to))

    return ingest.finish({"imported_format": "spdx3-json", "source_format": "spdx3"})


def _parse_comment(comment: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for bit in comment.split(";"):
        bit = bit.strip()
        if bit.startswith("sorb:") and "=" in bit:
            key, _, val = bit[5:].partition("=")
            out[key] = val
    return out
