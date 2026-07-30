"""SPDX 2.3 JSON emitter."""

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

_CHECKSUM_ALGOS = {
    "sha1": "SHA1",
    "sha256": "SHA256",
    "sha384": "SHA384",
    "sha512": "SHA512",
    "md5": "MD5",
}

_ID_SAFE = re.compile(r"[^A-Za-z0-9.\-]+")


def _spdx_id(c: Component) -> str:
    base = c.purl or f"{c.name}-{c.version or 'unversioned'}"
    return f"SPDXRef-Package-{_ID_SAFE.sub('-', base)}-{c.id}"


def emit_spdx(store: GraphStore, *, reproducible: bool = False) -> bytes:
    components = emitted_components(store)
    serial = content_serial(store)
    subject = store.get_meta("subject") or "unknown-subject"
    ids = {c.id: _spdx_id(c) for c in components}

    packages: list[dict[str, Any]] = []
    for c in components:
        pkg: dict[str, Any] = {
            "SPDXID": ids[c.id],
            "name": c.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": c.attrs.get("licenses_declared", "NOASSERTION"),
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
        }
        if c.version:
            pkg["versionInfo"] = c.version
        checksums = [
            {"algorithm": _CHECKSUM_ALGOS[algo], "checksumValue": value}
            for algo, value in sorted(c.hashes.items())
            if algo in _CHECKSUM_ALGOS
        ]
        if checksums:
            pkg["checksums"] = checksums
        external_refs = []
        if c.purl:
            external_refs.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.purl,
                }
            )
        if c.attrs.get("cpe"):
            external_refs.append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": c.attrs["cpe"],
                }
            )
        if external_refs:
            pkg["externalRefs"] = external_refs
        ann_notes = [
            f"{a['code']}: {a['detail']}".strip(": ")
            for a in (store.annotations_for("component", c.id))
        ]
        comment_bits = [f"sorb:tier={c.tier.label}", f"sorb:confidence={c.confidence:.4f}"]
        if not c.purl and c.attrs.get("ecosystem"):
            comment_bits.append(f"sorb:ecosystem={c.attrs['ecosystem']}")
        scope = c.attrs.get("scope")
        if scope:
            comment_bits.append(f"sorb:scope={scope}")
        comment_bits.extend(ann_notes)
        pkg["comment"] = "; ".join(comment_bits)
        packages.append(pkg)

    relationships: list[dict[str, str]] = []
    for c in components:
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": ids[c.id],
            }
        )
    kind_map = {"DEPENDS_ON": "DEPENDS_ON", "CONTAINS": "CONTAINS", "RESOLVED_FROM": "GENERATED_FROM"}
    for e in store.edges():
        rel = kind_map.get(e["kind"])
        if rel is None:
            continue
        if e["src"] in ids and e["dst"] in ids:
            relationships.append(
                {
                    "spdxElementId": ids[e["src"]],
                    "relationshipType": rel,
                    "relatedSpdxElement": ids[e["dst"]],
                }
            )

    created = run_timestamp(reproducible) or "1970-01-01T00:00:00Z"
    creation_comment = f"config_fingerprint={store.get_meta('config_fingerprint') or ''}"
    reissue = store.get_meta("reissue_reason")
    if reissue:
        creation_comment += f"; reissue_reason={reissue}"
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"sorb-sbom-{_ID_SAFE.sub('-', subject)}",
        "documentNamespace": f"https://sorbet.invalid/spdxdocs/{serial}",
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: sorb-{tools_metadata(store)['version']}"],
            "comment": creation_comment,
        },
        "packages": packages,
        "relationships": relationships,
    }
    doc_version = store.get_meta("doc_version")
    superseded = store.get_meta("supersedes_serial")
    if doc_version:
        doc["comment"] = f"documentVersion={doc_version}" + (
            f"; supersedes=https://sorbet.invalid/spdxdocs/{superseded}" if superseded else ""
        )
    return canonical_json(doc)
