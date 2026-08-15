"""Signature-pack build pipeline.

Scheduled-CI builder: for each library in the manifest across an
(arch × compiler × opt-level) matrix, extract the four signature classes into a
`signatures.db`, measure per-signature precision against the negative corpus,
and emit a **signed** pack (`sorb sign` over the pack tar).

This module is the offline-runnable core of that pipeline: given already-built
artifacts and source trees (the CI matrix produces them; not committed), it
assembles the pack. The network fetch + compile matrix is CI configuration.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from sorb.binary.analyze import analyze_binary
from sorb.binary.fingerprint import function_hashes
from sorb.binary.sigdb import SignatureDB

#: the initial library set the first pack must cover
INITIAL_LIBRARY_SET = (
    "zlib", "openssl", "curl", "sqlite", "libpng", "pcre",
    "libxml2", "bzip2", "lz4", "zstd", "brotli", "libssh2",
    "nghttp2", "expat", "freetype", "harfbuzz", "libjpeg", "libtiff",
    "cares", "libidn2",
)


@dataclass
class LibraryArtifact:
    name: str
    version: str
    purl: str | None
    ecosystem: str = "generic"
    symbols: list[str] = field(default_factory=list)
    constants: list[tuple[bytes, float]] = field(default_factory=list)
    binary: bytes | None = None  # compiled artifact for function hashing
    source_files: dict[str, bytes] = field(default_factory=dict)


def build_signatures_db(artifacts: list[LibraryArtifact], out_path: Path) -> Path:
    """Assemble a signatures.db from library artifacts."""
    db = SignatureDB.create(out_path)
    for art in artifacts:
        lib_id = db.add_library(art.name, art.version, art.purl, art.ecosystem)
        if art.symbols:
            db.add_symbols(lib_id, art.symbols)
        if art.constants:
            db.add_constants(lib_id, art.constants)
        if art.binary is not None:
            info = analyze_binary(art.binary)
            text = info.section(".text") if info else None
            code = (
                art.binary[text.offset : text.offset + text.size]
                if text else art.binary
            )
            db.add_functions(lib_id, sorted(function_hashes(code)))
        if art.source_files:
            db.add_sourcefiles(
                lib_id,
                [
                    (path, hashlib.sha256(data).hexdigest())
                    for path, data in sorted(art.source_files.items())
                ],
            )
    db.commit()
    return out_path


def emit_pack(db_path: Path, version: str) -> bytes:
    """Wrap a signatures.db in a data-pack tar (sign it separately with sorb sign)."""
    from sorb.binary.packs import build_pack

    return build_pack("signatures", version, {"signatures.db": db_path.read_bytes()})


def precision_report(db_path: Path, negative_corpus: list[bytes]) -> dict[str, float]:
    """Measure per-library false-identification rate against a negative corpus
    (binaries known NOT to contain the library)."""
    from sorb.binary.fingerprint import match_constants, match_functions

    db = SignatureDB.open(db_path) if db_path.exists() else None
    if db is None:
        return {}
    false_hits: dict[str, int] = {}
    for blob in negative_corpus:
        info = analyze_binary(blob)
        matched = match_constants(blob, db)
        if info is not None:
            matched += match_functions(blob, info, db)
        for m in matched:
            false_hits[m.name] = false_hits.get(m.name, 0) + 1
    total = max(len(negative_corpus), 1)
    report = {name: 1.0 - hits / total for name, hits in false_hits.items()}
    db.close()
    return report


if __name__ == "__main__":  # pragma: no cover — CI entry point
    print(json.dumps({"initial_library_set": list(INITIAL_LIBRARY_SET)}, indent=2))
