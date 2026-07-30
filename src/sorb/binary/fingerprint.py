"""Fingerprint engines.

Inferred-tier identification for stripped/static binaries and vendored source,
matched against the signature DB. Every engine reports the matched evidence
(which symbols/constants/functions/files hit) and clears an explicit vote
threshold — never a force-match. Order of application, cheap→expensive:
constants → symbols → functions.

The function-shape engine here is the **pure-Python correctness reference**;
the `sorb-accel` fast path processes the same normalized-instruction stream.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from sorb.binary.info import BinaryInfo
from sorb.binary.sigdb import SignatureDB

# vote thresholds: a library is reported only when enough distinct
# signals hit AND enough of the library's own fingerprint set is covered.
_MIN_SYMBOLS = 8
_MIN_FUNCTIONS = 12
_MIN_FUNCTION_COVERAGE = 0.10


@dataclass
class FingerprintMatch:
    library_id: int
    name: str
    version: str
    purl: str | None
    ecosystem: str
    technique: str  # "symbols" | "constants" | "functions" | "sourcetree"
    confidence: float
    evidence: list[str] = field(default_factory=list)  # human detail: which signals hit
    modified: bool = False  # vendored source with local patches
    match_ratio: float | None = None


# -- symbols ----------------------------------------------------------------------------


def match_symbols(info: BinaryInfo, db: SignatureDB) -> list[FingerprintMatch]:
    symbols = {s.name for s in info.exported_symbols} | {s.name for s in info.imported_symbols}
    symbols |= set(info.strings_hint)
    if not symbols:
        return []
    counts = db.library_ids_for_symbols(symbols)
    matches: list[FingerprintMatch] = []
    for lib_id, n in counts.items():
        if n < _MIN_SYMBOLS:
            continue
        lib = db.library(lib_id)
        if lib is None:
            continue
        total = len(db.symbols_for_library(lib_id)) or n
        ratio = n / total
        matches.append(
            FingerprintMatch(
                library_id=lib_id, name=lib.name, version=lib.version, purl=lib.purl,
                ecosystem=lib.ecosystem, technique="symbols",
                confidence=round(min(0.85, 0.5 + ratio * 0.35), 4),
                evidence=[f"{n}/{total} known symbols matched"],
                match_ratio=round(ratio, 3),
            )
        )
    return matches


# -- constants --------------------------------------------------------------------------


def match_constants(blob: bytes, db: SignatureDB) -> list[FingerprintMatch]:
    hits = db.constants_hits(blob)
    matches: list[FingerprintMatch] = []
    for lib_id, found in hits.items():
        lib = db.library(lib_id)
        if lib is None:
            continue
        # confidence = 1 − Π(1 − per-constant precision) (noisy-OR), inferred cap
        prod = 1.0
        for _value, precision in found:
            prod *= 1.0 - max(0.0, min(1.0, precision))
        confidence = min(0.85, 1.0 - prod)
        detail = [f"constant {_display(v)} (precision {p})" for v, p in found[:4]]
        matches.append(
            FingerprintMatch(
                library_id=lib_id, name=lib.name, version=lib.version, purl=lib.purl,
                ecosystem=lib.ecosystem, technique="constants",
                confidence=round(confidence, 4), evidence=detail,
            )
        )
    return matches


def _display(value: bytes) -> str:
    try:
        text = value.decode("ascii")
        if text.isprintable():
            return repr(text)
    except UnicodeDecodeError:
        pass
    return value[:16].hex()


# -- function-shape (pure-Python reference) ---------------------------------------------

# x86-64 function prologues that start a boundary sweep. Kept deliberately
# simple: the reference implementation trades recall for auditability.
_PROLOGUES = (
    b"\x55\x48\x89\xe5",  # push rbp; mov rbp, rsp
    b"\x48\x83\xec",       # sub rsp, imm8
    b"\xf3\x0f\x1e\xfa",  # endbr64
)
_RET = 0xC3


def function_hashes(code: bytes, *, max_functions: int = 4096) -> set[str]:
    """Position-independent hashes of function bodies in a code blob.

    Lightweight recursive-descent-free sweep: split at recognized prologues,
    end at RET, normalize by masking likely immediate/displacement operands,
    then hash the normalized byte sequence. This is the correctness reference —
    operand masking is coarse (mask bytes following common ModRM/immediate
    opcodes) but stable across position, which is what fingerprinting needs.
    """
    boundaries = _find_boundaries(code)
    hashes: set[str] = set()
    for start, end in boundaries[:max_functions]:
        body = code[start:end]
        if len(body) < 8:
            continue
        normalized = _normalize(body)
        hashes.add(hashlib.sha256(normalized).hexdigest()[:24])
    return hashes


def _find_boundaries(code: bytes) -> list[tuple[int, int]]:
    starts: list[int] = []
    for prologue in _PROLOGUES:
        idx = 0
        while True:
            idx = code.find(prologue, idx)
            if idx < 0:
                break
            starts.append(idx)
            idx += 1
    starts = sorted(set(starts))
    out: list[tuple[int, int]] = []
    for i, s in enumerate(starts):
        # end at the first RET after the prologue, or the next prologue
        ret = code.find(bytes([_RET]), s + 4)
        nxt = starts[i + 1] if i + 1 < len(starts) else len(code)
        end = min(x for x in (ret + 1 if ret >= 0 else len(code), nxt) if x > s)
        out.append((s, end))
    return out


# opcodes whose trailing bytes are commonly immediates/displacements → mask them
_MASK_AFTER = {0xE8, 0xE9, 0x8B, 0x89, 0x48, 0xC7, 0x05, 0x3D, 0x81}


def _normalize(body: bytes) -> bytes:
    out = bytearray(body)
    i = 0
    while i < len(out):
        if out[i] in _MASK_AFTER:
            for j in range(i + 1, min(i + 5, len(out))):
                out[j] = 0
            i += 5
        else:
            i += 1
    return bytes(out)


def match_functions(blob: bytes, info: BinaryInfo, db: SignatureDB) -> list[FingerprintMatch]:
    text = info.section(".text")
    code = blob[text.offset : text.offset + text.size] if text else blob
    hashes = function_hashes(code)
    if len(hashes) < _MIN_FUNCTIONS:
        return []
    counts = db.function_matches(hashes)
    matches: list[FingerprintMatch] = []
    for lib_id, n in counts.items():
        if n < _MIN_FUNCTIONS:
            continue
        total = db.library_function_count(lib_id) or n
        coverage = n / total
        if coverage < _MIN_FUNCTION_COVERAGE:
            continue
        lib = db.library(lib_id)
        if lib is None:
            continue
        matches.append(
            FingerprintMatch(
                library_id=lib_id, name=lib.name, version=lib.version, purl=lib.purl,
                ecosystem=lib.ecosystem, technique="functions",
                confidence=round(min(0.85, 0.55 + coverage * 0.3), 4),
                evidence=[f"{n}/{total} function shapes matched ({coverage:.0%} coverage)"],
                match_ratio=round(coverage, 3),
            )
        )
    return matches


# -- vendored source-tree ---------------------------------------------------------------


def match_source_tree(
    file_hashes: dict[str, str], db: SignatureDB, *, min_ratio: float = 0.5
) -> list[FingerprintMatch]:
    """Identify a vendored directory by per-file content-hash voting.

    `file_hashes` maps relative path → sha256 hex for the files in a candidate
    vendored dir. A library whose recorded files match enough is reported with
    `modified: true` and the match ratio when the match is partial (patched).
    """
    hashes = set(file_hashes.values())
    counts = db.libraries_by_source_hash(hashes)
    matches: list[FingerprintMatch] = []
    for lib_id, n in counts.items():
        lib = db.library(lib_id)
        if lib is None:
            continue
        total = len(db.sourcefiles_for_library(lib_id)) or n
        ratio = n / total
        if ratio < min_ratio:
            continue
        modified = n < total
        matches.append(
            FingerprintMatch(
                library_id=lib_id, name=lib.name, version=lib.version, purl=lib.purl,
                ecosystem=lib.ecosystem, technique="sourcetree",
                confidence=round(min(0.85, 0.5 + ratio * 0.35), 4),
                evidence=[f"matched {n}/{total} source files"],
                modified=modified,
                match_ratio=round(ratio, 3),
            )
        )
    return matches


# -- symbol demangling hints (Rust v0 / C++ Itanium) -----------------------------------

_RUST_V0 = re.compile(r"_R[NIC]?([a-zA-Z0-9_]+)")
_CPP_ITANIUM = re.compile(r"_ZN?(\d+)([a-zA-Z0-9_]+)")


def crate_namespace_hints(symbols: list[str]) -> set[str]:
    """Crate/namespace names decoded from mangled symbols."""
    hints: set[str] = set()
    for sym in symbols:
        m = _CPP_ITANIUM.match(sym)
        if m:
            length = int(m.group(1))
            hints.add(m.group(2)[:length])
            continue
        if sym.startswith("_R"):  # Rust v0: length-prefixed identifiers follow
            for lm in re.finditer(r"(\d+)([a-zA-Z][a-zA-Z0-9_]*)", sym):
                n = int(lm.group(1))
                hints.add(lm.group(2)[:n])
    return {h for h in hints if len(h) >= 3}
