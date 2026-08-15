"""License identification.

- SPDX expression parsing/normalization for *declared* metadata (tiny
  recursive-descent parser: IDs, AND/OR/WITH, parens, `+`).
- Full-text detection: normalized-token **Dice coefficient** (bigram sets,
  askalono-style) against a license corpus. The built-in corpus is a seed of
  exactly-known texts; the full SPDX corpus arrives as the `license-corpus`
  data pack and is preferred when unpacked.

`declared` and `detected` are kept separate by callers — a mismatch is an
annotation, never silently resolved.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_COPYRIGHT_LINE_RE = re.compile(r"^\s*copyright\b.*$", re.IGNORECASE | re.MULTILINE)

MATCH_THRESHOLD = 0.90


def normalize_tokens(text: str) -> list[str]:
    """Lowercased word tokens with copyright lines dropped (they vary per project)."""
    text = _COPYRIGHT_LINE_RE.sub(" ", text)
    return _TOKEN_RE.findall(text.lower())


def _bigrams(tokens: list[str]) -> set[tuple[str, str]]:
    if len(tokens) < 2:
        return {(t, "") for t in tokens}
    return set(zip(tokens, tokens[1:], strict=False))


def dice_coefficient(a: list[str], b: list[str]) -> float:
    ba, bb = _bigrams(a), _bigrams(b)
    if not ba or not bb:
        return 0.0
    return 2 * len(ba & bb) / (len(ba) + len(bb))


@dataclass(frozen=True, slots=True)
class LicenseMatch:
    spdx_id: str
    score: float
    corpus_entry: str  # entry name, e.g. "Apache-2.0 (header)"


_CORPUS: list[tuple[str, str, list[str]]] | None = None  # (entry name, spdx id, tokens)


def _load_corpus(packs_dir: Path | None = None) -> list[tuple[str, str, list[str]]]:
    global _CORPUS
    if _CORPUS is not None and packs_dir is None:
        return _CORPUS
    doc = None
    if packs_dir is not None:
        pack_root = packs_dir / "license-corpus"
        if pack_root.is_dir():
            versions = sorted(p for p in pack_root.iterdir() if p.is_dir())
            for version_dir in reversed(versions):
                candidate = version_dir / "license_corpus.json"
                if candidate.is_file():
                    doc = json.loads(candidate.read_text(encoding="utf-8"))
                    break
    if doc is None:
        raw = (resources.files("sorb") / "data" / "license_corpus.json").read_text(
            encoding="utf-8"
        )
        doc = json.loads(raw)
    corpus = [
        (str(e["name"]), str(e["spdx_id"]), normalize_tokens(str(e["text"])))
        for e in doc.get("licenses", [])
    ]
    if packs_dir is None:
        _CORPUS = corpus
    return corpus


def detect_license(text: str, packs_dir: Path | None = None) -> LicenseMatch | None:
    """Best full-text match ≥ threshold; None otherwise (never a guess)."""
    tokens = normalize_tokens(text)
    if len(tokens) < 10:
        return None
    best: LicenseMatch | None = None
    for name, spdx_id, corpus_tokens in _load_corpus(packs_dir):
        score = dice_coefficient(tokens, corpus_tokens)
        if score >= MATCH_THRESHOLD and (best is None or score > best.score):
            best = LicenseMatch(spdx_id=spdx_id, score=round(score, 4), corpus_entry=name)
    return best


# -- SPDX expression parsing ------------------------------------------------------------

_EXPR_TOKEN_RE = re.compile(r"\(|\)|AND|OR|WITH|[A-Za-z0-9.\-+]+")


class SpdxExpressionError(ValueError):
    pass


def parse_spdx_expression(expr: str) -> str:
    """Validate and normalize an SPDX license expression (canonical spacing,
    uppercase operators). Raises SpdxExpressionError on malformed input."""
    tokens = _EXPR_TOKEN_RE.findall(expr)
    if not tokens or "".join(tokens).replace("(", "").replace(")", "") == "":
        raise SpdxExpressionError(f"empty license expression: {expr!r}")
    joined = " ".join(tokens)
    if joined.replace(" ", "") != re.sub(r"\s+", "", expr):
        raise SpdxExpressionError(f"unrecognized characters in expression: {expr!r}")

    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return str(tok)

    def parse_operand() -> str:
        tok = peek()
        if tok == "(":
            take()
            inner = parse_expr()
            if peek() != ")":
                raise SpdxExpressionError(f"unbalanced parentheses in {expr!r}")
            take()
            return f"({inner})"
        if tok is None or tok.upper() in ("AND", "OR", "WITH", ")"):
            raise SpdxExpressionError(f"expected license id in {expr!r}")
        license_id = take()
        if peek() and peek().upper() == "WITH":  # type: ignore[union-attr]
            take()
            exception = peek()
            if exception is None or exception in ("(", ")"):
                raise SpdxExpressionError(f"WITH needs an exception id in {expr!r}")
            take()
            return f"{license_id} WITH {exception}"
        return license_id

    def parse_expr() -> str:
        left = parse_operand()
        while peek() and peek().upper() in ("AND", "OR"):  # type: ignore[union-attr]
            op = take().upper()
            right = parse_operand()
            left = f"{left} {op} {right}"
        return left

    result = parse_expr()
    if pos != len(tokens):
        raise SpdxExpressionError(f"trailing tokens in license expression {expr!r}")
    return result
