"""HCL2-lite parser + partial evaluator.

A pragmatic in-process HCL reader — no terraform binary — covering the
constructs the Terraform analyzer needs: blocks (with labels), attributes,
string/number/bool/list/object values, ``${...}`` interpolation with variable
substitution, and ``var.x``/``local.x`` references. Expressions it cannot
evaluate become explicit ``Unresolved`` placeholders (never a guess).
This is a recursive-descent tokenizer/parser, not a regex hack, so it
handles nesting correctly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<comment>\#[^\n]*|//[^\n]*|/\*.*?\*/)
  | (?P<heredoc><<-?(?P<h>\w+)\n(?P<hbody>.*?)\n\s*(?P=h))
  | (?P<string>"(?:\\.|[^"\\])*")
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_.\-]*)
  | (?P<punc>[{}\[\]()=,:])
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass(frozen=True, slots=True)
class Unresolved:
    """An expression that could not be statically evaluated."""

    expr: str


@dataclass
class Block:
    btype: str
    labels: list[str]
    body: dict[str, Any] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)

    def sub(self, btype: str) -> list[Block]:
        return [b for b in self.blocks if b.btype == btype]


@dataclass
class Tok:
    kind: str
    value: str


def _lex(text: str) -> list[Tok]:
    toks: list[Tok] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            pos += 1
            continue
        pos = m.end()
        kind = m.lastgroup or ""
        if kind in ("ws", "comment"):
            continue
        if kind == "heredoc":
            toks.append(Tok("string", '"' + (m.group("hbody") or "") + '"'))
            continue
        toks.append(Tok(kind, m.group()))
    return toks


class _Parser:
    def __init__(self, toks: list[Tok]):
        self.toks = toks
        self.i = 0

    def peek(self, off: int = 0) -> Tok | None:
        j = self.i + off
        return self.toks[j] if j < len(self.toks) else None

    def take(self) -> Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def parse_body(self, top: bool = False) -> tuple[dict[str, Any], list[Block]]:
        body: dict[str, Any] = {}
        blocks: list[Block] = []
        while self.i < len(self.toks):
            t = self.peek()
            if t is None:
                break
            if t.value == "}" and not top:
                self.take()
                break
            if t.kind in ("ident", "string"):
                nxt = self.peek(1)
                if nxt and nxt.value == "=":
                    key = _unquote(t.value)
                    self.take()  # ident
                    self.take()  # =
                    body[key] = self.parse_value()
                else:
                    blocks.append(self.parse_block())
            else:
                self.take()
        return body, blocks

    def parse_block(self) -> Block:
        btype = _unquote(self.take().value)
        labels: list[str] = []
        while True:
            t = self.peek()
            if t is None or t.value == "{":
                break
            labels.append(_unquote(self.take().value))
        if self.peek() and self.peek().value == "{":  # type: ignore[union-attr]
            self.take()
        body, blocks = self.parse_body()
        return Block(btype=btype, labels=labels, body=body, blocks=blocks)

    def parse_value(self) -> Any:
        t = self.peek()
        if t is None:
            return None
        if t.value == "[":
            return self.parse_list()
        if t.value == "{":
            return self.parse_object()
        self.take()
        if t.kind == "string":
            return _unquote(t.value)
        if t.kind == "number":
            return float(t.value) if "." in t.value else int(t.value)
        if t.value in ("true", "false"):
            return t.value == "true"
        # bare identifier / reference / function call → collect the expression
        expr = t.value
        while self.peek() and self.peek().value in ("(", ".") or (  # type: ignore[union-attr]
            self.peek() and self.peek().kind == "ident" and expr.endswith(".")  # type: ignore[union-attr]
        ):
            expr += self.take().value
        return Unresolved(expr)

    def parse_list(self) -> list[Any]:
        self.take()  # [
        out: list[Any] = []
        while self.peek() and self.peek().value != "]":  # type: ignore[union-attr]
            out.append(self.parse_value())
            if self.peek() and self.peek().value == ",":  # type: ignore[union-attr]
                self.take()
        if self.peek():
            self.take()  # ]
        return out

    def parse_object(self) -> dict[str, Any]:
        self.take()  # {
        out: dict[str, Any] = {}
        while self.peek() and self.peek().value != "}":  # type: ignore[union-attr]
            key_t = self.take()
            key = _unquote(key_t.value)
            if self.peek() and self.peek().value in ("=", ":"):  # type: ignore[union-attr]
                self.take()
            out[key] = self.parse_value()
            if self.peek() and self.peek().value == ",":  # type: ignore[union-attr]
                self.take()
        if self.peek():
            self.take()  # }
        return out


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1].encode().decode("unicode_escape")
    return s


def parse_hcl(text: str) -> tuple[dict[str, Any], list[Block]]:
    """Parse HCL text into (top-level attributes, blocks)."""
    return _Parser(_lex(text)).parse_body(top=True)


_INTERP_RE = re.compile(r"\$\{([^}]+)\}")


def interpolate(value: Any, variables: dict[str, Any]) -> Any:
    """Resolve ``${var.x}``/``${local.x}`` in a string against `variables`.

    Unresolvable references leave a placeholder marker; a fully-unresolved
    value becomes `Unresolved`.
    """
    if isinstance(value, Unresolved):
        ref = value.expr
        if ref.startswith("var.") and ref[4:] in variables:
            return variables[ref[4:]]
        if ref.startswith("local.") and ref[6:] in variables:
            return variables[ref[6:]]
        return value
    if not isinstance(value, str):
        return value
    unresolved = False

    def repl(m: re.Match[str]) -> str:
        nonlocal unresolved
        ref = m.group(1).strip()
        if ref.startswith("var.") and ref[4:] in variables:
            return str(variables[ref[4:]])
        if ref.startswith("local.") and ref[6:] in variables:
            return str(variables[ref[6:]])
        unresolved = True
        return f"<unresolved:{ref}>"

    out = _INTERP_RE.sub(repl, value)
    return Unresolved(value) if unresolved and out.startswith("<unresolved:") and out.endswith(">") else out
