"""Query DSL lexer + parser → AST.

Grammar (EBNF sketch)::

    query      := components_q | paths_q
    components_q := "components" ["where" condition] ["|" "count" "by" field]
    paths_q    := "paths" "from" ref "to" ref
    condition  := or_expr
    or_expr    := and_expr {"or" and_expr}
    and_expr   := term {"and" term}
    term       := "(" condition ")" | comparison
    comparison := field OP value
    OP         := "=" | "!=" | "<" | "<=" | ">" | ">=" | "~"   (~ = glob match)
    value      := STRING | NUMBER | "true" | "false" | BAREWORD
    field      := IDENT {"." IDENT}                            (dotted → attrs path)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sorb.query.errors import QueryError

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<op><=|>=|!=|=|<|>|~|\|)
  | (?P<punc>[().])
  | (?P<ident>[A-Za-z_][A-Za-z0-9_\-:/@*.]*)
    """,
    re.VERBOSE,
)

_KEYWORDS = {"components", "paths", "where", "and", "or", "from", "to", "count", "by", "true", "false"}


@dataclass(frozen=True, slots=True)
class Tok:
    kind: str
    value: str
    pos: int


def _lex(text: str) -> list[Tok]:
    toks: list[Tok] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise QueryError(f"unexpected character {text[pos]!r}", pos, text)
        kind = m.lastgroup or ""
        value = m.group()
        if kind != "ws":
            toks.append(Tok(kind=kind, value=value, pos=pos))
        pos = m.end()
    return toks


# -- AST ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Comparison:
    field: str
    op: str
    value: object  # str | float | bool
    pos: int = -1


@dataclass(frozen=True, slots=True)
class BoolExpr:
    op: str  # "and" | "or"
    left: object
    right: object


@dataclass
class ComponentsQuery:
    condition: object | None = None  # Comparison | BoolExpr | None
    count_by: str | None = None


@dataclass(frozen=True, slots=True)
class PathsQuery:
    src: str
    dst: str


class _Parser:
    def __init__(self, toks: list[Tok], text: str):
        self.toks = toks
        self.text = text
        self.i = 0

    def peek(self) -> Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _end_pos(self) -> int:
        return len(self.text)

    def expect(self, value: str) -> Tok:
        t = self.peek()
        if t is None:
            raise QueryError(f"expected {value!r} but query ended", self._end_pos(), self.text)
        if t.value.lower() != value:
            raise QueryError(f"expected {value!r}, got {t.value!r}", t.pos, self.text)
        self.i += 1
        return t

    def take(self) -> Tok:
        t = self.peek()
        if t is None:
            raise QueryError("unexpected end of query", self._end_pos(), self.text)
        self.i += 1
        return t

    def parse(self) -> ComponentsQuery | PathsQuery:
        head = self.peek()
        if head is None:
            raise QueryError("empty query", 0, self.text)
        if head.value.lower() == "components":
            return self._components()
        if head.value.lower() == "paths":
            return self._paths()
        raise QueryError(
            f"query must start with 'components' or 'paths', got {head.value!r}", head.pos, self.text
        )

    def _components(self) -> ComponentsQuery:
        self.expect("components")
        q = ComponentsQuery()
        if self.peek() and self.peek().value.lower() == "where":  # type: ignore[union-attr]
            self.take()
            q.condition = self._or_expr()
        if self.peek() and self.peek().value == "|":  # type: ignore[union-attr]
            self.take()
            self.expect("count")
            self.expect("by")
            q.count_by = self._field()
        if self.peek() is not None:
            t = self.peek()
            raise QueryError(f"unexpected trailing input {t.value!r}", t.pos, self.text)  # type: ignore[union-attr]
        return q

    def _paths(self) -> PathsQuery:
        self.expect("paths")
        self.expect("from")
        src = self._ref()
        self.expect("to")
        dst = self._ref()
        if self.peek() is not None:
            t = self.peek()
            raise QueryError(f"unexpected trailing input {t.value!r}", t.pos, self.text)  # type: ignore[union-attr]
        return PathsQuery(src=src, dst=dst)

    def _ref(self) -> str:
        t = self.take()
        if t.kind == "string":
            return _unquote(t.value)
        if t.kind == "punc" and t.value == ".":
            # `.` is how the CLI names the current project everywhere else, so
            # `paths from . to X` has to mean the same thing here. Deeper paths
            # go through `project:apps/web` or a quoted "./apps/web".
            return "."
        if t.kind not in ("ident", "number"):
            raise QueryError(f"expected a reference, got {t.value!r}", t.pos, self.text)
        return t.value

    def _or_expr(self) -> object:
        left = self._and_expr()
        while self.peek() and self.peek().value.lower() == "or":  # type: ignore[union-attr]
            self.take()
            right = self._and_expr()
            left = BoolExpr(op="or", left=left, right=right)
        return left

    def _and_expr(self) -> object:
        left = self._term()
        while self.peek() and self.peek().value.lower() == "and":  # type: ignore[union-attr]
            self.take()
            right = self._term()
            left = BoolExpr(op="and", left=left, right=right)
        return left

    def _term(self) -> object:
        t = self.peek()
        if t is not None and t.value == "(":
            self.take()
            inner = self._or_expr()
            self.expect(")")
            return inner
        return self._comparison()

    def _comparison(self) -> Comparison:
        field_tok = self.peek()
        f = self._field()
        op_tok = self.peek()
        if op_tok is None or op_tok.kind != "op" or op_tok.value == "|":
            raise QueryError(
                "expected a comparison operator (= != < <= > >= ~)",
                op_tok.pos if op_tok else self._end_pos(), self.text,
            )
        self.take()
        value = self._value()
        return Comparison(field=f, op=op_tok.value, value=value,
                          pos=field_tok.pos if field_tok else -1)

    def _field(self) -> str:
        t = self.take()
        if t.kind != "ident" or t.value.lower() in _KEYWORDS:
            raise QueryError(f"expected a field name, got {t.value!r}", t.pos, self.text)
        parts = [t.value]
        while self.peek() and self.peek().value == ".":  # type: ignore[union-attr]
            self.take()
            nxt = self.take()
            if nxt.kind != "ident":
                raise QueryError(f"expected a field name after '.', got {nxt.value!r}", nxt.pos, self.text)
            parts.append(nxt.value)
        return ".".join(parts)

    def _value(self) -> object:
        t = self.take()
        if t.kind == "string":
            return _unquote(t.value)
        if t.kind == "number":
            return float(t.value) if "." in t.value else int(t.value)
        if t.value.lower() == "true":
            return True
        if t.value.lower() == "false":
            return False
        if t.kind == "ident":
            return t.value  # bareword (e.g. runtime, npm)
        raise QueryError(f"expected a value, got {t.value!r}", t.pos, self.text)


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        return s[1:-1].encode().decode("unicode_escape")
    return s


def parse_query(text: str) -> ComponentsQuery | PathsQuery:
    """Parse a query string into an AST, or raise ``QueryError`` with position."""
    return _Parser(_lex(text), text).parse()
