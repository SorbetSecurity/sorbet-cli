"""Query error type carrying a source position."""

from __future__ import annotations


class QueryError(ValueError):
    """A malformed query. ``pos`` is the 0-based character offset of the problem."""

    def __init__(self, message: str, pos: int = -1, query: str = ""):
        self.pos = pos
        self.query = query
        if pos >= 0 and query:
            caret = " " * pos + "^"
            super().__init__(f"{message} (at position {pos})\n  {query}\n  {caret}")
        else:
            super().__init__(message)
