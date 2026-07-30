"""Query DSL.

A small documented grammar over the evidence graph, shared by the ``sorb query``
CLI and the ``/api/query`` endpoint and the UI filter bar — so all three agree.
Three query shapes:

    components where purl ~ "pkg:npm/*" and confidence < 0.9
    paths from project:apps/web to pkg:npm/minimist@0.0.8
    components where introduced_by.base_image = false and scope = runtime | count by ecosystem

Compilation is to **parameterized** SQL (string literals never interpolated),
so injection attempts are inert. A malformed query raises a
``QueryError`` carrying the character position of the problem.
"""

from sorb.query.engine import QueryResult, run_query
from sorb.query.errors import QueryError
from sorb.query.parser import parse_query

__all__ = ["QueryError", "QueryResult", "parse_query", "run_query"]
