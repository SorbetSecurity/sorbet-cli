"""Path-role classification (context modifiers).

One compiled table applied in the walker so every downstream consumer sees the
same ``role``. Roles feed confidence modifiers: fixture-ish paths ×0.3;
``vendor/``/``third_party/`` marks *vendored* (a real dep, flagged, no penalty).
"""

from __future__ import annotations

import re

_FIXTURE_RE = re.compile(
    r"(^|/)(tests?|testing|testdata|test[-_]?fixtures?|fixtures?|__fixtures__|__mocks__|spec)(/|$)",
    re.IGNORECASE,
)
_EXAMPLE_RE = re.compile(r"(^|/)(examples?|samples?|demos?)(/|$)", re.IGNORECASE)
_DOCS_RE = re.compile(r"(^|/)(docs?|documentation)(/|$)", re.IGNORECASE)
_VENDORED_RE = re.compile(r"(^|/)(vendor|vendored|third[-_]party|3rdparty|extern(al)?s?)(/|$)", re.IGNORECASE)

#: Install-state directories: still real evidence even when path looks test-ish
#: or is gitignored.
INSTALL_DIR_RE = re.compile(
    r"(^|/)(node_modules|\.pnpm|site-packages|dist-packages|\.venv|venv|conda-meta|"
    r"vendor/bundle|\.terraform)(/|$)"
)


def classify(path: str) -> str | None:
    """Classify a POSIX-style relative path. Returns None for ordinary paths."""
    if INSTALL_DIR_RE.search(path):
        return None  # installed state is never penalized as fixture
    if _FIXTURE_RE.search(path):
        return "fixture"
    if _VENDORED_RE.search(path):
        return "vendored"
    if _EXAMPLE_RE.search(path):
        return "example"
    if _DOCS_RE.search(path):
        return "docs"
    return None
