"""Example sorb plugin: a cataloger + an emitter.

Demonstrates the entry-point extension path. `pip install .` in this directory
and `sorb` discovers both — the cataloger parses a made-up `acme.lock` format,
and the emitter writes a one-line-per-component CSV (`-o acme-csv`).

Both use the public `sorb` ABCs. Plugin findings are validated, attributed
(`plugin:acme/...`), and reconciled exactly like first-party findings.
"""

from __future__ import annotations

from collections.abc import Iterable

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher
from sorb.emit.base import Emitter
from sorb.graph.store import GraphStore
from sorb.model import ComponentClaim, Finding, Tier
from sorb.source.base import Entry


class AcmeLockCataloger(Cataloger):
    """Parses a toy `acme.lock`: one `name==version` per line."""

    id = "acme-lock"
    version = 1
    matchers = [Matcher(basename="acme.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        for lineno, line in enumerate(blob.decode("utf-8", "replace").splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#") or "==" not in line:
                continue
            name, _, version = line.partition("==")
            yield Finding(
                claim=ComponentClaim(
                    ctype="library", name=name.strip(), version=version.strip(),
                    ecosystem="acme",
                ),
                evidence=(
                    ctx.evidence("lockfile-parse", Tier.LOCKED, entry, span=(lineno, lineno),
                                 captured=line),
                ),
            )


class AcmeCsvEmitter(Emitter):
    """Writes `name,version,tier` per component."""

    id = "acme-csv"
    media_type = "text/csv"

    def emit(self, store: GraphStore, *, reproducible: bool = False) -> bytes:
        rows = ["name,version,tier"]
        for c in sorted(store.components(), key=lambda c: (c.name, c.version or "")):
            if c.attrs.get("excluded"):
                continue
            rows.append(f"{c.name},{c.version or ''},{c.tier.label}")
        return ("\n".join(rows) + "\n").encode()
