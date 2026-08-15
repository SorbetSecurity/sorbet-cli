"""Run catalogers over an in-memory file map, with no Source on disk."""

from __future__ import annotations

from sorb.catalogers.base import CatalogerContext, dispatch
from sorb.model import Coordinates, Finding
from sorb.source.base import Entry


class MapSource:
    def __init__(self, files: dict[str, bytes]):
        self.files = files

    def exists(self, path: str) -> bool:
        return path in self.files

    def open(self, path: str) -> bytes:
        return self.files[path]

    def coords(self, path: str, span=None):  # noqa: ANN001
        return Coordinates(source_id="s1", path=path, span=span)


def catalog(files: dict[str, bytes | str], path: str) -> list[Finding]:
    """Run every matching registered cataloger over `path` within `files`."""
    raw = {k: (v.encode() if isinstance(v, str) else v) for k, v in files.items()}
    blob = raw[path]
    entry = Entry(path=path, size=len(blob), sniff=blob[:64])
    out: list[Finding] = []
    for cataloger in dispatch(entry):
        ctx = CatalogerContext(source=MapSource(raw), detector=cataloger.detector)  # type: ignore[arg-type]
        out.extend(cataloger.parse(ctx, entry, blob))
    return out


def by_name(findings: list[Finding]) -> dict[str, Finding]:
    return {f.claim.name: f for f in findings}
