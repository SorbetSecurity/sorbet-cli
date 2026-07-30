"""Entry-point cataloger plugins.

The natural Python extension path: `pip install sorb-plugin-foo` exposes a
`sorb.catalogers` entry point, and it is discovered and registered here — running
trusted and in-process, through the *same* `Cataloger` ABC and the *same*
ingestion/validation path as first-party catalogers. The only difference is
identity: a plugin's detector id is namespaced `plugin:<name>/<id>@<version>` so
every evidence record it produces is attributable to the plugin that made it.

Discovery is stdlib `importlib.metadata` over installed distributions — the plugin
classes are external, so nothing here imports across a layer boundary.
"""

from __future__ import annotations

from collections.abc import Iterable

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher
from sorb.model import Finding
from sorb.source.base import Entry

ENTRYPOINT_GROUP = "sorb.catalogers"


class PluginCataloger(Cataloger):
    """Wraps a plugin's `Cataloger` so its detector id is `plugin:`-namespaced."""

    def __init__(self, inner: Cataloger, namespace: str) -> None:
        self._inner = inner
        self.id = f"plugin:{namespace}/{inner.id}"
        self.version = inner.version
        self.matchers = inner.matchers

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        return self._inner.parse(ctx, entry, blob)


def _instantiate(obj: object) -> list[Cataloger]:
    """An entry point may resolve to a Cataloger class, instance, or a factory
    returning one or a list. Normalize to a list of instances."""
    if isinstance(obj, Cataloger):
        return [obj]
    if isinstance(obj, type) and issubclass(obj, Cataloger):
        return [obj()]
    if callable(obj):
        produced = obj()
        if isinstance(produced, Cataloger):
            return [produced]
        if isinstance(produced, Iterable):
            return [c for c in produced if isinstance(c, Cataloger)]
    return []


def discover_plugin_catalogers() -> list[Cataloger]:
    """Load every `sorb.catalogers` entry point, namespaced. Never raises: a
    broken plugin is skipped, not fatal to the scan."""
    from importlib.metadata import entry_points

    found: list[Cataloger] = []
    try:
        eps = entry_points(group=ENTRYPOINT_GROUP)
    except Exception:  # pragma: no cover - importlib edge on odd envs
        return found
    for ep in eps:
        try:
            for inner in _instantiate(ep.load()):
                if _valid(inner):
                    found.append(PluginCataloger(inner, namespace=ep.name))
        except Exception:  # a plugin that fails to import is skipped, logged by caller
            continue
    return found


def _valid(c: Cataloger) -> bool:
    return (
        isinstance(getattr(c, "id", None), str)
        and isinstance(getattr(c, "version", None), int)
        and isinstance(getattr(c, "matchers", None), list)
        and all(isinstance(m, Matcher) for m in c.matchers)
    )
