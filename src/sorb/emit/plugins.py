"""Discovery of `sorb.emitters` entry-point plugins."""

from __future__ import annotations

from collections.abc import Iterable

from sorb.emit.base import ENTRYPOINT_GROUP, Emitter


def discover_plugin_emitters() -> list[Emitter]:
    """Load every `sorb.emitters` entry point. Never raises; broken ones skip."""
    from importlib.metadata import entry_points

    found: list[Emitter] = []
    try:
        eps = entry_points(group=ENTRYPOINT_GROUP)
    except Exception:  # pragma: no cover
        return found
    for ep in eps:
        try:
            for emitter in _instantiate(ep.load()):
                if isinstance(getattr(emitter, "id", None), str):
                    found.append(emitter)
        except Exception:
            continue
    return found


def _instantiate(obj: object) -> list[Emitter]:
    if isinstance(obj, Emitter):
        return [obj]
    if isinstance(obj, type) and issubclass(obj, Emitter):
        return [obj()]
    if callable(obj):
        produced = obj()
        if isinstance(produced, Emitter):
            return [produced]
        if isinstance(produced, Iterable):
            return [e for e in produced if isinstance(e, Emitter)]
    return []
