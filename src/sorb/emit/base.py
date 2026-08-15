"""Emitter ABC + registry for entry-point emitter plugins.

First-party emitters are module functions (`emit_cyclonedx`, …); this ABC is the
extension surface for third-party output formats delivered as `sorb.emitters`
entry points. A plugin emitter is resolved by its `id` (the `-o` format name) and
runs in-process over the finished graph, exactly like a built-in.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from sorb.graph.store import GraphStore

ENTRYPOINT_GROUP = "sorb.emitters"


class Emitter(ABC):
    """Contract: id (the `-o` format name) + a byte serializer."""

    id: str
    media_type: str = "application/octet-stream"

    @abstractmethod
    def emit(self, store: GraphStore, *, reproducible: bool = False) -> bytes: ...


_EMITTERS: dict[str, Emitter] = {}
_PLUGINS_LOADED = False


def register_emitter(emitter: Emitter) -> Emitter:
    _EMITTERS.setdefault(emitter.id, emitter)
    return emitter


def emitter_for(fmt: str) -> Emitter | None:
    _ensure_plugins_loaded()
    return _EMITTERS.get(fmt)


def plugin_emitter_ids() -> list[str]:
    _ensure_plugins_loaded()
    return sorted(_EMITTERS)


def _ensure_plugins_loaded() -> None:
    global _PLUGINS_LOADED
    if _PLUGINS_LOADED:
        return
    _PLUGINS_LOADED = True
    from sorb.emit.plugins import discover_plugin_emitters

    for emitter in discover_plugin_emitters():
        register_emitter(emitter)
