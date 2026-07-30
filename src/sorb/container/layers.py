"""Layer model: whiteouts, transition log, SquashView.

Sorbet scans **per layer, then reasons about the squash**: every layer tar is
indexed independently; an oldest→newest path-state machine applies OCI
whiteout semantics (``.wh.`` markers, ``.wh..wh..opq`` opaque dirs) to compute
the merged view *and* record deletions. The transition log itself is data —
it powers ``state: removed`` components and the UI layer stack.
"""

from __future__ import annotations

import posixpath
from collections.abc import Iterator
from dataclasses import dataclass

from sorb.container.image import ImageLayer, ResolvedImage
from sorb.model import Coordinates
from sorb.source.archive import ArchiveBudget, ArchiveSource
from sorb.source.base import Entry, SourceProvenance, SourceRef

_WHITEOUT_PREFIX = ".wh."
_OPAQUE_MARKER = ".wh..wh..opq"

#: transition states (persisted in file_states)
ADDED = "added"
MODIFIED = "modified"
REMOVED = "removed"
OPAQUE_CLEARED = "opaque-cleared"


@dataclass(frozen=True, slots=True)
class FileTransition:
    path: str
    ordinal: int
    layer_digest: str
    state: str


class LayerStack:
    """All layer views of one image + the computed transition log."""

    def __init__(self, image: ResolvedImage, budget: ArchiveBudget | None = None) -> None:
        self._image = image
        self._budget = budget if budget is not None else ArchiveBudget()
        self.views: list[ArchiveSource] = []
        self.layers: list[ImageLayer] = list(image.layers)
        for layer in self.layers:
            # diff_id (uncompressed digest) is the layer identity everywhere
            # user-visible: it is invariant across acquisition paths.
            identity = layer.diff_id or layer.digest
            self.views.append(
                ArchiveSource(
                    image.layer_tar(layer),
                    name=identity,
                    source_id="s1",
                    layer_digest=identity,
                    budget=self._budget,
                )
            )
        self.transitions: list[FileTransition] = []
        #: final visible owner per path: path → layer ordinal
        self.owners: dict[str, int] = {}
        #: paths that existed at some point but are gone from the final view:
        #: path → (ordinal that last added/modified it, ordinal that removed it)
        self.removed: dict[str, tuple[int, int]] = {}
        self._compute()

    @property
    def budget(self) -> ArchiveBudget:
        return self._budget

    def _compute(self) -> None:
        visible: dict[str, int] = {}
        for view, layer in zip(self.views, self.layers, strict=True):
            k, digest = layer.ordinal, (layer.diff_id or layer.digest)
            members = view.member_paths()
            whiteouts: list[str] = []
            opaques: list[str] = []
            regular: list[str] = []
            for path in members:
                base = posixpath.basename(path)
                parent = posixpath.dirname(path)
                if base == _OPAQUE_MARKER:
                    opaques.append(parent)
                elif base.startswith(_WHITEOUT_PREFIX):
                    whiteouts.append(posixpath.join(parent, base[len(_WHITEOUT_PREFIX) :]))
                else:
                    regular.append(path)

            # Whiteouts and opaque markers hide *lower-layer* content first
            # (OCI image-spec layer ordering), then this layer's files apply.
            for target_dir in opaques:
                prefix = target_dir + "/" if target_dir else ""
                for p in [p for p in visible if p.startswith(prefix)]:
                    del visible[p]
                    self._record_gone(p, k, digest, OPAQUE_CLEARED)
            for target in whiteouts:
                prefix = target + "/"
                for p in [p for p in visible if p == target or p.startswith(prefix)]:
                    del visible[p]
                    self._record_gone(p, k, digest, REMOVED)

            for path in regular:
                state = MODIFIED if path in visible else ADDED
                visible[path] = k
                self.transitions.append(
                    FileTransition(path=path, ordinal=k, layer_digest=digest, state=state)
                )
        self.owners = visible

    def _record_gone(self, path: str, ordinal: int, digest: str, state: str) -> None:
        last_write = max(
            (t.ordinal for t in self.transitions if t.path == path and t.state in (ADDED, MODIFIED)),
            default=0,
        )
        self.transitions.append(
            FileTransition(path=path, ordinal=ordinal, layer_digest=digest, state=state)
        )
        self.removed[path] = (last_write, ordinal)

    # -- queries -----------------------------------------------------------------

    def owners_upto(self, upto: int) -> dict[str, int]:
        """Visible owner map considering only layers 0..upto (time travel)."""
        visible: dict[str, int] = {}
        for t in self.transitions:
            if t.ordinal > upto:
                break
            if t.state in (ADDED, MODIFIED):
                visible[t.path] = t.ordinal
            else:
                visible.pop(t.path, None)
        return visible

    def versions_of(self, path: str) -> list[int]:
        """Ordinals of every layer that wrote this path (added or modified)."""
        return [t.ordinal for t in self.transitions if t.path == path and t.state in (ADDED, MODIFIED)]

    def layer_of(self, ordinal: int) -> ImageLayer:
        return self.layers[ordinal]


class SquashView:
    """The merged filesystem view as a `Source` (whiteout-applied projection).

    `upto` restricts the view to layers 0..upto — the package-DB time-travel
    pass reads historical states through the same interface.
    """

    def __init__(
        self,
        stack: LayerStack,
        *,
        source_id: str = "s1",
        upto: int | None = None,
    ) -> None:
        self._stack = stack
        self._id = source_id
        self._owners = (
            dict(stack.owners) if upto is None else stack.owners_upto(upto)
        )
        self._upto = upto

    # -- Source protocol ------------------------------------------------------

    def root(self) -> SourceRef:
        return SourceRef(id=self._id, kind="oci", ref=self._stack._image.ref)

    def walk(self) -> Iterator[Entry]:
        for path in sorted(self._owners):
            view = self._stack.views[self._owners[path]]
            entry = view.entry_for(path)
            if entry is not None:
                yield entry

    def open(self, path: str) -> bytes:
        ordinal = self._owners.get(path)
        if ordinal is None:
            raise FileNotFoundError(path)
        return self._stack.views[ordinal].open(path)

    def exists(self, path: str) -> bool:
        return path in self._owners

    def digest(self, path: str) -> str:
        ordinal = self._owners.get(path)
        if ordinal is None:
            raise FileNotFoundError(path)
        return self._stack.views[ordinal].digest(path)

    def coords(self, path: str, span: tuple[int, int] | None = None) -> Coordinates:
        ordinal = self._owners.get(path)
        if ordinal is None:
            return Coordinates(source_id=self._id, path=path, span=span)
        return self._stack.views[ordinal].coords(path, span=span)

    def provenance(self) -> SourceProvenance:
        img = self._stack._image
        facts = {"platform": img.platform, **img.provenance_facts}
        return SourceProvenance(subject=img.subject(), facts=facts)

    # -- container-specific helpers ---------------------------------------------

    def owner_ordinal(self, path: str) -> int | None:
        return self._owners.get(path)

    def owners(self) -> dict[str, int]:
        """Visible path → owning layer ordinal (copy)."""
        return dict(self._owners)
