"""`LiveHostSource` — scan a running machine.

The point of a host scan is *targeted store discovery*, never a blind full-disk
crawl: we walk only the package stores that actually hold installed state — the
OS package DBs, Python site-packages/venvs, global `node_modules`, `~/.m2`, gem
homes, the Go module cache — and yield each file with a path relative to the
host root, so every cataloger dispatches on it unmodified. Everything
outside a known store is never opened. A `host://` scan therefore completes in
proportion to installed software, not disk size (profile-asserted).

The host root defaults to `/` but is configurable (`host://<abspath>`), which is
what lets a mounted image root — or a test fixture — be scanned identically.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator
from pathlib import Path

from sorb.model import Coordinates
from sorb.source.base import Entry, SourceProvenance, SourceRef
from sorb.source.roles import classify

_SNIFF_LEN = 64
_MAX_STORE_DEPTH = 12  # store trees are deep (node_modules) but not unbounded

#: Small virtual/config files yielded verbatim (kernel, distro id) — not a walk.
_PLATFORM_FILES: tuple[str, ...] = (
    "proc/version",
    "proc/modules",
    "etc/os-release",
    "usr/lib/os-release",
)

#: Store subroots relative to the host root. Fixed OS-DB paths plus globbed
#: language stores; home-relative stores are expanded per discovered home.
_FIXED_STORES: tuple[str, ...] = (
    "var/lib/dpkg",
    "var/lib/rpm",
    "usr/lib/sysimage/rpm",
    "lib/apk/db",
    "usr/lib/apk/db",
    "var/lib/pacman/local",
    "usr/lib/node_modules",
    "usr/local/lib/node_modules",
    "var/lib/gems",
    "usr/lib/go/pkg/mod",
    "usr/local/go/pkg/mod",
    # Homebrew: `/opt/homebrew` on Apple Silicon, `/usr/local` on Intel. Most
    # of the software on a developer Mac lives here, and without it a host
    # inventory of a Mac is close to empty.
    "opt/homebrew/Cellar",
    "usr/local/Cellar",
    # casks are applications rather than libraries, but `brew list` reports
    # them and they are installed software on the machine
    "opt/homebrew/Caskroom",
    "usr/local/Caskroom",
)
_GLOB_STORES: tuple[str, ...] = (
    "usr/lib/python*/site-packages",
    "usr/lib/python*/dist-packages",
    "usr/lib/python*.*/site-packages",
    "usr/local/lib/python*/site-packages",
    "usr/local/lib/python*/dist-packages",
    "usr/lib/ruby/gems/*",
)
#: Per-home stores (expanded under each discovered home directory).
_HOME_STORES: tuple[str, ...] = (
    ".m2/repository",
    ".gradle/caches/modules-2",
    ".gem",
    ".local/lib/python*/site-packages",
    "go/pkg/mod",
    ".cargo/registry/src",
    ".nuget/packages",
)


def _sha256_file(path: Path) -> str:
    from sorb.accel import hash_file  # native-accel escape hatch

    return hash_file(path)


def _home_dirs(root: Path) -> list[Path]:
    homes: list[Path] = []
    for base in ("home", "root", "Users"):
        d = root / base
        if not d.is_dir():
            continue
        if base == "root":
            homes.append(d)
        else:
            try:
                homes.extend(p for p in d.iterdir() if p.is_dir())
            except OSError:
                continue
    return homes


def discover_store_roots(root: Path) -> list[Path]:
    """The bounded set of package-store directories under `root` that exist.

    This *is* the "no full-disk walk" guarantee: only these subtrees are ever
    descended into."""
    found: list[Path] = []
    seen: set[str] = set()

    def add(p: Path) -> None:
        if p.is_dir():
            rp = str(p)
            if rp not in seen:
                seen.add(rp)
                found.append(p)

    for rel in _FIXED_STORES:
        add(root / rel)
    for pattern in _GLOB_STORES:
        try:
            for p in root.glob(pattern):
                add(p)
        except OSError:
            continue
    for home in _home_dirs(root):
        for rel in _HOME_STORES:
            if "*" in rel:
                try:
                    for p in home.glob(rel):
                        add(p)
                except OSError:
                    continue
            else:
                add(home / rel)
    return found


class LiveHostSource:
    """A running host presented as a Source, scanning only its package stores."""

    def __init__(self, root: Path | str = "/", source_id: str = "s1") -> None:
        self._root = Path(root).resolve()
        self._id = source_id
        self._digest_cache: dict[str, str] = {}
        self._store_roots = discover_store_roots(self._root)
        #: locations the walk could not read, and how many there were overall
        self._unreadable: list[str] = []
        self.unreadable_count = 0

    @property
    def host_root(self) -> Path:
        return self._root

    @property
    def store_roots(self) -> list[Path]:
        return list(self._store_roots)

    # -- Source protocol -----------------------------------------------------

    def root(self) -> SourceRef:
        return SourceRef(id=self._id, kind="host", ref=str(self._root))

    def walk(self) -> Iterator[Entry]:
        seen_dirs: set[tuple[int, int]] = set()
        for rel in _PLATFORM_FILES:
            p = self._root / rel
            try:
                if p.is_file():
                    with open(p, "rb") as f:
                        sniff = f.read(_SNIFF_LEN)
                    yield Entry(path=rel, size=p.stat().st_size, sniff=sniff)
            except OSError:
                self._note_unreadable(rel)
                continue
        for store in self._store_roots:
            yield from self._walk_dir(store, seen_dirs, depth=0)

    def _walk_dir(
        self, directory: Path, seen: set[tuple[int, int]], depth: int
    ) -> Iterator[Entry]:
        if depth > _MAX_STORE_DEPTH:
            return
        try:
            st = directory.stat()
        except OSError:
            self._note_unreadable(self._rel(directory))
            return
        key = (st.st_dev, st.st_ino)
        if key in seen:  # loop guard across symlinked stores
            return
        seen.add(key)
        try:
            children = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError:
            self._note_unreadable(self._rel(directory))
            return
        for child in children:
            try:
                is_symlink = child.is_symlink()
                if child.is_dir() and not is_symlink:
                    yield from self._walk_dir(child, seen, depth + 1)
                elif child.is_file() and not is_symlink:
                    rel = self._rel(child)
                    try:
                        fst = child.stat()
                        with open(child, "rb") as f:
                            sniff = f.read(_SNIFF_LEN)
                    except OSError:
                        self._note_unreadable(rel)
                        continue
                    yield Entry(path=rel, size=fst.st_size, role=classify(rel), sniff=sniff)
            except OSError:
                continue

    def _note_unreadable(self, where: str) -> None:
        """Record a location the walk could not read.

        A host inventory that silently skips what it cannot open reports a
        near-empty machine as though it were a complete answer — the usual
        cause is running unprivileged or inside a sandbox, and the user needs
        to be told rather than left to trust the number.
        """
        if len(self._unreadable) < 200:  # a bounded sample is enough to explain
            self._unreadable.append(where)
        self.unreadable_count += 1

    def _rel(self, path: Path) -> str:
        return unicodedata.normalize("NFC", path.relative_to(self._root).as_posix())

    def open(self, path: str) -> bytes:
        return (self._root / path).read_bytes()

    def exists(self, path: str) -> bool:
        return (self._root / path).is_file()

    def digest(self, path: str) -> str:
        if path not in self._digest_cache:
            self._digest_cache[path] = _sha256_file(self._root / path)
        return self._digest_cache[path]

    def coords(self, path: str, span: tuple[int, int] | None = None) -> Coordinates:
        return Coordinates(source_id=self._id, path=path, span=span)

    def provenance(self) -> SourceProvenance:
        import platform as _pf

        node = _pf.node() or self._root.name or "host"
        facts = {"hostname": node, "host_root": str(self._root)}
        return SourceProvenance(subject=f"host:{node}", facts=facts)
