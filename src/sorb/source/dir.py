"""DirSource and FileSource.

- Single-pass walk yielding `Entry` with stat + first-bytes sniff.
- Symlinks recorded, never followed outside the root; loop-safe.
- Honors `.gitignore` **except** install dirs (node_modules etc. still walked);
  `.sorbignore` for overrides.
- Unicode path normalization (NFC) at this layer (macOS NFD divergence).
"""

from __future__ import annotations

import os
import subprocess
import unicodedata
from collections.abc import Iterator
from pathlib import Path

import pathspec

from sorb.model import Coordinates
from sorb.source.base import Entry, SourceProvenance, SourceRef
from sorb.source.roles import INSTALL_DIR_RE, classify

_SNIFF_LEN = 64


def _sniff(path: Path) -> bytes:
    """First bytes of a file, for magic-byte matchers.

    Every walked file needs these, so this goes through the raw descriptor
    calls: the buffered `open()` wrapper roughly doubles the cost at this call
    count, and none of what it adds is used for a 64-byte read.
    """
    fd = os.open(path, os.O_RDONLY)
    try:
        return os.read(fd, _SNIFF_LEN)
    finally:
        os.close(fd)


_SKIP_DIRS = {".git", ".hg", ".svn", ".sorb", "__pycache__", ".mypy_cache", ".ruff_cache"}


def _sha256_file(path: Path) -> str:
    from sorb.accel import hash_file  # native-accel escape hatch

    return hash_file(path)


def _git_provenance(root: Path) -> dict[str, str]:
    facts: dict[str, str] = {}
    if not (root / ".git").exists():
        return facts
    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if commit.returncode == 0:
            facts["git_commit"] = commit.stdout.strip()
        remote = subprocess.run(
            ["git", "-C", str(root), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if remote.returncode == 0 and remote.stdout.strip():
            facts["git_remote"] = remote.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return facts


class DirSource:
    """Local filesystem directory source."""

    def __init__(self, root: Path, source_id: str = "s1", extra_ignores: tuple[str, ...] = ()):
        self._root = root.resolve()
        self._id = source_id
        self._digest_cache: dict[str, str] = {}
        self._ignore = self._load_ignores(extra_ignores)

    def _load_ignores(self, extra: tuple[str, ...]) -> pathspec.PathSpec:  # type: ignore[type-arg]
        patterns: list[str] = list(extra)
        for name in (".gitignore", ".sorbignore"):
            p = self._root / name
            if p.is_file():
                try:
                    patterns.extend(p.read_text(encoding="utf-8", errors="replace").splitlines())
                except OSError:
                    pass
        try:
            return pathspec.PathSpec.from_lines("gitignore", patterns)
        except KeyError:  # older pathspec
            return pathspec.PathSpec.from_lines("gitwildmatch", patterns)

    # -- Source protocol -----------------------------------------------------

    def root(self) -> SourceRef:
        return SourceRef(id=self._id, kind="dir", ref=str(self._root))

    def walk(self) -> Iterator[Entry]:
        seen_dirs: set[tuple[int, int]] = set()
        yield from self._walk_dir(self._root, seen_dirs)

    def _walk_dir(self, directory: Path, seen: set[tuple[int, int]]) -> Iterator[Entry]:
        try:
            st = directory.stat()
        except OSError:
            return
        key = (st.st_dev, st.st_ino)
        if key in seen:  # symlink/junction loop guard
            return
        seen.add(key)
        try:
            children = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for child in children:
            name = child.name
            rel = unicodedata.normalize(
                "NFC", child.relative_to(self._root).as_posix()
            )
            try:
                is_symlink = child.is_symlink()
                if child.is_dir() and not is_symlink:
                    if name in _SKIP_DIRS:
                        continue
                    # gitignored dirs are skipped EXCEPT install dirs
                    if self._ignore.match_file(rel + "/") and not INSTALL_DIR_RE.search(
                        rel + "/"
                    ):
                        continue
                    yield from self._walk_dir(child, seen)
                elif child.is_file() or is_symlink:
                    if is_symlink:
                        # record, never follow outside the root
                        try:
                            resolved = child.resolve()
                            if not resolved.is_relative_to(self._root) or not resolved.is_file():
                                yield Entry(path=rel, size=0, is_symlink=True)
                                continue
                        except OSError:
                            continue
                    if self._ignore.match_file(rel) and not INSTALL_DIR_RE.search(rel):
                        continue
                    try:
                        fst = child.stat()
                        sniff = _sniff(child)
                    except OSError:
                        continue
                    yield Entry(
                        path=rel,
                        size=fst.st_size,
                        role=classify(rel),
                        sniff=sniff,
                        is_symlink=is_symlink,
                    )
            except OSError:
                continue

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
        facts = _git_provenance(self._root)
        if "git_remote" in facts:
            subject = f"git:{facts['git_remote']}"
        else:
            subject = f"dir:{self._root.name}"
        return SourceProvenance(subject=subject, facts=facts)


class FileSource:
    """Single-file target (a binary, an archive, an SBOM…)."""

    def __init__(self, file: Path, source_id: str = "s1"):
        self._file = file.resolve()
        self._id = source_id
        self._digest: str | None = None

    def root(self) -> SourceRef:
        return SourceRef(id=self._id, kind="file", ref=str(self._file))

    def walk(self) -> Iterator[Entry]:
        st = self._file.stat()
        with open(self._file, "rb") as f:
            sniff = f.read(_SNIFF_LEN)
        yield Entry(path=self._file.name, size=st.st_size, sniff=sniff)

    def open(self, path: str) -> bytes:
        if path != self._file.name:
            raise FileNotFoundError(path)
        return self._file.read_bytes()

    def exists(self, path: str) -> bool:
        return path == self._file.name

    def digest(self, path: str) -> str:
        if self._digest is None:
            self._digest = _sha256_file(self._file)
        return self._digest

    def coords(self, path: str, span: tuple[int, int] | None = None) -> Coordinates:
        return Coordinates(source_id=self._id, path=path, span=span)

    def provenance(self) -> SourceProvenance:
        return SourceProvenance(
            subject=f"file:{self._file.name}:sha256:{self.digest(self._file.name)}"
        )
