"""Symlink loops, ignored-but-walked install dirs, roles."""

from __future__ import annotations

import os
from pathlib import Path

from sorb.source.dir import DirSource
from sorb.source.roles import classify


def test_symlink_loop_is_safe(tmp_path: Path) -> None:
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "file.txt").write_text("x")
    os.symlink(tmp_path / "a", tmp_path / "a" / "b" / "loop")
    entries = list(DirSource(tmp_path).walk())
    assert any(e.path == "a/file.txt" for e in entries)


def test_symlink_outside_root_recorded_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("secret")
    os.symlink(tmp_path / "outside.txt", root / "link.txt")
    entries = list(DirSource(root).walk())
    link = [e for e in entries if e.path == "link.txt"]
    assert link and link[0].is_symlink and link[0].size == 0


def test_gitignored_node_modules_still_walked(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("node_modules/\ndist/\n")
    nm = tmp_path / "node_modules" / "foo"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text("{}")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "bundle.js").write_text("x")
    paths = {e.path for e in DirSource(tmp_path).walk()}
    assert "node_modules/foo/package.json" in paths  # ignored-but-walked install-dir semantics
    assert "dist/bundle.js" not in paths


def test_role_classification() -> None:
    assert classify("tests/fixtures/package.json") == "fixture"
    assert classify("testdata/go.mod") == "fixture"
    assert classify("third_party/zlib/zlib.h") == "vendored"
    assert classify("examples/demo/app.py") == "example"
    assert classify("docs/conf.py") == "docs"
    assert classify("src/app/main.py") is None
    # installed state is never penalized as fixture (roles.py rule)
    assert classify("tests/node_modules/lodash/package.json") is None


def test_host_walk_records_what_it_could_not_read(tmp_path, monkeypatch) -> None:
    """A partial host inventory must say so.

    Silently skipping unreadable locations reports a near-empty machine as
    though it were a complete answer.
    """
    from sorb.source.host import LiveHostSource

    root = tmp_path / "host"
    (root / "usr/lib/node_modules/pkg").mkdir(parents=True)
    (root / "usr/lib/node_modules/pkg/package.json").write_text('{"name":"pkg","version":"1.0.0"}')
    source = LiveHostSource(root=root)
    assert source.unreadable_count == 0

    real_iterdir = type(root).iterdir

    def deny(self):  # noqa: ANN001, ANN202
        if self.name == "node_modules":
            raise PermissionError(13, "Operation not permitted")
        return real_iterdir(self)

    monkeypatch.setattr(type(root), "iterdir", deny)
    list(source.walk())
    assert source.unreadable_count > 0
