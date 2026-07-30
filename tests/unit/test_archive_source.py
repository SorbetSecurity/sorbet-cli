"""ArchiveSource + nesting — coordinate chains and recursion budgets."""

from __future__ import annotations

import io
import tarfile
import zipfile

import pytest

from sorb.errors import DetectorFailure, TargetError
from sorb.source.archive import (
    ArchiveBudget,
    ArchiveSource,
    open_nested,
    sniff_archive_kind,
)


def make_tar(files: dict[str, bytes], compress: str = "") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=f"w:{compress}") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_sniff_kinds() -> None:
    assert sniff_archive_kind(make_zip({"a": b"x"})[:64]) == "zip"
    assert sniff_archive_kind(make_tar({"a": b"x"}, "gz")[:64]) == "tar+gzip"
    assert sniff_archive_kind(make_tar({"a": b"x"})[:512]) == "tar"
    assert sniff_archive_kind(b"just text") is None


def test_tar_walk_open_digest() -> None:
    src = ArchiveSource(make_tar({"dir/a.txt": b"hello", "b.json": b"{}"}), name="t.tar")
    entries = {e.path: e for e in src.walk()}
    assert set(entries) == {"dir/a.txt", "b.json"}
    assert entries["dir/a.txt"].size == 5
    assert src.open("dir/a.txt") == b"hello"
    assert src.digest("b.json") == __import__("hashlib").sha256(b"{}").hexdigest()
    assert src.exists("dir/a.txt") and not src.exists("nope")


def test_zstd_tar_supported() -> None:
    import zstandard

    raw = make_tar({"x": b"y"})
    src = ArchiveSource(zstandard.compress(raw), name="t.tar.zst")
    assert [e.path for e in src.walk()] == ["x"]


def test_path_escapes_are_dropped() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in ("../evil", "/abs/path", "ok/./fine"):
            info = tarfile.TarInfo(name=name)
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
    src = ArchiveSource(buf.getvalue(), name="t.tar")
    paths = [e.path for e in src.walk()]
    # "../evil" escapes and is dropped; "/abs/path" is re-rooted inside
    assert paths == ["abs/path", "ok/fine"]


def test_three_level_coordinate_chain() -> None:
    """jar-in-zip-in-tar yields a 3-level chain."""
    jar = make_zip({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"})
    inner_zip = make_zip({"lib/app.jar": jar})
    outer_tar = make_tar({"bundle/inner.zip": inner_zip})

    budget = ArchiveBudget()
    lvl1 = ArchiveSource(outer_tar, name="outer.tar", budget=budget)
    lvl2 = open_nested(
        lvl1.open("bundle/inner.zip"),
        name="inner.zip", outer=lvl1, outer_path="bundle/inner.zip",
        budget=budget, depth=1,
    )
    assert lvl2 is not None
    lvl3 = open_nested(
        lvl2.open("lib/app.jar"),
        name="app.jar", outer=lvl2, outer_path="lib/app.jar",
        budget=budget, depth=2,
    )
    assert lvl3 is not None
    coords = lvl3.coords("META-INF/MANIFEST.MF")
    assert coords.physical_path() == "bundle/inner.zip!lib/app.jar!META-INF/MANIFEST.MF"
    assert coords.parent is not None and coords.parent.path == "lib/app.jar"
    assert coords.parent.parent is not None and coords.parent.parent.path == "bundle/inner.zip"


def test_depth_budget_stops_nesting() -> None:
    budget = ArchiveBudget(max_depth=1)
    outer = ArchiveSource(make_tar({"z.zip": make_zip({"a": b"x"})}), name="o.tar", budget=budget)
    nested = open_nested(
        outer.open("z.zip"), name="z.zip", outer=outer, outer_path="z.zip",
        budget=budget, depth=1,
    )
    assert nested is None
    assert any("depth" in r for r in budget.exhausted_reasons)


def test_bomb_budget_degrades_to_warning_not_oom() -> None:
    """A crafted expansion bomb hits the budget: walk truncates with a recorded
    reason and open() raises DetectorFailure — never an OOM."""
    big = b"\x00" * 4096
    budget = ArchiveBudget(max_total_bytes=6000, max_member_bytes=100_000)
    src = ArchiveSource(
        make_tar({"a.bin": big, "b.bin": big, "c.bin": big}, "gz"), name="bomb.tgz",
        budget=budget,
    )
    walked = [e.path for e in src.walk()]
    assert walked == ["a.bin"]  # second member would exceed the total budget
    assert budget.exhausted_reasons

    tight = ArchiveBudget(max_member_bytes=10)
    src2 = ArchiveSource(make_tar({"big.bin": big}), name="t.tar", budget=tight)
    with pytest.raises(DetectorFailure):
        src2.open("big.bin")


def test_member_count_budget() -> None:
    files = {f"f{i}": b"x" for i in range(20)}
    budget = ArchiveBudget(max_members=5)
    src = ArchiveSource(make_tar(files), name="many.tar", budget=budget)
    assert len(list(src.walk())) == 5


def test_symlinks_recorded_not_followed() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    src = ArchiveSource(buf.getvalue(), name="t.tar")
    entries = list(src.walk())
    assert entries[0].is_symlink and entries[0].size == 0
    assert src.open("link") == b""
    assert src.link_target("link") == "/etc/passwd"


def test_not_an_archive_raises_target_error() -> None:
    with pytest.raises(TargetError):
        ArchiveSource(b"plain text, no archive", name="x.txt")
