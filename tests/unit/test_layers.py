"""Whiteouts, transition log, SquashView, history linking,
package-DB time travel."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from container_fixtures import (  # noqa: E402
    DPKG_STATUS_V1,
    DPKG_STATUS_V2,
    OS_RELEASE_DEBIAN,
    build_image,
    write_oci_layout,
)
from sorb.container.history import (  # noqa: E402
    link_dockerfile,
    link_history,
    normalize_created_by,
)
from sorb.container.layers import LayerStack, SquashView  # noqa: E402
from sorb.container.local import open_oci_layout  # noqa: E402
from sorb.container.pkgdb_timeline import diff_timeline, first_seen  # noqa: E402
from sorb.core.config import load_config  # noqa: E402
from sorb.core.explain import explain  # noqa: E402
from sorb.core.pipeline import run_scan  # noqa: E402
from sorb.graph.store import GraphStore  # noqa: E402


def _stack(layers: list[dict[str, bytes]], tmp_path: Path, **kwargs) -> LayerStack:
    bundle = build_image(layers, **kwargs)
    root = write_oci_layout(bundle, tmp_path / "layout")
    return LayerStack(open_oci_layout(str(root), None))


def test_whiteout_removes_file_and_subtree(tmp_path: Path) -> None:
    stack = _stack(
        [
            {"opt/tool/bin/tool": b"v1", "opt/tool/README": b"r", "etc/keep": b"k"},
            {"opt/.wh.tool": b""},  # whiteout of the whole dir
        ],
        tmp_path,
    )
    squash = SquashView(stack)
    assert squash.exists("etc/keep")
    assert not squash.exists("opt/tool/bin/tool")
    assert not squash.exists("opt/tool/README")
    removed = {t.path: t.state for t in stack.transitions if t.state == "removed"}
    assert set(removed) == {"opt/tool/bin/tool", "opt/tool/README"}
    # both layers referenced: written in 0, removed in 1
    assert stack.removed["opt/tool/bin/tool"] == (0, 1)


def test_opaque_dir_clears_lower_content(tmp_path: Path) -> None:
    stack = _stack(
        [
            {"data/old1": b"a", "data/old2": b"b"},
            {"data/.wh..wh..opq": b"", "data/new": b"n"},
        ],
        tmp_path,
    )
    squash = SquashView(stack)
    assert squash.exists("data/new")
    assert not squash.exists("data/old1") and not squash.exists("data/old2")
    states = {(t.path, t.state) for t in stack.transitions}
    assert ("data/old1", "opaque-cleared") in states
    assert ("data/new", "added") in states


def test_modified_state_and_owner(tmp_path: Path) -> None:
    stack = _stack(
        [{"app/config": b"v1"}, {"app/config": b"v2"}],
        tmp_path,
    )
    states = [(t.ordinal, t.state) for t in stack.transitions if t.path == "app/config"]
    assert states == [(0, "added"), (1, "modified")]
    squash = SquashView(stack)
    assert squash.open("app/config") == b"v2"
    assert squash.owner_ordinal("app/config") == 1
    # time travel: at layer 0 the old content is visible
    past = SquashView(stack, upto=0)
    assert past.open("app/config") == b"v1"


def test_coords_carry_layer_digest(tmp_path: Path) -> None:
    stack = _stack([{"a": b"1"}, {"b": b"2"}], tmp_path)
    squash = SquashView(stack)
    coords_b = squash.coords("b")
    assert coords_b.layer_digest is not None
    assert coords_b.layer_digest == stack.layers[1].diff_id


def test_normalize_created_by() -> None:
    assert normalize_created_by("/bin/sh -c #(nop) COPY file:abc in /") == "COPY file:abc in /"
    assert normalize_created_by("/bin/sh -c apt-get install -y curl") == "RUN apt-get install -y curl"
    assert normalize_created_by("RUN /bin/sh -c make # buildkit") == "RUN /bin/sh -c make"


def test_link_history_skips_empty_layers() -> None:
    config = {
        "history": [
            {"created_by": "/bin/sh -c #(nop) FROM debian"},
            {"created_by": "/bin/sh -c #(nop) ENV X=1", "empty_layer": True},
            {"created_by": "/bin/sh -c apt-get install -y curl"},
        ]
    }
    linked = link_history(config, 2)
    assert len(linked) == 2
    assert linked[0].command == "FROM debian"
    assert linked[1].command == "RUN apt-get install -y curl"


def test_link_dockerfile_lines() -> None:
    config = {
        "history": [
            {"created_by": "/bin/sh -c #(nop) FROM debian:12"},
            {"created_by": "/bin/sh -c apt-get install -y curl"},
        ]
    }
    dockerfile = "# comment\nFROM debian:12\n\nRUN apt-get install \\\n    -y curl\n"
    linked = link_dockerfile(link_history(config, 2), dockerfile)
    assert linked[1].dockerfile_line == 4


def test_diff_timeline_upgrade_and_removal() -> None:
    states = {
        0: {("deb", "curl"): "8.4.0-1", ("deb", "leftme"): "1.0-1", ("deb", "libssl3"): "3.0.13-1"},
        3: {("deb", "curl"): "8.5.0-1", ("deb", "libssl3"): "3.0.13-1"},
    }
    events = {(e.kind, e.name): e for e in diff_timeline(states)}
    up = events[("upgraded", "curl")]
    assert up.old_version == "8.4.0-1" and up.new_version == "8.5.0-1"
    assert up.old_ordinal == 0 and up.new_ordinal == 3
    gone = events[("removed", "leftme")]
    assert gone.old_version == "1.0-1" and gone.new_ordinal == 3
    assert first_seen(states, ("deb", "libssl3"), "3.0.13-1") == 0
    assert first_seen(states, ("deb", "curl"), "8.5.0-1") == 3


@pytest.fixture()
def upgraded_image_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Fixture: apt upgrade mid-build + a deleted package."""
    monkeypatch.setenv("SORB_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    bundle = build_image(
        [
            {
                "var/lib/dpkg/status": DPKG_STATUS_V1.encode(),
                "etc/os-release": OS_RELEASE_DEBIAN.encode(),
            },
            {"var/lib/dpkg/status": DPKG_STATUS_V2.encode()},
        ],
        history=["FROM debian:12", "apt-get upgrade -y && apt-get purge leftme"],
        ref_name="acme/api:1.2",
    )
    root = write_oci_layout(bundle, tmp_path / "layout")
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(f"oci-dir:{root}", cfg, store_path=tmp_path / "run.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    yield result, store
    store.close()


def test_pkgdb_time_travel_shows_both_versions(upgraded_image_scan) -> None:
    _result, store = upgraded_image_scan
    curls = store.find_component("curl")
    versions = {c.version: c for c in curls}
    assert set(versions) == {"8.5.0-1", "8.4.0-1"}

    final = versions["8.5.0-1"]
    old = versions["8.4.0-1"]
    assert final.attrs.get("state") is None
    assert old.attrs["state"] == "superseded"
    assert old.attrs["excluded"]  # not emitted by default
    assert old.attrs["layer_ordinal"] == 0

    # SUPERSEDES chain new → old
    supersedes = [e for e in store.edges() if e["kind"] == "SUPERSEDES"]
    assert any(e["src"] == final.id and e["dst"] == old.id for e in supersedes)

    codes = {a["code"] for a in store.all_annotations()}
    assert "pkgdb-upgraded" in codes


def test_removed_package_has_state_removed_with_both_layers(upgraded_image_scan) -> None:
    _result, store = upgraded_image_scan
    left = store.find_component("leftme")
    assert left, "deleted package must still exist in the graph"
    comp = left[0]
    assert comp.attrs["state"] == "removed"
    assert comp.attrs["layer_ordinal"] == 0
    assert comp.attrs["removed_in_layer"] == 1
    anns = store.annotations_for("component", comp.id)
    assert any(a["code"] == "pkgdb-removed" for a in anns)
    # evidence still present (G3: no component without evidence)
    assert store.evidence_for_component(comp.id)


def test_removed_excluded_from_sbom_unless_flag(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SORB_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    bundle = build_image(
        [
            {
                "var/lib/dpkg/status": DPKG_STATUS_V1.encode(),
                "etc/os-release": OS_RELEASE_DEBIAN.encode(),
            },
            {"var/lib/dpkg/status": DPKG_STATUS_V2.encode()},
        ],
        ref_name="acme/api:1.2",
    )
    root = write_oci_layout(bundle, tmp_path / "layout")

    from sorb.emit.canonical import emitted_components

    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    r1 = run_scan(f"oci-dir:{root}", cfg, store_path=tmp_path / "one.sorb.db")
    s1 = GraphStore.open_readonly(r1.store_path)
    names1 = {c.name for c in emitted_components(s1)}
    s1.close()
    assert "leftme" not in names1

    cfg2 = load_config(
        flags={"include_removed": True}, env={}, user_config_path=tmp_path / "nc.toml"
    )
    r2 = run_scan(f"oci-dir:{root}", cfg2, store_path=tmp_path / "two.sorb.db")
    s2 = GraphStore.open_readonly(r2.store_path)
    names2 = {c.name for c in emitted_components(s2)}
    s2.close()
    assert "leftme" in names2


def test_explain_names_layer_and_created_by(upgraded_image_scan) -> None:
    """Explain names the layer ordinal + created_by command."""
    _result, store = upgraded_image_scan
    text = explain(store, "curl@8.5.0-1")
    assert text is not None
    assert "Introduced by layer 2" in text
    assert "RUN apt-get upgrade -y && apt-get purge leftme" in text


def test_file_states_persisted(upgraded_image_scan) -> None:
    _result, store = upgraded_image_scan
    states = store.file_states("var/lib/dpkg/status")
    assert [s["state"] for s in states] == ["added", "modified"]
    assert [s["ordinal"] for s in states] == [0, 1]


def _layered_store(tmp_path):  # noqa: ANN001, ANN202
    """A two-layer image store with churn and per-layer components."""
    from sorb.graph.store import GraphStore

    store = GraphStore.create(tmp_path / "layers.sorb.db")
    store.add_source("s1", "oci", "demo", {})
    store.set_meta("target", "image:demo:1")
    for ordinal, digest, made in ((0, "sha256:aa", "ADD rootfs /"), (1, "sha256:bb", "RUN apk add curl")):
        store.add_layer(digest, "s1", ordinal, made)
    for path, digest, ordinal, state in (
        ("bin/sh", "sha256:aa", 0, "added"),
        ("etc/os-release", "sha256:aa", 0, "added"),
        ("usr/bin/curl", "sha256:bb", 1, "added"),
        ("etc/os-release", "sha256:bb", 1, "modified"),
        ("bin/sh", "sha256:bb", 1, "removed"),
    ):
        store.add_file_state("s1", path, digest, ordinal, state)
    store.add_component(
        purl="pkg:apk/alpine/musl@1.2.5", ctype="os-package", name="musl", version="1.2.5",
        qualifiers={}, hashes={}, confidence=0.95, tier_cap=4,
        attrs={"ecosystem": "apk", "layer_ordinal": 0, "from_base_image": "alpine:3.20"},
    )
    store.add_component(
        purl="pkg:apk/alpine/curl@8.11.0", ctype="os-package", name="curl", version="8.11.0",
        qualifiers={}, hashes={}, confidence=0.95, tier_cap=4,
        attrs={"ecosystem": "apk", "layer_ordinal": 1},
    )
    store.commit()
    return store


def test_layer_stack_json_counts_churn_and_components(tmp_path) -> None:
    """The UI layer stack reports what each layer changed and introduced."""
    from sorb.ui.server import _layers_json

    store = _layered_store(tmp_path)
    try:
        rows = {row["ordinal"]: row for row in _layers_json(store)["layers"]}
        assert rows[0]["added"] == 2 and rows[0]["components"] == 1
        assert rows[0]["from_base_image"] is True
        assert rows[1]["added"] == 1 and rows[1]["modified"] == 1 and rows[1]["removed"] == 1
        assert rows[1]["components"] == 1 and rows[1]["from_base_image"] is False
        assert rows[1]["created_by"] == "RUN apk add curl"
    finally:
        store.close()


def test_cli_layers_report_matches_the_stack(tmp_path, capsys) -> None:
    """`sorb layers` renders the same facts the UI draws, from the same store."""
    from sorb.cli.main import _render_layers

    store = _layered_store(tmp_path)
    try:
        _render_layers(store, "image:demo:1", None)
        out = capsys.readouterr().out
        assert "2 layers" in out
        assert "RUN apk add curl" in out
        assert "(base)" in out  # layer 0 came from the base image

        _render_layers(store, "image:demo:1", 1)
        detail = capsys.readouterr().out
        assert "curl@8.11.0" in detail
        assert "musl" not in detail  # layer 1 did not introduce musl
    finally:
        store.close()
