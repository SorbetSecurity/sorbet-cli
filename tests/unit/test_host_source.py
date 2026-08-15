"""LiveHostSource + runtime augmentation.

A synthetic host root is built deterministically (OS package DB, kernel virtual
files, a running process with a listening socket, a docker image), scanned via
`host://`, and asserted end-to-end — no real `/proc`, no network.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.graph.store import GraphStore
from sorb.query import run_query
from sorb.source.host import LiveHostSource, discover_store_roots

_DPKG_STATUS = """\
Package: nginx
Status: install ok installed
Architecture: amd64
Version: 1.24.0-1
Description: web server

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1
Description: Secure Sockets Layer toolkit

Package: coreutils
Status: install ok installed
Architecture: amd64
Version: 9.1-1
Description: core utilities
"""


def _build_host(root: Path) -> None:
    # OS package DB (dpkg)
    dpkg = root / "var/lib/dpkg"
    dpkg.mkdir(parents=True)
    (dpkg / "status").write_text(_DPKG_STATUS)
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="22.04"\n')

    # kernel virtual files
    proc = root / "proc"
    proc.mkdir(parents=True)
    (proc / "version").write_text(
        "Linux version 5.15.0-91-generic (buildd@lcy02) (gcc 11) #101-Ubuntu SMP\n"
    )
    (proc / "modules").write_text(
        "nf_tables 200704 1 - Live 0xffffffffc0a00000\n"
        "overlay 151552 1 - Live 0xffffffffc0900000\n"
    )

    # a running nginx process (pid 1000) linking libssl, listening on :80
    pid = proc / "1000"
    (pid / "fd").mkdir(parents=True)
    (pid / "comm").write_text("nginx\n")
    (pid / "exe").write_text("/usr/sbin/nginx")  # _readlink also reads plain files
    (pid / "maps").write_text(
        "5566aa000-5566bb000 r-xp 00000000 08:01 100 /usr/sbin/nginx\n"
        "7f00aa000-7f00bb000 r-xp 00000000 08:01 200 /usr/lib/x86_64-linux-gnu/libssl.so.3\n"
    )
    os.symlink("socket:[12345]", pid / "fd" / "3")
    # /proc/net/tcp: one LISTEN entry on port 0x0050 (80), inode 12345
    (proc / "net").mkdir()
    (proc / "net/tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000  0 12345 1 0000 100 0 0 10 0\n"
    )

    # a docker image on disk (sub-target)
    dimg = root / "var/lib/docker/image/overlay2"
    dimg.mkdir(parents=True)
    (dimg / "repositories.json").write_text(
        '{"Repositories": {"nginx": {"nginx:latest": "sha256:abc"}}}'
    )

    # noise OUTSIDE any store — must never be walked
    (root / "var/log").mkdir(parents=True)
    (root / "var/log/huge.log").write_text("x" * 10000)
    (root / "etc/passwd").write_text("root:x:0:0::/root:/bin/bash\n")


@pytest.fixture()
def scanned_host(tmp_path: Path):
    root = tmp_path / "hostroot"
    root.mkdir()
    _build_host(root)
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(f"host://{root}", cfg, store_path=tmp_path / "host.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    yield store
    store.close()


# -- store discovery ---------------------------------------------------------------------


def test_store_discovery_is_bounded(tmp_path: Path) -> None:
    root = tmp_path / "hostroot"
    root.mkdir()
    _build_host(root)
    roots = discover_store_roots(root)
    names = {str(p.relative_to(root)) for p in roots}
    assert "var/lib/dpkg" in names
    # noise dirs are never store roots
    assert "var/log" not in names and "etc" not in names


def test_host_walk_skips_non_store_files(tmp_path: Path) -> None:
    root = tmp_path / "hostroot"
    root.mkdir()
    _build_host(root)
    walked = {e.path for e in LiveHostSource(root=root).walk()}
    assert "var/lib/dpkg/status" in walked
    assert "proc/version" in walked and "proc/modules" in walked
    # the full-disk-crawl guarantee: noise files are never yielded
    assert "var/log/huge.log" not in walked
    assert "etc/passwd" not in walked


def test_host_scan_finds_os_packages(scanned_host: GraphStore) -> None:
    names = {c.name for c in scanned_host.components()}
    assert {"nginx", "openssl", "coreutils"} <= names


def test_kernel_and_modules_are_platform_components(scanned_host: GraphStore) -> None:
    comps = {c.name: c for c in scanned_host.components()}
    assert "linux-kernel" in comps
    assert comps["linux-kernel"].tier.label == "observed"
    assert comps["linux-kernel"].attrs.get("kind") == "kernel"
    assert "nf_tables" in comps and comps["nf_tables"].attrs.get("kind") == "kernel-module"


# -- runtime augmentation ----------------------------------------------------------------


def test_running_service_is_observed_with_port(scanned_host: GraphStore) -> None:
    nginx = next(c for c in scanned_host.components() if c.name == "nginx")
    assert nginx.attrs.get("observed") == "true"
    assert nginx.attrs.get("observed_ports") == "80"  # "what is exposed"


def test_loaded_library_attributes_to_package(scanned_host: GraphStore) -> None:
    # nginx maps libssl.so.3 → openssl marked observed (soname alias)
    openssl = next(c for c in scanned_host.components() if c.name == "openssl")
    assert openssl.attrs.get("observed") == "true"


def test_non_running_package_is_not_observed(scanned_host: GraphStore) -> None:
    coreutils = next(c for c in scanned_host.components() if c.name == "coreutils")
    assert coreutils.attrs.get("observed") is None


def test_observed_query_answerable(scanned_host: GraphStore) -> None:
    """'what is exposed and what code is it?' — answerable via a query."""
    result = run_query(scanned_host, "components where observed = true")
    observed = {r["name"] for r in result.rows}
    assert "nginx" in observed and "openssl" in observed
    assert "coreutils" not in observed


# -- container sub-targets ---------------------------------------------------------------


def test_docker_image_listed_as_subtarget(scanned_host: GraphStore) -> None:
    import json

    subs = json.loads(scanned_host.get_meta("subtargets") or "[]")
    refs = {s["ref"] for s in subs}
    assert "image:nginx:latest" in refs
    ann = [a for a in scanned_host.all_annotations() if a["code"] == "container-subtarget"]
    assert ann
