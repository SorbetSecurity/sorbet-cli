"""Local container sources — OCI layout, docker-archive, spec grammar,
and determinism across acquisition paths (identical serial + SBOM bytes)."""

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
    write_docker_archive,
    write_oci_layout,
)
from sorb.container.local import open_docker_archive, open_oci_layout  # noqa: E402
from sorb.container.spec import parse_container_spec, parse_image_ref  # noqa: E402
from sorb.core.config import load_config  # noqa: E402
from sorb.core.pipeline import run_scan  # noqa: E402
from sorb.emit.cyclonedx import emit_cyclonedx  # noqa: E402
from sorb.errors import TargetError  # noqa: E402
from sorb.graph.store import GraphStore  # noqa: E402


def test_spec_parsing() -> None:
    assert parse_container_spec("image:nginx:1.27").kind == "registry"
    assert parse_container_spec("oci-dir:/tmp/layout").kind == "oci-layout"
    assert parse_container_spec("docker-archive:api.tar").kind == "docker-archive"
    assert parse_container_spec("container://abc123").kind == "running"
    assert parse_container_spec("docker:nginx").kind == "daemon"
    assert parse_container_spec("podman:nginx").kind == "podman"
    assert parse_container_spec("containerd:docker.io/library/x:1").kind == "containerd"
    assert parse_container_spec("./some/dir") is None
    assert parse_container_spec("requirements.txt") is None


def test_image_ref_grammar() -> None:
    r = parse_image_ref("nginx")
    assert r.registry == "registry-1.docker.io"
    assert r.repository == "library/nginx" and r.tag is None
    assert r.familiar() == "nginx:latest"

    r = parse_image_ref("ghcr.io/acme/api:1.2")
    assert r.registry == "ghcr.io" and r.repository == "acme/api" and r.tag == "1.2"

    r = parse_image_ref("localhost:5000/team/app@sha256:" + "a" * 64)
    assert r.registry == "localhost:5000"
    assert r.digest == "sha256:" + "a" * 64

    r = parse_image_ref("acme/api")
    assert r.repository == "acme/api" and r.registry == "registry-1.docker.io"


@pytest.fixture()
def bundle():
    return build_image(
        [
            {
                "var/lib/dpkg/status": DPKG_STATUS_V1.encode(),
                "etc/os-release": OS_RELEASE_DEBIAN.encode(),
            },
            {"var/lib/dpkg/status": DPKG_STATUS_V2.encode()},
        ],
        history=["FROM debian:12", "apt-get install -y curl"],
        ref_name="acme/api:1.2",
    )


def test_open_oci_layout(bundle, tmp_path: Path) -> None:
    root = write_oci_layout(bundle, tmp_path / "layout")
    img = open_oci_layout(str(root), None)
    assert img.digest == bundle.config_digest  # image ID as identity
    assert len(img.layers) == 2
    assert img.layers[0].diff_id is not None
    tar0 = img.layer_tar(img.layers[0])
    assert b"curl" in tar0
    assert img.platform == "linux/amd64"


def test_open_oci_layout_tag_selection(bundle, tmp_path: Path) -> None:
    root = write_oci_layout(bundle, tmp_path / "layout")
    img = open_oci_layout(f"{root}#acme/api:1.2", None)
    assert img.ref == "acme/api:1.2"
    with pytest.raises(TargetError):
        open_oci_layout(f"{root}#missing-tag", None)


def test_open_docker_archive(bundle, tmp_path: Path) -> None:
    tar_path = write_docker_archive(bundle, tmp_path / "api.tar")
    img = open_docker_archive(str(tar_path), None)
    assert img.digest == bundle.config_digest
    assert img.ref == "acme/api:1.2"
    assert len(img.layers) == 2
    # docker-archive layers are uncompressed; diff_ids come from the config
    import hashlib

    expected_diff = "sha256:" + hashlib.sha256(bundle.layer_tars[0]).hexdigest()
    assert img.layers[0].diff_id == expected_diff


def test_identical_sbom_across_acquisition_paths(
    bundle, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Registry-less paths (layout + archive) give identical
    serial AND identical CycloneDX bytes (the registry path is asserted in
    test_registry.py against the same bundle)."""
    monkeypatch.setenv("SORB_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))

    layout = write_oci_layout(bundle, tmp_path / "layout")
    archive = write_docker_archive(bundle, tmp_path / "api.tar")
    cfg = load_config(flags={"reproducible": True}, env={}, user_config_path=tmp_path / "nc.toml")

    r1 = run_scan(f"oci-dir:{layout}", cfg, store_path=tmp_path / "a.sorb.db")
    r2 = run_scan(f"docker-archive:{archive}", cfg, store_path=tmp_path / "b.sorb.db")
    assert r1.subject == r2.subject
    assert r1.serial == r2.serial

    s1, s2 = GraphStore.open_readonly(r1.store_path), GraphStore.open_readonly(r2.store_path)
    try:
        assert emit_cyclonedx(s1, reproducible=True) == emit_cyclonedx(s2, reproducible=True)
    finally:
        s1.close()
        s2.close()


def test_scan_populates_layers_and_attribution(
    bundle, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SORB_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    layout = write_oci_layout(bundle, tmp_path / "layout")
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(f"oci-dir:{layout}", cfg, store_path=tmp_path / "run.sorb.db")
    assert not result.had_scan_errors

    store = GraphStore.open_readonly(result.store_path)
    try:
        layers = store.layers()
        assert len(layers) == 2
        assert layers[1]["created_by"] == "/bin/sh -c apt-get install -y curl"

        comps = {c.name: c for c in store.components() if not c.attrs.get("state")}
        curl = comps["curl"]
        assert curl.version == "8.5.0-1"
        # curl 8.5.0 first appears in layer 2 (ordinal 1) — DB time travel attribution
        assert curl.attrs["layer_ordinal"] == 1
        assert curl.attrs["introduced_by"] == "RUN apt-get install -y curl"
        # libssl3 was present since the base layer even though the DB file
        # itself was rewritten in layer 2
        assert comps["libssl3"].attrs["layer_ordinal"] == 0

        # INTRODUCED_BY edges land on layer nodes
        introduced = store.edges()
        kinds = {e["kind"] for e in introduced}
        assert "INTRODUCED_BY" in kinds
    finally:
        store.close()


def test_daemon_api_version_is_negotiated() -> None:
    """A hardcoded API version ages into a total failure.

    Docker 29 reports MinAPIVersion 1.44 and answers 400 to every request under
    it, so the old `v1.43` pin broke `docker:` and `container://` outright.
    """
    import httpx

    from sorb.container.daemon import DaemonClient

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/version":
            return httpx.Response(200, json={"ApiVersion": "1.53", "MinAPIVersion": "1.44"})
        if not request.url.path.startswith("/v1.53/"):
            return httpx.Response(400, text="client version too old")  # what Docker 29 does
        return httpx.Response(200, json={"Id": "abc"})

    client = DaemonClient("/nonexistent.sock", transport=httpx.MockTransport(handler))
    assert client.container_inspect("abc") == {"Id": "abc"}
    assert "/version" in seen and "/v1.53/containers/abc/json" in seen
    # negotiated once, then remembered
    client.container_inspect("abc")
    assert seen.count("/version") == 1


def test_daemon_falls_back_when_version_unavailable() -> None:
    """An engine that will not answer /version still gets a usable prefix."""
    import httpx

    from sorb.container.daemon import DaemonClient

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/version":
            return httpx.Response(500)
        return httpx.Response(200, json={"Id": "abc"})

    client = DaemonClient("/nonexistent.sock", transport=httpx.MockTransport(handler))
    assert client.container_inspect("abc") == {"Id": "abc"}
