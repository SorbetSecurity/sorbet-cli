"""OCI registry client — auth paths, platform selection, blob
verification, retry, offline semantics, and registry-vs-local determinism.
All against an in-process fake Distribution API (socket guard proves no
network is touched)."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from container_fixtures import (  # noqa: E402
    DPKG_STATUS_V1,
    DPKG_STATUS_V2,
    OS_RELEASE_DEBIAN,
    build_image,
    registry_transport,
    write_oci_layout,
)
from sorb.cache import Cas  # noqa: E402
from sorb.container.registry import RegistryClient, load_registry_credentials  # noqa: E402
from sorb.container.spec import parse_image_ref  # noqa: E402
from sorb.core.config import load_config  # noqa: E402
from sorb.core.container_scan import run_container_scan  # noqa: E402
from sorb.core.events import ProgressBus  # noqa: E402
from sorb.core.pipeline import run_scan  # noqa: E402
from sorb.errors import TargetError  # noqa: E402


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


def _client(bundle, tmp_path: Path, **kwargs) -> RegistryClient:
    transport = registry_transport({"1.2": bundle}, **kwargs)
    return RegistryClient(
        parse_image_ref("registry.test/acme/api:1.2"),
        cas=Cas(tmp_path / "cas"),
        transport=transport,
    )


def test_anonymous_pull(bundle, tmp_path: Path) -> None:
    client = _client(bundle, tmp_path)
    image = client.resolve(None)
    assert image.digest == bundle.config_digest
    assert len(image.layers) == 2
    assert image.layer_tar(image.layers[0])  # decompresses gzip blob
    assert image.provenance_facts["manifest_digest"] == bundle.manifest_digest


def test_token_auth_flow(bundle, tmp_path: Path) -> None:
    client = _client(bundle, tmp_path, auth="token")
    image = client.resolve(None)
    assert image.digest == bundle.config_digest


def test_basic_auth_uses_docker_config(bundle, tmp_path: Path, monkeypatch) -> None:
    docker_dir = tmp_path / "docker"
    docker_dir.mkdir()
    auth = base64.b64encode(b"alice:s3cret").decode()
    (docker_dir / "config.json").write_text(
        json.dumps({"auths": {"registry.test": {"auth": auth}}})
    )
    monkeypatch.setenv("DOCKER_CONFIG", str(docker_dir))
    assert load_registry_credentials("registry.test") == ("alice", "s3cret")

    client = _client(bundle, tmp_path, auth="basic")
    image = client.resolve(None)
    assert image.digest == bundle.config_digest


def test_basic_auth_without_credentials_is_clear_error(bundle, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "empty"))
    client = _client(bundle, tmp_path, auth="basic")
    with pytest.raises(TargetError, match="credential"):
        client.resolve(None)


def test_retry_on_5xx(bundle, tmp_path: Path) -> None:
    client = _client(bundle, tmp_path, fail_first=1)
    image = client.resolve(None)
    assert image.digest == bundle.config_digest


def test_blob_digest_verified(bundle, tmp_path: Path) -> None:
    bad_digest = "sha256:" + "0" * 64
    transport = registry_transport({"1.2": bundle}, extra_blobs={bad_digest: b"tampered"})
    client = RegistryClient(
        parse_image_ref("registry.test/acme/api:1.2"),
        cas=Cas(tmp_path / "cas"),
        transport=transport,
    )
    with pytest.raises(TargetError, match="digest mismatch"):
        client.fetch_blob(bad_digest)


def test_platform_selection_and_listing(tmp_path: Path) -> None:
    amd = build_image([{"bin/app": b"amd64"}], ref_name="multi:1")
    arm = build_image([{"bin/app": b"arm64!"}], ref_name="multi:1", arch="arm64")
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": amd.manifest_digest,
                "size": len(amd.manifest_bytes),
                "platform": {"os": "linux", "architecture": "amd64"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": arm.manifest_digest,
                "size": len(arm.manifest_bytes),
                "platform": {"os": "linux", "architecture": "arm64"},
            },
        ],
    }
    import hashlib

    import httpx

    index_bytes = json.dumps(index, sort_keys=True).encode()
    blobs = {**amd.blobs, **arm.blobs}
    by_digest = {
        amd.manifest_digest: amd.manifest_bytes,
        arm.manifest_digest: arm.manifest_bytes,
        "sha256:" + hashlib.sha256(index_bytes).hexdigest(): index_bytes,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/v2/acme/multi/manifests/"):
            ref = path.rsplit("/", 1)[-1]
            if ref == "1":
                return httpx.Response(200, content=index_bytes)
            if ref in by_digest:
                return httpx.Response(200, content=by_digest[ref])
        if path.startswith("/v2/acme/multi/blobs/"):
            digest = path.rsplit("/", 1)[-1]
            if digest in blobs:
                return httpx.Response(200, content=blobs[digest])
        return httpx.Response(404)

    client = RegistryClient(
        parse_image_ref("registry.test/acme/multi:1"),
        cas=Cas(tmp_path / "cas"),
        transport=httpx.MockTransport(handler),
    )
    assert client.platforms() == ["linux/amd64", "linux/arm64"]
    image = client.resolve("linux/arm64")
    assert image.platform == "linux/arm64"
    assert image.digest == arm.config_digest
    with pytest.raises(TargetError, match="platform"):
        client.resolve("linux/s390x")


def test_offline_without_cache_is_typed_error(bundle, tmp_path: Path) -> None:
    client = RegistryClient(
        parse_image_ref("registry.test/acme/api:1.2"),
        cas=Cas(tmp_path / "cas"),
        offline=True,
        transport=registry_transport({"1.2": bundle}),
    )
    with pytest.raises(TargetError, match="offline"):
        client.resolve(None)


def test_offline_serves_from_cache(bundle, tmp_path: Path) -> None:
    cas = Cas(tmp_path / "cas")
    online = RegistryClient(
        parse_image_ref("registry.test/acme/api:1.2"),
        cas=cas,
        transport=registry_transport({"1.2": bundle}),
    )
    image = online.resolve(None)
    for layer in image.layers:
        image.blob_opener(layer)  # populate the CAS

    offline = RegistryClient(
        parse_image_ref("registry.test/acme/api:1.2"),
        cas=cas,
        offline=True,
        transport=registry_transport({}),  # would 404 if touched
    )
    cached = offline.resolve(None)
    assert cached.digest == image.digest
    assert cached.layer_tar(cached.layers[0])


def test_registry_scan_matches_local_scan_serial(bundle, tmp_path: Path, monkeypatch) -> None:
    """The same image via registry and OCI layout yields the identical
    document serial."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")

    layout = write_oci_layout(bundle, tmp_path / "layout")
    local = run_scan(f"oci-dir:{layout}", cfg, store_path=tmp_path / "local.sorb.db")

    from sorb.container.spec import parse_container_spec

    spec = parse_container_spec("image:registry.test/acme/api:1.2")
    assert spec is not None
    remote = run_container_scan(
        spec,
        cfg,
        ProgressBus(),
        store_path=tmp_path / "remote.sorb.db",
        cas=Cas(tmp_path / "cas"),
        transport=registry_transport({"1.2": bundle}),
    )
    # image ID is the subject → identical document identity across paths
    assert remote.subject == local.subject
    assert remote.serial == local.serial


# -- platform variants ------------------------------------------------------------------

_ARM_INDEX = {
    "manifests": [
        {"digest": "sha256:a" * 1, "platform": {"os": "linux", "architecture": "amd64"}},
        {"digest": "v6", "platform": {"os": "linux", "architecture": "arm", "variant": "v6"}},
        {"digest": "v7", "platform": {"os": "linux", "architecture": "arm", "variant": "v7"}},
        {"digest": "a64", "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
        {
            "digest": "att",
            "platform": {"os": "unknown", "architecture": "unknown"},
            "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
        },
    ]
}


def test_index_platforms_keeps_variants() -> None:
    """linux/arm/v6 and linux/arm/v7 are different images.

    Collapsing them to `linux/arm` made --all-platforms scan one twice and skip
    the other, while still reporting the full platform count.
    """
    from sorb.container.image import index_platforms

    got = index_platforms(_ARM_INDEX)
    assert got == ["linux/amd64", "linux/arm/v6", "linux/arm/v7", "linux/arm64/v8"]
    assert len(got) == len(set(got)), "every platform must be distinctly addressable"


def test_select_manifest_honors_requested_variant() -> None:
    from sorb.container.image import select_manifest_from_index

    desc, resolved = select_manifest_from_index(_ARM_INDEX, "linux/arm/v7")
    assert desc["digest"] == "v7" and resolved == "linux/arm/v7"
    desc, resolved = select_manifest_from_index(_ARM_INDEX, "linux/arm/v6")
    assert desc["digest"] == "v6" and resolved == "linux/arm/v6"
    # no variant asked for: first matching architecture, reported with its variant
    desc, resolved = select_manifest_from_index(_ARM_INDEX, "linux/arm")
    assert desc["digest"] == "v6" and resolved == "linux/arm/v6"
    desc, resolved = select_manifest_from_index(_ARM_INDEX, "linux/arm64")
    assert desc["digest"] == "a64" and resolved == "linux/arm64/v8"


def test_select_manifest_rejects_absent_variant() -> None:
    from sorb.container.image import select_manifest_from_index
    from sorb.errors import TargetError

    with pytest.raises(TargetError) as excinfo:
        select_manifest_from_index(_ARM_INDEX, "linux/arm/v8")
    assert "linux/arm/v7" in str(excinfo.value)  # the available list names variants
