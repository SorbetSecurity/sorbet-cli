"""Base-image identification (+data-pack loader), attestation
verify-ingest, the layer cache, and running containers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from container_fixtures import (  # noqa: E402
    DPKG_STATUS_V1,
    OS_RELEASE_DEBIAN,
    build_image,
    make_layer_tar,
    registry_transport,
    write_oci_layout,
)
from sorb.cache import Cas  # noqa: E402
from sorb.container.baseimage import identify_base, load_pack  # noqa: E402
from sorb.container.spec import parse_container_spec  # noqa: E402
from sorb.core.config import load_config  # noqa: E402
from sorb.core.container_scan import run_container_scan  # noqa: E402
from sorb.core.events import ProgressBus  # noqa: E402
from sorb.core.pipeline import run_scan  # noqa: E402
from sorb.errors import SubsystemDegraded  # noqa: E402
from sorb.graph.store import GraphStore  # noqa: E402


def _write_pack(packs_dir: Path, images: list[dict]) -> None:
    pack_dir = packs_dir / "base-images" / "1.0.0"
    pack_dir.mkdir(parents=True)
    pack_dir.joinpath("base_images.json").write_text(
        json.dumps(
            {"name": "base-images", "schema": 1, "min_sorb_version": "0.1.0", "images": images}
        )
    )


def _diff_id(files: dict[str, bytes]) -> str:
    return "sha256:" + hashlib.sha256(make_layer_tar(files)).hexdigest()


BASE_FILES = {
    "var/lib/dpkg/status": DPKG_STATUS_V1.encode(),
    "etc/os-release": OS_RELEASE_DEBIAN.encode(),
}
APP_FILES = {
    "app/node_modules/lodash/package.json": b'{"name": "lodash", "version": "4.17.21"}'
}


def test_pack_loader_validates(tmp_path: Path) -> None:
    packs = tmp_path / "packs"
    _write_pack(packs, [])
    assert load_pack(packs)["images"] == []

    bad = tmp_path / "bad-packs" / "base-images" / "2.0.0"
    bad.mkdir(parents=True)
    bad.joinpath("base_images.json").write_text(
        json.dumps({"name": "base-images", "schema": 99, "min_sorb_version": "0.1.0", "images": []})
    )
    with pytest.raises(SubsystemDegraded, match="schema"):
        load_pack(tmp_path / "bad-packs")

    newer = tmp_path / "newer-packs" / "base-images" / "3.0.0"
    newer.mkdir(parents=True)
    newer.joinpath("base_images.json").write_text(
        json.dumps(
            {"name": "base-images", "schema": 1, "min_sorb_version": "99.0", "images": []}
        )
    )
    with pytest.raises(SubsystemDegraded, match="requires sorb"):
        load_pack(tmp_path / "newer-packs")


def test_identify_base_layer_chain_and_annotation(tmp_path: Path) -> None:
    packs = tmp_path / "packs"
    base_diff = _diff_id(BASE_FILES)
    _write_pack(packs, [{"name": "debian:12.5", "diff_ids": [base_diff]}])

    hit = identify_base([base_diff, _diff_id(APP_FILES)], {}, packs)
    assert hit is not None and hit.name == "debian:12.5"
    assert hit.boundary == 1 and hit.method == "layer-chain"

    # unknown chain, no annotation → honest None
    assert identify_base(["sha256:" + "9" * 64], {}, packs) is None

    # unknown chain + OCI annotation → named base, unknown boundary
    ann = identify_base(
        ["sha256:" + "9" * 64],
        {"org.opencontainers.image.base.name": "alpine:3.19"},
        packs,
    )
    assert ann is not None and ann.name == "alpine:3.19"
    assert ann.boundary is None and ann.method == "oci-annotation"


def test_scan_splits_base_vs_added(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    cache_dir = Path(os.environ["SORB_CACHE_DIR"])
    _write_pack(cache_dir / "packs", [{"name": "debian:12.5", "diff_ids": [_diff_id(BASE_FILES)]}])

    bundle = build_image(
        [BASE_FILES, APP_FILES],
        history=["FROM debian:12.5", "COPY app /app"],
        ref_name="acme/api:1.2",
    )
    root = write_oci_layout(bundle, tmp_path / "layout")
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(f"oci-dir:{root}", cfg, store_path=tmp_path / "run.sorb.db")

    store = GraphStore.open_readonly(result.store_path)
    try:
        assert store.get_meta("base_image") == "debian:12.5"
        assert store.get_meta("base_image_boundary") == "1"
        comps = {c.name: c for c in store.components()}
        assert comps["curl"].attrs.get("from_base_image") == "debian:12.5"
        assert comps["lodash"].attrs.get("from_base_image") is None
        assert comps["lodash"].attrs["layer_ordinal"] == 1
    finally:
        store.close()


# -- attestation verify-ingest ---------------------------------------------------------


def _dsse_envelope(cyclonedx: dict) -> bytes:
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://cyclonedx.org/bom",
        "predicate": cyclonedx,
    }
    return json.dumps(
        {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
            "signatures": [{"sig": "unchecked-here"}],
        }
    ).encode()


def _attested_scan(tmp_path: Path, attestation_components: list[dict], monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    bundle = build_image(
        [BASE_FILES],
        history=["FROM debian:12"],
        ref_name="acme/api:1.2",
    )
    envelope = _dsse_envelope(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": attestation_components}
    )
    env_digest = "sha256:" + hashlib.sha256(envelope).hexdigest()
    att_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": env_digest, "size": 2},
        "layers": [
            {
                "mediaType": "application/vnd.dsse.envelope.v1+json",
                "digest": env_digest,
                "size": len(envelope),
            }
        ],
    }
    att_manifest_bytes = json.dumps(att_manifest).encode()
    att_digest = "sha256:" + hashlib.sha256(att_manifest_bytes).hexdigest()

    base = registry_transport(
        {"1.2": bundle},
        referrers={
            bundle.manifest_digest: [
                {"digest": att_digest, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                 "artifactType": "application/vnd.cyclonedx+json"}
            ]
        },
        extra_blobs={env_digest: envelope},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/v2/acme/api/manifests/{att_digest}":
            return httpx.Response(200, content=att_manifest_bytes)
        return base.handler(request)  # type: ignore[attr-defined]

    spec = parse_container_spec("image:registry.test/acme/api:1.2")
    assert spec is not None
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_container_scan(
        spec,
        cfg,
        ProgressBus(),
        store_path=tmp_path / "attested.sorb.db",
        cas=Cas(tmp_path / "cas"),
        transport=httpx.MockTransport(handler),
    )
    return result


def test_wrong_attestation_produces_mismatch_findings(tmp_path: Path, monkeypatch) -> None:
    """A deliberately wrong attached SBOM produces mismatch
    findings — never blended results."""
    result = _attested_scan(
        tmp_path,
        [
            {"name": "curl", "version": "9.9.9", "purl": "pkg:deb/debian/curl@9.9.9"},
            {"name": "ghost-package", "version": "1.0", "purl": "pkg:deb/debian/ghost-package@1.0"},
            {"name": "libssl3", "version": "3.0.13-1", "purl": "pkg:deb/debian/libssl3@3.0.13-1"},
        ],
        monkeypatch,
    )
    assert any(code == "SORB-W033" for code, _ in result.warnings)

    store = GraphStore.open_readonly(result.store_path)
    try:
        annotations = store.all_annotations()
        mismatches = [a for a in annotations if a["code"] == "drift:attestation-mismatch"]
        details = " | ".join(a["detail"] for a in mismatches)
        assert "curl" in details and "9.9.9" in details  # version disagreement
        assert "ghost-package" in details  # claimed, not found
        # the ghost never became a component (no blending)
        assert not store.find_component("ghost-package")
        # agreement recorded as corroboration
        libssl = store.find_component("libssl3")[0]
        assert any(
            a["code"] == "attestation-corroborated"
            for a in store.annotations_for("component", libssl.id)
        )
    finally:
        store.close()


# -- layer cache across images ----------------------------------------------------------


def test_shared_base_layer_reanalysed_zero_times(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    cas = Cas(tmp_path / "shared-cas")
    cfg = load_config(
        flags={"profile": True}, env={}, user_config_path=tmp_path / "nc.toml"
    )

    image_a = build_image([BASE_FILES, {"app/a.txt": b"a"}], ref_name="acme/a:1")
    image_b = build_image([BASE_FILES, {"app/b.txt": b"b"}], ref_name="acme/b:1")
    root_a = write_oci_layout(image_a, tmp_path / "layout-a")
    root_b = write_oci_layout(image_b, tmp_path / "layout-b")

    spec_a = parse_container_spec(f"oci-dir:{root_a}")
    spec_b = parse_container_spec(f"oci-dir:{root_b}")
    assert spec_a and spec_b
    r1 = run_container_scan(spec_a, cfg, ProgressBus(), store_path=tmp_path / "a.db", cas=cas)
    r2 = run_container_scan(spec_b, cfg, ProgressBus(), store_path=tmp_path / "b.db", cas=cas)

    assert r1.profile["layer_cache_hits"] == 0
    assert r2.profile["layer_cache_hits"] == 1  # the shared base layer
    assert r2.profile["layer_cache_misses"] == 1  # only its own app layer

    # cached replay produces the same components
    s2 = GraphStore.open_readonly(r2.store_path)
    try:
        names = {c.name for c in s2.components()}
        assert {"curl", "libssl3", "leftme"} <= names
    finally:
        s2.close()


# -- running containers --------------------------------------------------------------------


def test_running_container_marks_entrypoint_observed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    sys.path.insert(0, str(Path(__file__).parent))
    from test_gobuildinfo import MODINFO, make_binary

    rootfs = make_layer_tar(
        {"usr/local/bin/server": make_binary(MODINFO), "etc/hostname": b"c1"}
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/containers/c1/export"):
            return httpx.Response(200, content=rootfs)
        if path.endswith("/containers/c1/json"):
            return httpx.Response(
                200,
                json={
                    "Id": "c1",
                    "Name": "/api-1",
                    "Image": "sha256:abc",
                    "Platform": "linux",
                    "Config": {"Entrypoint": ["/usr/local/bin/server"], "Cmd": ["--port", "8080"]},
                },
            )
        if path.endswith("/containers/c1/top"):
            return httpx.Response(
                200,
                json={
                    "Titles": ["PID", "CMD"],
                    "Processes": [["1", "/usr/local/bin/server --port 8080"]],
                },
            )
        return httpx.Response(404)

    spec = parse_container_spec("container://c1")
    assert spec is not None
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_container_scan(
        spec,
        cfg,
        ProgressBus(),
        store_path=tmp_path / "running.sorb.db",
        cas=Cas(tmp_path / "cas"),
        transport=httpx.MockTransport(handler),
    )
    store = GraphStore.open_readonly(result.store_path)
    try:
        apps = [c for c in store.components() if c.ctype == "application"]
        assert apps, "the Go entrypoint binary must be identified"
        app = apps[0]
        assert app.attrs.get("scope") == "runtime-observed"
        assert app.tier.label == "observed"
        assert any(
            a["code"] == "runtime-observed" for a in store.annotations_for("component", app.id)
        )
        assert any(e["kind"] == "OBSERVED_IN" for e in store.edges())
    finally:
        store.close()
