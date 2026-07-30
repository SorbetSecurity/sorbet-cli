"""Programmatic container-image fixtures for the container tests.

Builds format-exact images entirely in memory — OCI layouts, docker-archive
tars, and fake-registry blob maps — so container tests run fully offline
(socket-blocking guard).
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DPKG_STATUS_V1 = """Package: curl
Status: install ok installed
Version: 8.4.0-1
Architecture: amd64
Depends: libssl3 (>= 3.0.0)
Source: curl

Package: libssl3
Status: install ok installed
Version: 3.0.13-1
Architecture: amd64
Source: openssl

Package: leftme
Status: install ok installed
Version: 1.0-1
Architecture: amd64
"""

DPKG_STATUS_V2 = """Package: curl
Status: install ok installed
Version: 8.5.0-1
Architecture: amd64
Depends: libssl3 (>= 3.0.0)
Source: curl

Package: libssl3
Status: install ok installed
Version: 3.0.13-1
Architecture: amd64
Source: openssl
"""

OS_RELEASE_DEBIAN = 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n'


def make_layer_tar(files: dict[str, bytes]) -> bytes:
    """Deterministic uncompressed layer tar."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _gzip_deterministic(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()


@dataclass
class ImageBundle:
    """One built image: config + manifest + compressed layer blobs."""

    manifest_bytes: bytes
    manifest_digest: str
    config_bytes: bytes
    config_digest: str
    blobs: dict[str, bytes]  # digest → bytes (includes config + layers)
    layer_tars: list[bytes] = field(default_factory=list)  # uncompressed
    ref_name: str = "fixture:1.0"

    @property
    def manifest(self) -> dict[str, Any]:
        doc: dict[str, Any] = json.loads(self.manifest_bytes)
        return doc


def build_image(
    layers: list[dict[str, bytes]],
    *,
    history: list[str] | None = None,
    ref_name: str = "fixture:1.0",
    os_: str = "linux",
    arch: str = "amd64",
    annotations: dict[str, str] | None = None,
    entrypoint: list[str] | None = None,
) -> ImageBundle:
    """Build an OCI image from per-layer file maps. `history` gives one
    created_by string per layer (classic /bin/sh -c form when it starts with
    a lowercase word)."""
    layer_tars = [make_layer_tar(files) for files in layers]
    diff_ids = [_sha256(t) for t in layer_tars]
    compressed = [_gzip_deterministic(t) for t in layer_tars]

    history = history or [f"RUN layer-{i}" for i in range(len(layers))]
    config: dict[str, Any] = {
        "architecture": arch,
        "os": os_,
        "config": {"Env": ["PATH=/usr/bin"], **({"Entrypoint": entrypoint} if entrypoint else {})},
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
        "history": [
            {"created_by": cb if cb.startswith(("RUN ", "COPY ", "FROM ")) else f"/bin/sh -c {cb}"}
            for cb in history
        ],
    }
    config_bytes = json.dumps(config, sort_keys=True).encode()
    config_digest = _sha256(config_bytes)

    manifest: dict[str, Any] = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(config_bytes),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": _sha256(c),
                "size": len(c),
            }
            for c in compressed
        ],
    }
    if annotations:
        manifest["annotations"] = annotations
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()

    blobs = {config_digest: config_bytes}
    for c in compressed:
        blobs[_sha256(c)] = c
    return ImageBundle(
        manifest_bytes=manifest_bytes,
        manifest_digest=_sha256(manifest_bytes),
        config_bytes=config_bytes,
        config_digest=config_digest,
        blobs=blobs,
        layer_tars=layer_tars,
        ref_name=ref_name,
    )


def write_oci_layout(bundle: ImageBundle, root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}\n')
    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": bundle.manifest_digest,
                "size": len(bundle.manifest_bytes),
                "annotations": {"org.opencontainers.image.ref.name": bundle.ref_name},
            }
        ],
    }
    (root / "index.json").write_text(json.dumps(index, sort_keys=True))
    blob_dir = root / "blobs" / "sha256"
    blob_dir.mkdir(parents=True, exist_ok=True)
    for digest, data in bundle.blobs.items():
        (blob_dir / digest.partition(":")[2]).write_bytes(data)
    (blob_dir / bundle.manifest_digest.partition(":")[2]).write_bytes(bundle.manifest_bytes)
    return root


def write_docker_archive(bundle: ImageBundle, path: Path) -> Path:
    """Classic `docker save` format: manifest.json + uncompressed layer tars."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:

        def add(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            tf.addfile(info, io.BytesIO(data))

        config_name = bundle.config_digest.partition(":")[2] + ".json"
        add(config_name, bundle.config_bytes)
        layer_names = []
        for i, tar_bytes in enumerate(bundle.layer_tars):
            name = f"layer{i}/layer.tar"
            layer_names.append(name)
            add(name, tar_bytes)
        manifest = [
            {"Config": config_name, "RepoTags": [bundle.ref_name], "Layers": layer_names}
        ]
        add("manifest.json", json.dumps(manifest, sort_keys=True).encode())
    path.write_bytes(buf.getvalue())
    return path


def registry_transport(
    bundles: dict[str, ImageBundle],
    *,
    repo: str = "acme/api",
    auth: str | None = None,  # None | "token" | "basic"
    referrers: dict[str, list[dict[str, Any]]] | None = None,
    extra_blobs: dict[str, bytes] | None = None,
    fail_first: int = 0,
) -> Any:
    """httpx.MockTransport implementing enough of the Distribution API:
    tags, digests, blobs, token auth challenge, referrers. `bundles` maps
    tag → bundle; manifests are also addressable by digest."""
    import httpx

    by_digest: dict[str, bytes] = {}
    blobs: dict[str, bytes] = dict(extra_blobs or {})
    for bundle in bundles.values():
        by_digest[bundle.manifest_digest] = bundle.manifest_bytes
        blobs.update(bundle.blobs)
    state = {"failures_left": fail_first, "token_issued": False}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if state["failures_left"] > 0:
            state["failures_left"] -= 1
            return httpx.Response(503, text="temporarily unavailable")
        if path == "/token":
            if auth == "basic-at-token" and "authorization" not in request.headers:
                return httpx.Response(401, text="credentials required")
            state["token_issued"] = True
            return httpx.Response(200, json={"token": "test-token-abc"})
        authorized = (
            auth is None
            or (auth == "token" and request.headers.get("authorization") == "Bearer test-token-abc")
            or (auth == "basic" and request.headers.get("authorization", "").startswith("Basic "))
        )
        if not authorized:
            if auth == "token":
                return httpx.Response(
                    401,
                    headers={
                        "www-authenticate": (
                            'Bearer realm="https://registry.test/token",'
                            f'service="registry.test",scope="repository:{repo}:pull"'
                        )
                    },
                )
            return httpx.Response(401, headers={"www-authenticate": "Basic realm=registry"})
        if path.startswith(f"/v2/{repo}/manifests/"):
            ref = path.rsplit("/", 1)[-1]
            if ref in bundles:
                return httpx.Response(
                    200,
                    content=bundles[ref].manifest_bytes,
                    headers={"content-type": "application/vnd.oci.image.manifest.v1+json"},
                )
            if ref in by_digest:
                return httpx.Response(
                    200,
                    content=by_digest[ref],
                    headers={"content-type": "application/vnd.oci.image.manifest.v1+json"},
                )
            return httpx.Response(404)
        if path.startswith(f"/v2/{repo}/blobs/"):
            digest = path.rsplit("/", 1)[-1]
            if digest in blobs:
                return httpx.Response(200, content=blobs[digest])
            return httpx.Response(404)
        if path.startswith(f"/v2/{repo}/referrers/"):
            digest = path.rsplit("/", 1)[-1]
            manifests = (referrers or {}).get(digest, [])
            return httpx.Response(
                200,
                json={"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests},
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)
