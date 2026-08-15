"""Local container sources.

- OCI image-layout directories (``oci-dir:path[#tag]``)
- ``docker save`` tarballs (``docker-archive:path``), classic and OCI-hybrid
- Docker / Podman daemon APIs over their unix sockets (``docker:``/``podman:``)
- containerd content store, direct read + boltdb metadata (``containerd:``)

Every path resolves to the same `ResolvedImage`; the **image ID (config
digest)** is the cross-acquisition identity used in scan subjects, so the same
image scanned via registry, archive, or layout yields the identical document
serial.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

from sorb.container.image import (
    MT_DOCKER_LIST,
    MT_OCI_INDEX,
    ImageLayer,
    ResolvedImage,
    layers_from_manifest,
    load_json_bytes,
    select_manifest_from_index,
    sha256_digest,
)
from sorb.errors import TargetError


def _blob_from_layout(root: Path, digest: str) -> bytes:
    algo, _, hexval = digest.partition(":")
    p = root / "blobs" / algo / hexval
    if not p.is_file():
        raise TargetError(f"blob {digest} missing from OCI layout {root}")
    return p.read_bytes()


def open_oci_layout(ref: str, platform: str | None) -> ResolvedImage:
    """``oci-dir:path[#tag]`` — an OCI image layout directory."""
    path_part, _, tag = ref.partition("#")
    root = Path(path_part)
    if not (root / "oci-layout").is_file():
        raise TargetError(f"{root} is not an OCI image layout (missing oci-layout file)")
    index = load_json_bytes((root / "index.json").read_bytes(), f"{root}/index.json")
    manifests = index.get("manifests", [])
    if not manifests:
        raise TargetError(f"OCI layout {root} has an empty index")
    desc: dict[str, Any] | None = None
    if tag:
        for cand in manifests:
            ann = cand.get("annotations") or {}
            if ann.get("org.opencontainers.image.ref.name") in (tag, f"{tag}:latest"):
                desc = cand
                break
        if desc is None:
            raise TargetError(f"tag {tag!r} not found in OCI layout {root}")
    else:
        desc = manifests[0]

    manifest_bytes = _blob_from_layout(root, str(desc["digest"]))
    doc = load_json_bytes(manifest_bytes, f"blob {desc['digest']}")
    resolved_platform = platform
    if doc.get("mediaType") in (MT_OCI_INDEX, MT_DOCKER_LIST) or "manifests" in doc:
        inner_desc, resolved_platform = select_manifest_from_index(doc, platform)
        manifest_bytes = _blob_from_layout(root, str(inner_desc["digest"]))
        doc = load_json_bytes(manifest_bytes, f"blob {inner_desc['digest']}")
    manifest_digest = sha256_digest(manifest_bytes)

    config_desc = doc.get("config") or {}
    config_bytes = _blob_from_layout(root, str(config_desc["digest"]))
    config = load_json_bytes(config_bytes, "image config")
    layers = layers_from_manifest(doc, config)

    ann = desc.get("annotations") or {}
    display_ref = ann.get("org.opencontainers.image.ref.name") or tag or root.name

    def opener(layer: ImageLayer) -> bytes:
        return _blob_from_layout(root, layer.digest)

    cfg_os = str(config.get("os", "linux"))
    cfg_arch = str(config.get("architecture", "unknown"))
    return ResolvedImage(
        ref=display_ref,
        digest=str(config_desc["digest"]),  # image ID: cross-acquisition identity
        platform=resolved_platform or f"{cfg_os}/{cfg_arch}",
        manifest=doc,
        config=config,
        layers=layers,
        blob_opener=opener,
        provenance_facts={
            "acquisition": "oci-layout",
            "layout_path": str(root),
            "manifest_digest": manifest_digest,
            "image_id": str(config_desc["digest"]),
        },
        annotations={**(doc.get("annotations") or {}), **ann},
    )


def open_docker_archive(ref: str, platform: str | None) -> ResolvedImage:
    path = Path(ref)
    if not path.is_file():
        raise TargetError(f"docker archive not found: {ref}")
    return open_docker_archive_bytes(path.read_bytes(), display=path.name, platform=platform)


def open_docker_archive_bytes(
    data: bytes, *, display: str, platform: str | None, acquisition: str = "docker-archive"
) -> ResolvedImage:
    """A `docker save` tar — classic (manifest.json) or OCI-hybrid layout."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as e:
        raise TargetError(f"cannot open docker archive {display}: {e}") from e
    names = set(tf.getnames())

    def member(name: str) -> bytes:
        for cand in (name, f"./{name}"):
            if cand in names:
                fobj = tf.extractfile(cand)
                if fobj is not None:
                    with fobj:
                        return fobj.read()
        raise TargetError(f"{display}: archive member {name!r} missing")

    if "manifest.json" not in names and "./manifest.json" not in names:
        raise TargetError(f"{display}: not a docker archive (no manifest.json)")
    entries = json.loads(member("manifest.json"))
    if not isinstance(entries, list) or not entries:
        raise TargetError(f"{display}: empty docker-archive manifest")
    entry = entries[0]

    config_bytes = member(str(entry["Config"]))
    config = load_json_bytes(config_bytes, f"{display}:{entry['Config']}")
    image_id = sha256_digest(config_bytes)

    layer_paths: list[str] = [str(p) for p in entry.get("Layers", [])]
    diff_ids: list[str] = list((config.get("rootfs") or {}).get("diff_ids") or [])
    layers: list[ImageLayer] = []
    blobs: dict[str, bytes] = {}
    for i, lp in enumerate(layer_paths):
        blob = member(lp)
        digest = sha256_digest(blob)
        blobs[digest] = blob
        layers.append(
            ImageLayer(
                digest=digest,
                diff_id=diff_ids[i] if i < len(diff_ids) else None,
                media_type="application/vnd.oci.image.layer.v1.tar",
                size=len(blob),
                ordinal=i,
            )
        )

    repo_tags = entry.get("RepoTags") or []
    display_ref = str(repo_tags[0]) if repo_tags else display

    def opener(layer: ImageLayer) -> bytes:
        return blobs[layer.digest]

    cfg_os = str(config.get("os", "linux"))
    cfg_arch = str(config.get("architecture", "unknown"))
    resolved_platform = platform or f"{cfg_os}/{cfg_arch}"
    return ResolvedImage(
        ref=display_ref,
        digest=image_id,
        platform=resolved_platform,
        manifest={"layers": [{"digest": la.digest, "mediaType": la.media_type} for la in layers]},
        config=config,
        layers=layers,
        blob_opener=opener,
        provenance_facts={"acquisition": acquisition, "image_id": image_id},
    )


# -- daemons (docker / podman) ---------------------------------------------------


def open_daemon_image(
    ref: str, platform: str | None, *, flavor: str = "docker", transport: Any | None = None
) -> ResolvedImage:
    """Pull `docker save` bytes from a local daemon and reuse the archive reader."""
    from sorb.container.daemon import DaemonClient

    client = DaemonClient.for_flavor(flavor, transport=transport)
    data = client.image_save(ref)
    img = open_docker_archive_bytes(
        data, display=ref, platform=platform, acquisition=f"{flavor}-daemon"
    )
    return img


# -- containerd content store ------------------------------------------------------


def open_containerd(ref: str, platform: str | None, root: Path | None = None) -> ResolvedImage:
    """Direct read of the containerd content store (+ boltdb metadata).

    ``containerd:<image name>[?namespace=<ns>]`` — e.g.
    ``containerd:docker.io/library/nginx:1.27``. Degrades with a typed error
    (never a crash) when the store or metadata cannot be read.
    """
    from sorb.container.boltdb import BoltReadError, bolt_get

    name, _, query = ref.partition("?")
    namespace = "default"
    if query.startswith("namespace="):
        namespace = query[len("namespace=") :]
    base = root or Path("/var/lib/containerd")
    content = base / "io.containerd.content.v1.content"
    meta_db = base / "io.containerd.metadata.v1.bolt" / "meta.db"
    if not content.is_dir() or not meta_db.is_file():
        raise TargetError(
            f"containerd store not found under {base} "
            "(need io.containerd.content.v1.content and metadata boltdb)"
        )
    try:
        digest_raw = bolt_get(
            meta_db.read_bytes(),
            [b"v1", namespace.encode(), b"images", name.encode(), b"target", b"digest"],
        )
    except BoltReadError as e:
        raise TargetError(f"cannot read containerd metadata ({meta_db}): {e}") from e
    if digest_raw is None:
        raise TargetError(f"image {name!r} not found in containerd namespace {namespace!r}")
    top_digest = digest_raw.decode("utf-8", "replace")

    def blob(digest: str) -> bytes:
        algo, _, hexval = digest.partition(":")
        p = content / "blobs" / algo / hexval
        if not p.is_file():
            raise TargetError(f"blob {digest} missing from containerd content store")
        return p.read_bytes()

    manifest_bytes = blob(top_digest)
    doc = load_json_bytes(manifest_bytes, f"containerd blob {top_digest}")
    resolved_platform = platform
    if "manifests" in doc:
        inner, resolved_platform = select_manifest_from_index(doc, platform)
        manifest_bytes = blob(str(inner["digest"]))
        doc = load_json_bytes(manifest_bytes, f"containerd blob {inner['digest']}")
    config_desc = doc.get("config") or {}
    config_bytes = blob(str(config_desc["digest"]))
    config = load_json_bytes(config_bytes, "image config")
    layers = layers_from_manifest(doc, config)

    def opener(layer: ImageLayer) -> bytes:
        return blob(layer.digest)

    cfg_os = str(config.get("os", "linux"))
    cfg_arch = str(config.get("architecture", "unknown"))
    return ResolvedImage(
        ref=name,
        digest=str(config_desc["digest"]),
        platform=resolved_platform or f"{cfg_os}/{cfg_arch}",
        manifest=doc,
        config=config,
        layers=layers,
        blob_opener=opener,
        provenance_facts={
            "acquisition": "containerd",
            "manifest_digest": sha256_digest(manifest_bytes),
            "image_id": str(config_desc["digest"]),
            "namespace": namespace,
        },
        annotations=dict(doc.get("annotations") or {}),
    )
