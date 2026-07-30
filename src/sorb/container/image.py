"""Resolved-image model shared by every acquisition path.

Every acquisition backend (registry, OCI layout, docker-archive, daemon,
containerd) resolves to the same `ResolvedImage`, so the layer model and the
pipeline never know where an image came from — which is what makes
"identical SBOM across acquisition paths" testable.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sorb.errors import TargetError

# OCI / Docker media types
MT_OCI_INDEX = "application/vnd.oci.image.index.v1+json"
MT_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MT_DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
MT_DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"

_LAYER_ZSTD_SUFFIXES = ("+zstd",)
_LAYER_GZIP_SUFFIXES = ("+gzip", ".gzip")

DEFAULT_PLATFORM = "linux/amd64"


@dataclass(frozen=True, slots=True)
class ImageLayer:
    """One layer as listed in the manifest (compressed blob identity)."""

    digest: str  # compressed blob digest "sha256:…"
    diff_id: str | None  # uncompressed digest from config.rootfs (compression-invariant)
    media_type: str
    size: int
    ordinal: int  # 0-based, oldest first


@dataclass
class ResolvedImage:
    """An image resolved to config + ordered layers with a blob opener."""

    ref: str  # familiar reference as given by the user
    digest: str  # platform manifest digest "sha256:…"
    platform: str  # "linux/amd64"
    manifest: dict[str, Any]
    config: dict[str, Any]
    layers: list[ImageLayer]
    #: returns the layer blob bytes as stored (possibly compressed)
    blob_opener: Callable[[ImageLayer], bytes]
    provenance_facts: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    #: attestation documents discovered during acquisition
    attestations: list[dict[str, Any]] = field(default_factory=list)

    def layer_tar(self, layer: ImageLayer) -> bytes:
        """Uncompressed tar bytes for a layer (gzip/zstd per media type or sniff)."""
        raw = self.blob_opener(layer)
        return decompress_layer(raw, layer.media_type)

    def subject(self) -> str:
        """Lineage subject = the image ID (config digest): identical no matter
        how the image was acquired or what tag it wore. The familiar
        ref is display metadata (`ref`, provenance facts), never identity."""
        return f"image:{self.digest}"


def decompress_layer(raw: bytes, media_type: str) -> bytes:
    """Decompress a layer blob according to its media type (sniff as fallback)."""
    if media_type.endswith(_LAYER_ZSTD_SUFFIXES) or raw[:4] == b"\x28\xb5\x2f\xfd":
        import zstandard

        return zstandard.ZstdDecompressor().decompress(raw, max_output_size=1 << 32)
    if media_type.endswith(_LAYER_GZIP_SUFFIXES) or raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw)
    return raw


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def parse_platform(p: str | None) -> tuple[str, str]:
    """'linux/amd64' → ('linux', 'amd64'); default applied when None."""
    value = p or DEFAULT_PLATFORM
    os_, sep, arch = value.partition("/")
    if not sep or not os_ or not arch:
        raise TargetError(f"invalid --platform {value!r} (expected os/arch)")
    return os_, arch.split("/", 1)[0]  # variant dropped for matching


def select_manifest_from_index(
    index: dict[str, Any], platform: str | None
) -> tuple[dict[str, Any], str]:
    """Pick the platform manifest descriptor from an index/manifest list.

    Returns (descriptor, resolved_platform). Attestation manifests
    (vnd.dev.cosign / in-toto referrer types) are never selected.
    """
    want_os, want_arch = parse_platform(platform)
    candidates: list[dict[str, Any]] = []
    for desc in index.get("manifests", []):
        ann = desc.get("annotations") or {}
        if ann.get("vnd.docker.reference.type") == "attestation-manifest":
            continue
        candidates.append(desc)
    for desc in candidates:
        plat = desc.get("platform") or {}
        if plat.get("os") == want_os and plat.get("architecture") == want_arch:
            return desc, f"{want_os}/{want_arch}"
    available = ", ".join(
        f"{(d.get('platform') or {}).get('os', '?')}/"
        f"{(d.get('platform') or {}).get('architecture', '?')}"
        for d in candidates
    )
    raise TargetError(
        f"platform {want_os}/{want_arch} not in image index (available: {available or 'none'})"
    )


def index_platforms(index: dict[str, Any]) -> list[str]:
    """All scannable platforms in an index (attestation manifests excluded)."""
    out: list[str] = []
    for desc in index.get("manifests", []):
        ann = desc.get("annotations") or {}
        if ann.get("vnd.docker.reference.type") == "attestation-manifest":
            continue
        plat = desc.get("platform") or {}
        if plat.get("os") and plat.get("architecture"):
            if plat.get("os") == "unknown":
                continue
            out.append(f"{plat['os']}/{plat['architecture']}")
    return out


def layers_from_manifest(manifest: dict[str, Any], config: dict[str, Any]) -> list[ImageLayer]:
    """Zip manifest layer descriptors with config rootfs diff_ids."""
    diff_ids: list[str] = list((config.get("rootfs") or {}).get("diff_ids") or [])
    layers: list[ImageLayer] = []
    for i, desc in enumerate(manifest.get("layers", [])):
        layers.append(
            ImageLayer(
                digest=str(desc.get("digest", "")),
                diff_id=diff_ids[i] if i < len(diff_ids) else None,
                media_type=str(desc.get("mediaType", "")),
                size=int(desc.get("size", 0) or 0),
                ordinal=i,
            )
        )
    return layers


def load_json_bytes(data: bytes, what: str) -> dict[str, Any]:
    try:
        doc = json.loads(data)
    except json.JSONDecodeError as e:
        raise TargetError(f"malformed JSON in {what}: {e}") from e
    if not isinstance(doc, dict):
        raise TargetError(f"unexpected JSON shape in {what} (expected object)")
    return doc
