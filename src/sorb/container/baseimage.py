"""Base-image identification.

Mechanisms, in order:

1. **Layer-chain matching** against the base-images data pack: the longest
   pack entry whose ``diff_ids`` chain is a prefix of the image's rootfs
   diff_ids wins (diff_ids are compression-invariant, unlike blob digests).
2. **OCI 1.1 annotations** (``org.opencontainers.image.base.name/digest``) —
   names the base but cannot place the boundary by itself.

Unknown bases degrade gracefully: no guess, no boundary.

This is the first data-pack consumer: the loader enforces ``schema`` and
``min_sorb_version`` and prefers an unpacked pack in the cache's ``packs/``
directory over the built-in seed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from sorb import __version__
from sorb.errors import SubsystemDegraded

PACK_NAME = "base-images"
PACK_SCHEMA = 1

ANN_BASE_NAME = "org.opencontainers.image.base.name"
ANN_BASE_DIGEST = "org.opencontainers.image.base.digest"


@dataclass(frozen=True, slots=True)
class BaseImageInfo:
    name: str  # e.g. "debian:12.5"
    boundary: int | None  # first `boundary` layers are inherited (None: unknown)
    method: str  # "layer-chain" | "oci-annotation"
    digest: str | None = None


def _validate_pack(doc: dict[str, Any], origin: str) -> dict[str, Any]:
    if int(doc.get("schema", -1)) != PACK_SCHEMA:
        raise SubsystemDegraded(
            f"base-images pack at {origin} has schema {doc.get('schema')!r}; "
            f"this sorb supports schema {PACK_SCHEMA}"
        )
    min_version = str(doc.get("min_sorb_version", "0"))
    try:
        if Version(__version__) < Version(min_version):
            raise SubsystemDegraded(
                f"base-images pack at {origin} requires sorb ≥ {min_version} "
                f"(this is {__version__}); run `sorb db update` after upgrading"
            )
    except InvalidVersion as e:
        raise SubsystemDegraded(f"base-images pack at {origin}: bad min_sorb_version: {e}") from e
    return doc


def load_pack(packs_dir: Path | None = None) -> dict[str, Any]:
    """Load the base-images pack: cache `packs/` first, built-in seed as fallback."""
    if packs_dir is not None:
        pack_root = packs_dir / PACK_NAME
        if pack_root.is_dir():
            versions = sorted(p for p in pack_root.iterdir() if p.is_dir())
            for version_dir in reversed(versions):
                candidate = version_dir / "base_images.json"
                if candidate.is_file():
                    doc = json.loads(candidate.read_text(encoding="utf-8"))
                    return _validate_pack(doc, str(candidate))
    raw = (resources.files("sorb") / "data" / "base_images.json").read_text(encoding="utf-8")
    return _validate_pack(json.loads(raw), "built-in")


def identify_base(
    diff_ids: list[str],
    annotations: dict[str, str],
    packs_dir: Path | None = None,
) -> BaseImageInfo | None:
    """Identify the base image; None when nothing matches (never a guess)."""
    try:
        pack = load_pack(packs_dir)
    except (OSError, json.JSONDecodeError):
        pack = {"images": []}

    best: BaseImageInfo | None = None
    for entry in pack.get("images", []):
        chain = [str(d) for d in entry.get("diff_ids", [])]
        if not chain or len(chain) > len(diff_ids):
            continue
        if diff_ids[: len(chain)] == chain and (best is None or len(chain) > (best.boundary or 0)):
            best = BaseImageInfo(
                name=str(entry.get("name", "unknown")),
                boundary=len(chain),
                method="layer-chain",
                digest=entry.get("digest"),
            )
    if best is not None:
        return best

    base_name = annotations.get(ANN_BASE_NAME)
    if base_name:
        return BaseImageInfo(
            name=base_name,
            boundary=None,  # the annotation names the base but not the boundary
            method="oci-annotation",
            digest=annotations.get(ANN_BASE_DIGEST),
        )
    return None
