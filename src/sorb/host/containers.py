"""Container-runtime discovery on a live host.

A host is rarely just its packages — it also runs container images. We read the
local docker / containerd / podman *state on disk* (no daemon socket, no network)
and enumerate the images and running containers as **scannable sub-targets**: the
user is told "there are 4 images here, scan them with `sorb scan image:<ref>`".
Purely a read of on-disk metadata, so it works offline and against a mounted
image root just as well as a live `/`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SubTarget:
    kind: str  # "image" | "container"
    ref: str  # a `sorb scan` target spec
    runtime: str  # "docker" | "containerd" | "podman"
    detail: str = ""


def discover_subtargets(root: Path) -> list[SubTarget]:
    """Enumerate container images/containers from on-disk runtime state."""
    out: list[SubTarget] = []
    out.extend(_docker(root))
    out.extend(_containerd(root))
    out.extend(_podman(root))
    # stable, de-duplicated order
    seen: set[tuple[str, str]] = set()
    uniq: list[SubTarget] = []
    for s in sorted(out, key=lambda s: (s.runtime, s.kind, s.ref)):
        key = (s.kind, s.ref)
        if key not in seen:
            seen.add(key)
            uniq.append(s)
    return uniq


def _read_json(path: Path) -> object | None:
    try:
        if path.is_file():
            parsed: object = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            return parsed
    except (OSError, json.JSONDecodeError):
        return None
    return None


def _docker(root: Path) -> list[SubTarget]:
    out: list[SubTarget] = []
    repos = _read_json(root / "var/lib/docker/image/overlay2/repositories.json")
    if repos is None:
        for driver in ("overlay", "aufs", "btrfs", "vfs"):
            repos = _read_json(root / f"var/lib/docker/image/{driver}/repositories.json")
            if repos is not None:
                break
    if isinstance(repos, dict):
        for name, tags in (repos.get("Repositories") or {}).items():
            if isinstance(tags, dict):
                for tag_ref in tags:
                    out.append(SubTarget("image", f"image:{tag_ref}", "docker"))
            else:
                out.append(SubTarget("image", f"image:{name}", "docker"))
    # running containers
    cdir = root / "var/lib/docker/containers"
    try:
        if cdir.is_dir():
            for cfg in sorted(cdir.glob("*/config.v2.json")):
                data = _read_json(cfg)
                if isinstance(data, dict):
                    img = data.get("Config", {}).get("Image") or data.get("Image", "")
                    cid = data.get("ID", cfg.parent.name)[:12]
                    if img:
                        out.append(SubTarget("container", f"image:{img}", "docker",
                                             detail=f"container {cid}"))
    except OSError:
        pass
    return out


def _containerd(root: Path) -> list[SubTarget]:
    out: list[SubTarget] = []
    base = root / "var/lib/containerd"
    try:
        if base.is_dir():
            # content store presence → images exist; names live in the metadata
            # bolt db (not parsed here), so we surface the store as a hint.
            for meta in base.glob("io.containerd.metadata.v1.bolt/meta.db"):
                if meta.is_file():
                    out.append(SubTarget("image", "container://containerd", "containerd",
                                         detail="containerd content store present"))
    except OSError:
        pass
    return out


def _podman(root: Path) -> list[SubTarget]:
    out: list[SubTarget] = []
    for home_glob in ("home/*/.local/share/containers/storage", "var/lib/containers/storage"):
        try:
            for storage in root.glob(home_glob):
                images = _read_json(storage / "overlay-images/images.json")
                if isinstance(images, list):
                    for img in images:
                        for name in (img.get("names") or []) if isinstance(img, dict) else []:
                            out.append(SubTarget("image", f"image:{name}", "podman"))
        except OSError:
            continue
    return out
