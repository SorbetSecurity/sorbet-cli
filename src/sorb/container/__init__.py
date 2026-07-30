"""Container subsystem.

`acquire_image` is the single entry point the orchestrator uses: every
acquisition path (registry, OCI layout, docker-archive, daemons, containerd,
running container) resolves to the same `ResolvedImage`, and the layer model
(`LayerStack`/`SquashView`) presents it through the `Source` protocol.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sorb.cache import Cas
from sorb.container.attest import AttestationDoc, parse_envelope
from sorb.container.image import ImageLayer, ResolvedImage
from sorb.container.spec import (
    CONTAINER_PREFIXES,
    ContainerTarget,
    parse_container_spec,
    parse_image_ref,
)
from sorb.errors import TargetError

__all__ = [
    "CONTAINER_PREFIXES",
    "ContainerTarget",
    "ResolvedImage",
    "acquire_image",
    "list_platforms",
    "parse_container_spec",
]


def acquire_image(
    target: ContainerTarget,
    *,
    platform: str | None = None,
    offline: bool = False,
    cas: Cas | None = None,
    transport: Any | None = None,
) -> ResolvedImage:
    """Resolve any container target to a `ResolvedImage`.

    `transport` is an injectable httpx transport for the registry/daemon
    clients (tests run socket-blocked).
    """
    from sorb.container import local

    if target.kind == "registry":
        from sorb.container.registry import RegistryClient

        client = RegistryClient(
            parse_image_ref(target.ref), cas=cas, offline=offline, transport=transport
        )
        image = client.resolve(platform)
        _discover_attestations(client, image)
        return image
    if target.kind == "oci-layout":
        return local.open_oci_layout(target.ref, platform)
    if target.kind == "docker-archive":
        return local.open_docker_archive(target.ref, platform)
    if target.kind in ("daemon", "podman"):
        flavor = "docker" if target.kind == "daemon" else "podman"
        return local.open_daemon_image(target.ref, platform, flavor=flavor, transport=transport)
    if target.kind == "containerd":
        return local.open_containerd(target.ref, platform)
    if target.kind == "running":
        return _acquire_running(target.ref, transport=transport)
    raise TargetError(f"unknown container target kind {target.kind!r}")


def list_platforms(
    target: ContainerTarget,
    *,
    offline: bool = False,
    cas: Cas | None = None,
    transport: Any | None = None,
) -> list[str]:
    """Platforms available for a target (``--all-platforms`` fan-out)."""
    if target.kind == "registry":
        from sorb.container.registry import RegistryClient

        client = RegistryClient(
            parse_image_ref(target.ref), cas=cas, offline=offline, transport=transport
        )
        return client.platforms()
    image = acquire_image(target, offline=offline, cas=cas, transport=transport)
    return [image.platform]


def _discover_attestations(client: Any, image: ResolvedImage) -> None:
    """Fetch referrer-attached SBOM/provenance attestations.

    Failures degrade silently to "no attestations" — discovery is enrichment,
    never a scan blocker.
    """
    manifest_digest = image.provenance_facts.get("manifest_digest", "")
    if not manifest_digest:
        return
    try:
        descriptors = client.referrers(manifest_digest)
    except Exception:  # noqa: BLE001 — enrichment is fail-open by design
        return
    docs: list[AttestationDoc] = []
    for desc in descriptors:
        try:
            manifest = desc.get("_doc")
            if manifest is None:
                manifest, _digest, _raw = client.fetch_manifest(str(desc.get("digest", "")))
            for blob_desc in manifest.get("layers", []) or []:
                raw = client.fetch_blob(str(blob_desc.get("digest", "")))
                parsed = parse_envelope(raw, source=str(desc.get("digest", "referrer")))
                if parsed is not None and (parsed.components or parsed.kind == "provenance"):
                    docs.append(parsed)
        except TargetError:
            continue
    image.attestations = [
        {
            "kind": d.kind,
            "source": d.source,
            "predicate_type": d.predicate_type,
            "components": [
                {"name": c.name, "version": c.version, "purl": c.purl} for c in d.components
            ],
        }
        for d in docs
    ]


def _acquire_running(container_id: str, *, transport: Any | None = None) -> ResolvedImage:
    """A running container: merged-rootfs snapshot + live process info.

    The export tar becomes a single pseudo-layer; process observation facts
    ride in `provenance_facts` for the orchestrator's OBSERVED_IN pass.
    """
    import json as _json

    from sorb.container.daemon import DaemonClient

    client = DaemonClient.for_flavor("docker", transport=transport)
    inspect = client.container_inspect(container_id)
    rootfs = client.container_export(container_id)
    digest = "sha256:" + hashlib.sha256(rootfs).hexdigest()

    processes: list[str] = []
    try:
        top = client.container_top(container_id)
        titles = [str(t).upper() for t in top.get("Titles", [])]
        cmd_idx = titles.index("CMD") if "CMD" in titles else len(titles) - 1
        for row in top.get("Processes", []) or []:
            if isinstance(row, list) and row:
                processes.append(str(row[cmd_idx if cmd_idx < len(row) else -1]))
    except TargetError:
        pass

    config = inspect.get("Config") or {}
    entrypoint = config.get("Entrypoint") or []
    cmd = config.get("Cmd") or []
    layer = ImageLayer(
        digest=digest,
        diff_id=digest,
        media_type="application/vnd.oci.image.layer.v1.tar",
        size=len(rootfs),
        ordinal=0,
    )
    name = str(inspect.get("Name", "")).lstrip("/") or container_id
    return ResolvedImage(
        ref=f"container://{name}",
        digest=digest,
        platform=str(inspect.get("Platform", "linux")) or "linux",
        manifest={},
        config={"config": config},
        layers=[layer],
        blob_opener=lambda _layer: rootfs,
        provenance_facts={
            "acquisition": "running-container",
            "container_id": str(inspect.get("Id", container_id)),
            "image": str(inspect.get("Image", "")),
            "processes": _json.dumps(processes),
            "entrypoint": _json.dumps([*entrypoint, *cmd]),
        },
    )
