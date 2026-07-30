"""Container target specs and image-reference grammar.

Target spellings recognized by ``sorb scan``:

    image:ghcr.io/acme/api:1.2       registry pull (no daemon needed)
    oci-dir:path/to/layout           OCI image layout directory
    docker-archive:api.tar           `docker save` tarball
    docker:nginx:1.27                image from the local Docker daemon
    podman:nginx:1.27                image from the local Podman service
    containerd:docker.io/library/x   containerd content store (direct read)
    container://<id>                 a *running* container
"""

from __future__ import annotations

from dataclasses import dataclass

#: spec prefixes owned by the container subsystem, checked by the pipeline
CONTAINER_PREFIXES = (
    "image:",
    "oci-dir:",
    "docker-archive:",
    "docker:",
    "podman:",
    "containerd:",
    "container://",
)


@dataclass(frozen=True, slots=True)
class ContainerTarget:
    kind: str  # registry|oci-layout|docker-archive|daemon|podman|containerd|running
    ref: str  # image reference, path, or container id
    raw: str  # the spec as given


def parse_container_spec(spec: str) -> ContainerTarget | None:
    """Classify a target spec; None when it is not a container target."""
    if spec.startswith("image:"):
        return ContainerTarget(kind="registry", ref=spec[len("image:") :], raw=spec)
    if spec.startswith("oci-dir:"):
        return ContainerTarget(kind="oci-layout", ref=spec[len("oci-dir:") :], raw=spec)
    if spec.startswith("docker-archive:"):
        return ContainerTarget(
            kind="docker-archive", ref=spec[len("docker-archive:") :], raw=spec
        )
    if spec.startswith("container://"):
        return ContainerTarget(kind="running", ref=spec[len("container://") :], raw=spec)
    if spec.startswith("docker:"):
        return ContainerTarget(kind="daemon", ref=spec[len("docker:") :], raw=spec)
    if spec.startswith("podman:"):
        return ContainerTarget(kind="podman", ref=spec[len("podman:") :], raw=spec)
    if spec.startswith("containerd:"):
        return ContainerTarget(kind="containerd", ref=spec[len("containerd:") :], raw=spec)
    return None


@dataclass(frozen=True, slots=True)
class ImageRef:
    """A parsed image reference with registry defaulting rules."""

    registry: str  # API host, e.g. "ghcr.io", "registry-1.docker.io"
    repository: str  # e.g. "acme/api", "library/nginx"
    tag: str | None
    digest: str | None  # "sha256:…" when pinned

    def familiar(self) -> str:
        """The human-familiar form (docker.io/library elision)."""
        host = "docker.io" if self.registry == "registry-1.docker.io" else self.registry
        repo = self.repository
        if host == "docker.io" and repo.startswith("library/"):
            repo = repo[len("library/") :]
        base = repo if host == "docker.io" else f"{host}/{repo}"
        if self.digest:
            return f"{base}@{self.digest}"
        return f"{base}:{self.tag or 'latest'}"

    def canonical(self) -> str:
        """Fully-qualified form used for subjects and cache keys."""
        base = f"{self.registry}/{self.repository}"
        if self.digest:
            return f"{base}@{self.digest}"
        return f"{base}:{self.tag or 'latest'}"


def parse_image_ref(ref: str) -> ImageRef:
    """Parse ``[host/]repo[:tag][@digest]`` with Docker defaulting rules."""
    digest: str | None = None
    if "@" in ref:
        ref, _, digest = ref.partition("@")
    first, slash, rest = ref.partition("/")
    is_host = slash != "" and ("." in first or ":" in first or first == "localhost")
    if is_host:
        host, remainder = first, rest
    else:
        host, remainder = "docker.io", ref
    tag: str | None = None
    # a colon after the last slash is the tag separator (hosts keep their port)
    last = remainder.rsplit("/", 1)[-1]
    if ":" in last:
        remainder, _, tag = remainder.rpartition(":")
    if host == "docker.io" and "/" not in remainder:
        remainder = f"library/{remainder}"
    api_host = "registry-1.docker.io" if host == "docker.io" else host
    return ImageRef(registry=api_host, repository=remainder, tag=tag, digest=digest)
