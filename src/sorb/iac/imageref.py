"""Shared container-image reference extraction.

One normalizer used by k8s/helm/compose/dockerfile/terraform: every image ref
is classified digest-pinned vs tag-floating (a floating tag is a
reproducibility finding) and turned into a component + optional ``--follow-images``
chain target.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ImageReference:
    raw: str
    registry: str
    repository: str
    tag: str | None
    digest: str | None

    @property
    def pinned(self) -> bool:
        return self.digest is not None

    @property
    def floating(self) -> bool:
        return self.digest is None and (self.tag is None or self.tag == "latest")

    def name(self) -> str:
        base = self.repository.rsplit("/", 1)[-1]
        return base

    def purl(self) -> str:
        from sorb.ident import make_purl

        qualifiers = {}
        if self.registry and self.registry != "docker.io":
            qualifiers["repository_url"] = f"{self.registry}/{self.repository}"
        version = self.digest or self.tag or "latest"
        return make_purl("oci", self.name(), version, qualifiers=qualifiers)


_REF_RE = re.compile(
    r"^(?:(?P<registry>[\w.\-]+(?::\d+)?)/)?"
    r"(?P<repo>[\w.\-/]+?)"
    r"(?::(?P<tag>[\w.\-]+))?"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?$"
)


def parse_image_reference(raw: str) -> ImageReference | None:
    raw = raw.strip()
    if not raw or " " in raw or "<unresolved:" in raw:
        return None
    m = _REF_RE.match(raw)
    if not m:
        return None
    registry = m.group("registry")
    repo = m.group("repo")
    # a first segment is a registry only if it has a dot/port or is localhost
    if registry is None and "/" in repo:
        first = repo.split("/", 1)[0]
        if "." in first or ":" in first or first == "localhost":
            registry, repo = first, repo.split("/", 1)[1]
    if registry is None:
        registry = "docker.io"
        if "/" not in repo:
            repo = f"library/{repo}"
    return ImageReference(
        raw=raw, registry=registry, repository=repo,
        tag=m.group("tag"), digest=m.group("digest"),
    )
