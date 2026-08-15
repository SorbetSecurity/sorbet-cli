"""Kubernetes / Helm / Kustomize analyzers.

- **Manifests**: schema-aware YAML walk over workload kinds (and CRD-embedded
  podSpecs via well-known paths), extracting container/init/ephemeral image
  refs (digest-pinned vs tag-floating recorded — a floating tag is a
  reproducibility finding). Each image gets a ``RUNS`` edge from its workload.
- **Helm**: ``Chart.yaml``/``Chart.lock`` chart deps (locked tier); a
  Go-template-subset renderer resolves ``{{ .Values.image.tag }}`` against
  ``values.yaml`` defaults so image refs hidden behind templating are found;
  render failure degrades to regex extraction at inferred tier.
- **Kustomize**: the ``images:`` transformer (which rewrites refs and must be
  applied to get the true image).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

import yaml

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.catalogers.common import ref_purl
from sorb.iac.imageref import parse_image_reference
from sorb.ident import make_purl
from sorb.model import (
    Annotation,
    ComponentClaim,
    EdgeClaim,
    EdgeType,
    Finding,
    Tier,
)
from sorb.source.base import Entry

_WORKLOAD_KINDS = {
    "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
    "Job", "CronJob", "ReplicationController",
}


def _iter_docs(text: str) -> Iterable[dict[str, Any]]:
    try:
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict):
                yield doc
    except yaml.YAMLError:
        return


def _find_containers(obj: Any) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield (section, container) for containers/initContainers/ephemeral at any
    depth (covers CRD-embedded podSpecs via well-known keys)."""
    if isinstance(obj, dict):
        for key in ("containers", "initContainers", "ephemeralContainers"):
            val = obj.get(key)
            if isinstance(val, list):
                for c in val:
                    if isinstance(c, dict) and c.get("image"):
                        yield key, c
        for v in obj.values():
            yield from _find_containers(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _find_containers(item)


def _image_finding(
    ctx: CatalogerContext, entry: Entry, image: str, workload: str, technique: str, tier: Tier
) -> Finding | None:
    ref = parse_image_reference(image)
    if ref is None:
        return None
    purl = ref.purl()
    annotations: tuple[Annotation, ...] = ()
    if ref.floating:
        annotations = (
            Annotation(code="unpinned-image", subject=ref_purl(purl),
                       detail=f"{workload} runs {ref.raw} — floating tag, not digest-pinned "
                       "(reproducibility risk)"),
        )
    return Finding(
        claim=ComponentClaim(
            ctype="application", name=ref.name(), version=ref.digest or ref.tag,
            purl=purl, ecosystem="oci",
            attrs=(("image-ref", ref.raw), ("follow-target", ref.raw)),
        ),
        evidence=(ctx.evidence(technique, tier, entry, captured=f"image {ref.raw} ({workload})"),),
        edges=(EdgeClaim(kind=EdgeType.RUNS, src=f"resource:{workload}", dst=ref_purl(purl)),),
        annotations=annotations,
    )


class K8sManifestCataloger(Cataloger):
    id = "iac/kubernetes"
    version = 1
    matchers = [Matcher(basename="*.yaml"), Matcher(basename="*.yml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        # skip files owned by more specific catalogers
        base = entry.path.rsplit("/", 1)[-1]
        if base in ("Chart.yaml", "Chart.lock", "kustomization.yaml", "docker-compose.yml",
                    "docker-compose.yaml", "pubspec.yaml", "stack.yaml") or "values" in base:
            return
        text = blob.decode("utf-8", errors="replace")
        if "apiVersion" not in text or "kind" not in text:
            return
        seen: set[str] = set()
        for doc in _iter_docs(text):
            kind = str(doc.get("kind", ""))
            if kind not in _WORKLOAD_KINDS:
                continue
            name = str(doc.get("metadata", {}).get("name", kind))
            for _section, container in _find_containers(doc):
                image = str(container.get("image", ""))
                if image in seen:
                    continue
                seen.add(image)
                f = _image_finding(ctx, entry, image, f"{kind}/{name}", "manifest-parse", Tier.DECLARED)
                if f is not None:
                    yield f


class HelmChartCataloger(Cataloger):
    id = "iac/helm-chart"
    version = 1
    matchers = [Matcher(basename="Chart.yaml"), Matcher(basename="Chart.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return
        if not isinstance(doc, dict):
            return
        is_lock = entry.path.endswith("Chart.lock")
        for dep in doc.get("dependencies", []):
            if not isinstance(dep, dict) or not dep.get("name"):
                continue
            name = str(dep["name"])
            version = str(dep.get("version", "")) or None
            repo = str(dep.get("repository", ""))
            purl = make_purl("helm", name, version) if version else None
            yield Finding(
                claim=ComponentClaim(
                    ctype="library", name=name, version=version, purl=purl, ecosystem="helm",
                    attrs=(("repository", repo),) if repo else (),
                ),
                evidence=(ctx.evidence(
                    "lockfile-parse" if is_lock else "manifest-parse",
                    Tier.LOCKED if is_lock else Tier.DECLARED, entry,
                    captured=f"chart dep {name} {version or '?'}"),),
            )


# -- Go-template-subset renderer for {{ .Values.x }} -----------------------------------

_TMPL_RE = re.compile(r"\{\{-?\s*\.Values\.([\w.]+)\s*-?\}\}")


def render_values(template: str, values: dict[str, Any]) -> str:
    """Resolve ``{{ .Values.a.b }}`` against `values`; unresolved → placeholder."""
    def get(path: str) -> Any:
        cur: Any = values
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur

    def repl(m: re.Match[str]) -> str:
        v = get(m.group(1))
        return str(v) if v is not None else f"<unresolved:.Values.{m.group(1)}>"

    return _TMPL_RE.sub(repl, template)


class HelmTemplateCataloger(Cataloger):
    """Helm templates: render `{{ .Values.image.* }}` against values.yaml."""

    id = "iac/helm-template"
    version = 1
    matchers = [Matcher(glob="*templates/*.yaml"), Matcher(glob="*templates/*.yml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        if "{{" not in text or "image:" not in text:
            return
        values = self._values(ctx, entry.path)
        rendered = render_values(text, values)
        seen: set[str] = set()
        for m in re.finditer(r"image:\s*[\"']?([^\s\"'#]+)", rendered):
            image = m.group(1)
            if image in seen or "<unresolved:" in image:
                continue
            seen.add(image)
            f = _image_finding(ctx, entry, image, "helm-chart", "manifest-parse", Tier.INFERRED)
            if f is not None:
                yield f

    def _values(self, ctx: CatalogerContext, path: str) -> dict[str, Any]:
        # values.yaml lives at the chart root (parent of templates/)
        chart_root = path.split("templates/", 1)[0]
        raw = ctx.peek(f"{chart_root}values.yaml") or ctx.peek(f"{chart_root}values.yml")
        if raw is None:
            return {}
        try:
            doc = yaml.safe_load(raw.decode("utf-8", "replace"))
            return doc if isinstance(doc, dict) else {}
        except yaml.YAMLError:
            return {}


class KustomizeCataloger(Cataloger):
    """`kustomization.yaml` — the `images:` transformer rewrites refs; the
    rewritten ref is the true image."""

    id = "iac/kustomize"
    version = 1
    matchers = [Matcher(basename="kustomization.yaml"), Matcher(basename="kustomization.yml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return
        if not isinstance(doc, dict):
            return
        for img in doc.get("images", []):
            if not isinstance(img, dict):
                continue
            new_name = img.get("newName") or img.get("name")
            new_tag = img.get("newTag")
            digest = img.get("digest")
            if not new_name:
                continue
            ref_str = str(new_name)
            if digest:
                ref_str += f"@{digest}"
            elif new_tag:
                ref_str += f":{new_tag}"
            f = _image_finding(ctx, entry, ref_str, "kustomize", "manifest-parse", Tier.DECLARED)
            if f is not None:
                yield f


register(K8sManifestCataloger())
register(HelmChartCataloger())
register(HelmTemplateCataloger())
register(KustomizeCataloger())
