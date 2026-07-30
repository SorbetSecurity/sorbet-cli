"""Terraform / OpenTofu analyzer.

Two outputs from the same parse: the **SBOM of the IaC itself**
(providers + modules are versioned dependencies with sources and lock digests)
and the **infrastructure component model** (Resource components with typed
extractors for AMIs, container image refs, lambda runtimes, DB engine
versions). Variables resolve from defaults + provided values; unresolvable
expressions become placeholders, never guesses.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, find_span, register
from sorb.catalogers.common import dirname_of, ref_project, ref_purl
from sorb.errors import DetectorFailure
from sorb.iac.hcl import Block, Unresolved, interpolate, parse_hcl
from sorb.iac.imageref import parse_image_reference
from sorb.ident import make_purl
from sorb.model import (
    Annotation,
    ComponentClaim,
    EdgeClaim,
    EdgeType,
    Finding,
    Scope,
    Tier,
)
from sorb.source.base import Entry

# resource type → (attribute holding an image ref, extractor kind)
_IMAGE_ATTRS = {
    "aws_ecs_task_definition": "container_definitions",
    "google_cloud_run_service": "image",
    "google_cloud_run_v2_service": "image",
    "kubernetes_deployment": "image",
}
_RUNTIME_ATTRS = {
    "aws_lambda_function": "runtime",
    "google_cloudfunctions_function": "runtime",
}
_DB_ENGINE = {"aws_db_instance": ("engine", "engine_version"), "aws_rds_cluster": ("engine", "engine_version")}


def _block_span(text: str, keyword: str, *labels: str) -> tuple[int, int] | None:
    """Line of the block's declaration, e.g. `resource "aws_iam_role" "fleet"`.

    Searching for a bare label would land on the first place the word appears,
    which for a common name is rarely the block that declares it.
    """
    quoted = " ".join(f'"{label}"' for label in labels)
    return find_span(text, f"{keyword} {quoted}") or find_span(text, quoted)


class TerraformCataloger(Cataloger):
    id = "iac/terraform"
    version = 1
    matchers = [Matcher(basename="*.tf")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            _attrs, blocks = parse_hcl(text)
        except Exception as e:  # noqa: BLE001 — malformed HCL: gap
            raise DetectorFailure(f"HCL parse failed: {e}", path=entry.path, detector=self.detector) from e
        proj_dir = dirname_of(entry.path)
        proj_ref = ref_project(proj_dir)
        variables = self._variables(ctx, proj_dir, blocks)

        for block in blocks:
            if block.btype == "terraform":
                yield from self._providers_from_required(ctx, entry, block, proj_ref)
            elif block.btype == "provider":
                pass  # version pinning lives in required_providers
            elif block.btype == "module":
                yield from self._module(ctx, entry, text, block, proj_ref)
            elif block.btype == "resource":
                yield from self._resource(ctx, entry, text, block, variables, proj_ref)

    def _variables(self, ctx: CatalogerContext, proj_dir: str, blocks: list[Block]) -> dict[str, Any]:
        variables: dict[str, Any] = {}
        for b in blocks:
            if b.btype == "variable" and b.labels:
                default = b.body.get("default")
                if default is not None and not isinstance(default, Unresolved):
                    variables[b.labels[0]] = default
        # provided -var-file values (terraform.tfvars) override defaults
        prefix = "" if proj_dir == "." else f"{proj_dir}/"
        raw = ctx.peek(f"{prefix}terraform.tfvars")
        if raw:
            try:
                tfvars, _ = parse_hcl(raw.decode("utf-8", "replace"))
                for k, v in tfvars.items():
                    if not isinstance(v, Unresolved):
                        variables[k] = v
            except Exception:  # noqa: BLE001
                pass
        return variables

    def _providers_from_required(
        self, ctx: CatalogerContext, entry: Entry, tf_block: Block, proj_ref: str
    ) -> Iterable[Finding]:
        for rp in tf_block.sub("required_providers"):
            for name, spec in rp.body.items():
                source = version = None
                if isinstance(spec, dict):
                    source = spec.get("source")
                    version = spec.get("version")
                elif isinstance(spec, str):
                    version = spec
                if isinstance(version, Unresolved):
                    version = None
                clean_version = _clean_constraint(version) if version else None
                namespace = str(source).rsplit("/", 1)[0] if source and "/" in str(source) else "hashicorp"
                purl = make_purl("terraform", name, clean_version, namespace=namespace) if clean_version else None
                yield Finding(
                    claim=ComponentClaim(
                        ctype="library", name=name, version=clean_version, purl=purl,
                        ecosystem="terraform", namespace=namespace,
                        requested=str(version) if version else None,
                        attrs=(("provider-source", str(source)),) if source else (),
                    ),
                    evidence=(
                        ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                     captured=f"provider {name} {version or '(unpinned)'}"),
                    ),
                    edges=(
                        EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref,
                                  dst=ref_purl(purl) if purl else f"claim:terraform/{name}@",
                                  scope=Scope.BUILD, direct=True),
                    ),
                )

    def _module(self, ctx: CatalogerContext, entry: Entry, text: str, block: Block,
                proj_ref: str) -> Iterable[Finding]:
        name = block.labels[0] if block.labels else "module"
        source = block.body.get("source")
        version = block.body.get("version")
        if isinstance(source, Unresolved) or not source:
            return
        source = str(source)
        if isinstance(version, Unresolved):
            version = None
        if source.startswith(("./", "../")):
            return  # local modules are not external dependencies
        git_m = re.match(r"(?:git::)?(?:https://|git@)([\w.\-]+)[:/](.+?)(?:\.git)?(?:\?ref=(\S+))?$", source)
        if git_m:
            ref = git_m.group(3)
            purl = make_purl("github", git_m.group(2).rsplit("/", 1)[-1], ref,
                             namespace=git_m.group(1) + "/" + git_m.group(2).rsplit("/", 1)[0]) if ref else None
            tier = Tier.LOCKED if ref and re.fullmatch(r"[0-9a-f]{40}", ref) else Tier.DECLARED
        else:  # registry module
            purl = make_purl("terraform", source.rsplit("/", 1)[-1], str(version) if version else None,
                             namespace=source.rsplit("/", 1)[0]) if version else None
            tier = Tier.DECLARED
        yield Finding(
            claim=ComponentClaim(
                ctype="library", name=source, version=str(version) if version else None,
                purl=purl, ecosystem="terraform-module", attrs=(("module-name", name),),
            ),
            evidence=(ctx.evidence("manifest-parse", tier, entry,
                                   span=_block_span(text, "module", name),
                                   captured=f"module {name} = {source}"),),
            edges=(EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref,
                             dst=ref_purl(purl) if purl else f"claim:terraform-module/{name}@",
                             scope=Scope.BUILD, direct=True),),
        )

    def _resource(
        self, ctx: CatalogerContext, entry: Entry, text: str, block: Block,
        variables: dict[str, Any], proj_ref: str
    ) -> Iterable[Finding]:
        if len(block.labels) < 2:
            return
        rtype, rname = block.labels[0], block.labels[1]
        resource_ref = f"resource:{rtype}.{rname}"
        # the Resource node itself (ctype="resource")
        yield Finding(
            claim=ComponentClaim(
                ctype="resource", name=f"{rtype}.{rname}", ecosystem="terraform",
                attrs=(("resource_type", rtype),),
            ),
            evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                   span=_block_span(text, "resource", rtype, rname),
                                   captured=f"resource {rtype} {rname}"),),
        )

        # image refs → image components + RUNS edge (chained scan when --follow-images)
        image_val = None
        if rtype in _IMAGE_ATTRS:
            image_val = _extract_image(block, _IMAGE_ATTRS[rtype], variables)
        if image_val:
            ref = parse_image_reference(image_val)
            if ref is not None:
                image_purl = ref.purl()
                annotations: tuple[Annotation, ...] = ()
                if ref.floating:
                    annotations = (
                        Annotation(code="unpinned-image", subject=ref_purl(image_purl),
                                   detail=f"{rtype}.{rname} runs {ref.raw} — floating tag "
                                   "(not digest-pinned): a reproducibility risk"),
                    )
                yield Finding(
                    claim=ComponentClaim(
                        ctype="application", name=ref.name(),
                        version=ref.digest or ref.tag, purl=image_purl, ecosystem="oci",
                        attrs=(("image-ref", ref.raw), ("follow-target", ref.raw)),
                    ),
                    evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                           captured=f"image {ref.raw} in {rtype}.{rname}"),),
                    edges=(EdgeClaim(kind=EdgeType.RUNS, src=resource_ref, dst=ref_purl(image_purl)),),
                    annotations=annotations,
                )

        # lambda/function runtimes
        if rtype in _RUNTIME_ATTRS:
            runtime = interpolate(block.body.get(_RUNTIME_ATTRS[rtype]), variables)
            if isinstance(runtime, str) and runtime:
                m = re.match(r"([a-z]+)(\d+(?:\.\d+)?)?", runtime)
                if m:
                    yield self._runtime_component(ctx, entry, m.group(1), m.group(2), resource_ref)

        # DB engine versions
        if rtype in _DB_ENGINE:
            eng_attr, ver_attr = _DB_ENGINE[rtype]
            engine = interpolate(block.body.get(eng_attr), variables)
            ver = interpolate(block.body.get(ver_attr), variables)
            if isinstance(engine, str) and isinstance(ver, str):
                yield self._runtime_component(ctx, entry, engine, ver, resource_ref, ctype="application")

    def _runtime_component(self, ctx: CatalogerContext, entry: Entry, name: str,
                           version: str | None, resource_ref: str, ctype: str = "application") -> Finding:
        purl = make_purl("generic", name, version) if version else None
        return Finding(
            claim=ComponentClaim(ctype=ctype, name=name, version=version, purl=purl, ecosystem="generic"),
            evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                   captured=f"{name} {version or '?'}"),),
            edges=(EdgeClaim(kind=EdgeType.RUNS, src=resource_ref,
                             dst=ref_purl(purl) if purl else f"claim:generic/{name}@"),),
        )


class TerraformLockCataloger(Cataloger):
    """`.terraform.lock.hcl` — locked tier: exact provider versions + h1/zh hashes."""

    id = "iac/terraform-lock"
    version = 1
    matchers = [Matcher(basename=".terraform.lock.hcl")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            _attrs, blocks = parse_hcl(text)
        except Exception as e:  # noqa: BLE001
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        for block in blocks:
            if block.btype != "provider" or not block.labels:
                continue
            source = block.labels[0]  # "registry.terraform.io/hashicorp/aws"
            name = source.rsplit("/", 1)[-1]
            namespace = source.rsplit("/", 1)[0]
            version = block.body.get("version")
            if isinstance(version, Unresolved) or not version:
                continue
            hashes: tuple[tuple[str, str], ...] = ()
            hlist = block.body.get("hashes")
            if isinstance(hlist, list):
                for h in hlist:
                    if isinstance(h, str) and h.startswith("h1:"):
                        hashes = (("terraform-h1", h[3:]),)
                        break
            purl = make_purl("terraform", name, str(version), namespace=namespace)
            yield Finding(
                claim=ComponentClaim(
                    ctype="library", name=name, version=str(version), purl=purl,
                    ecosystem="terraform", namespace=namespace, hashes=hashes,
                ),
                evidence=(ctx.evidence("lockfile-parse", Tier.LOCKED, entry,
                                       span=find_span(text, source), captured=f"{source} {version}"),),
            )


def _extract_image(block: Block, attr: str, variables: dict[str, Any]) -> str | None:
    value = block.body.get(attr)
    resolved = interpolate(value, variables)
    if isinstance(resolved, str):
        # ECS container_definitions is JSON with an "image" field
        m = re.search(r'"image"\s*:\s*"([^"]+)"', resolved)
        if m:
            return m.group(1)
        if "/" in resolved or ":" in resolved:
            return resolved
    return None


def _clean_constraint(v: str) -> str | None:
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", str(v))
    return m.group(1) if m else None


register(TerraformCataloger())
register(TerraformLockCataloger())
