"""CloudFormation / Bicep / Ansible analyzers.

- **CFN**: YAML/JSON template parse incl. intrinsics (``Fn::Sub``/``Ref``
  partial evaluation with parameter defaults); SAM function runtimes;
  ``AWS::ECS::TaskDefinition`` / SAM image refs → Resource + image components.
- **Bicep/ARM**: module refs (``br:`` registry refs are versioned components).
- **Ansible**: ``requirements.yml`` roles/collections (galaxy components);
  collection ``MANIFEST.json`` (installed tier); playbook package-install task
  scan (apt/yum/pip/npm → declared-tier future-state packages).

CDK/Pulumi are analysed at two levels: program deps via the language
catalogers, and the synthesized output in native mode.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

import yaml

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.catalogers.common import ref_family, ref_project, ref_purl
from sorb.iac.imageref import parse_image_reference
from sorb.ident import make_purl
from sorb.model import (
    ComponentClaim,
    EdgeClaim,
    EdgeType,
    Finding,
    Scope,
    Tier,
)
from sorb.source.base import Entry

_SAM_RUNTIME_RE = re.compile(r"([a-z]+)(\d+(?:\.\d+)?)?")


class CfnCataloger(Cataloger):
    id = "iac/cloudformation"
    version = 1
    matchers = [Matcher(basename="*.template"), Matcher(basename="template.yaml"),
                Matcher(basename="template.yml"), Matcher(basename="cloudformation.yaml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        doc = _load_cfn(text)
        if not isinstance(doc, dict) or "Resources" not in doc:
            return
        params = {
            k: v.get("Default")
            for k, v in (doc.get("Parameters") or {}).items()
            if isinstance(v, dict) and v.get("Default") is not None
        }
        for logical, res in (doc.get("Resources") or {}).items():
            if not isinstance(res, dict):
                continue
            rtype = str(res.get("Type", ""))
            props = res.get("Properties") or {}
            yield Finding(
                claim=ComponentClaim(
                    ctype="resource", name=f"{rtype}.{logical}", ecosystem="cloudformation",
                    attrs=(("resource_type", rtype),),
                ),
                evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                       captured=f"{rtype} {logical}"),),
            )
            # SAM function runtime
            if rtype in ("AWS::Serverless::Function", "AWS::Lambda::Function"):
                runtime = _resolve_intrinsic(props.get("Runtime"), params)
                if isinstance(runtime, str):
                    m = _SAM_RUNTIME_RE.match(runtime)
                    if m:
                        purl = make_purl("generic", m.group(1), m.group(2)) if m.group(2) else None
                        yield Finding(
                            claim=ComponentClaim(ctype="application", name=m.group(1),
                                                 version=m.group(2), purl=purl, ecosystem="generic"),
                            evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                                   captured=f"runtime {runtime}"),),
                            edges=(EdgeClaim(kind=EdgeType.RUNS, src=f"resource:{rtype}.{logical}",
                                             dst=ref_purl(purl) if purl else f"claim:generic/{m.group(1)}@"),),
                        )
            # image refs (ECS task def / SAM image)
            image = _find_image(props)
            if image:
                image = _resolve_intrinsic(image, params)
                ref = parse_image_reference(image) if isinstance(image, str) else None
                if ref is not None:
                    yield Finding(
                        claim=ComponentClaim(ctype="application", name=ref.name(),
                                             version=ref.digest or ref.tag, purl=ref.purl(),
                                             ecosystem="oci", attrs=(("image-ref", ref.raw),)),
                        evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                               captured=f"image {ref.raw}"),),
                        edges=(EdgeClaim(kind=EdgeType.RUNS, src=f"resource:{rtype}.{logical}",
                                         dst=ref_purl(ref.purl())),),
                    )


class BicepCataloger(Cataloger):
    id = "iac/bicep"
    version = 1
    matchers = [Matcher(basename="*.bicep")]

    _MODULE_RE = re.compile(r"module\s+\w+\s+'(br(?:/[\w.\-]+)?:[\w.\-/]+:[\w.\-]+)'")

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        for m in self._MODULE_RE.finditer(text):
            ref = m.group(1)  # br:registry/path:version
            body = ref.split(":", 1)[1]
            path, _, version = body.rpartition(":")
            name = path.rsplit("/", 1)[-1]
            purl = make_purl("bicep", name, version, namespace=path.rsplit("/", 1)[0]) if version else None
            line = text.count("\n", 0, m.start()) + 1
            yield Finding(
                claim=ComponentClaim(ctype="library", name=name, version=version, purl=purl,
                                     ecosystem="bicep", attrs=(("registry-ref", ref),)),
                evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                       span=(line, line), captured=ref),),
            )


class AnsibleRequirementsCataloger(Cataloger):
    id = "iac/ansible-requirements"
    version = 1
    matchers = [Matcher(basename="requirements.yml"), Matcher(basename="requirements.yaml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        if "roles/" not in entry.path and "playbook" not in entry.path and "/" in entry.path.rsplit("requirements", 1)[0]:
            pass  # galaxy requirements can live anywhere; parse regardless
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return
        # galaxy requirements: {roles: [...], collections: [...]} or a bare list
        sections: list[tuple[str, list[Any]]] = []
        if isinstance(doc, dict):
            sections = [("role", doc.get("roles") or []), ("collection", doc.get("collections") or [])]
        elif isinstance(doc, list):
            sections = [("role", doc)]
        for kind, items in sections:
            for item in items:
                name = version = None
                if isinstance(item, str):
                    name = item
                elif isinstance(item, dict):
                    name = item.get("name") or item.get("src") or item.get("role")
                    version = item.get("version")
                if not name:
                    continue
                ptype = "ansible-role" if kind == "role" else "ansible-collection"
                purl = make_purl(ptype, str(name).rsplit(".", 1)[-1], str(version) if version else None,
                                 namespace=str(name).rsplit(".", 1)[0] if "." in str(name) else None) if version else None
                yield Finding(
                    claim=ComponentClaim(
                        ctype="library", name=str(name), version=str(version) if version else None,
                        purl=purl, ecosystem=ptype,
                    ),
                    evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                           captured=f"{kind} {name} {version or ''}".strip()),),
                )


class AnsiblePlaybookCataloger(Cataloger):
    """Playbook package-install tasks → declared-tier future-state packages."""

    id = "iac/ansible-playbook"
    version = 1
    matchers = [Matcher(glob="*playbook*.yml"), Matcher(glob="*playbooks/*.yml"),
                Matcher(glob="*tasks/*.yml")]

    _MODULES = {"apt": "deb", "yum": "rpm", "dnf": "rpm", "package": "generic",
                "pip": "pypi", "npm": "npm", "gem": "gem"}

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError:
            return
        for doc in docs:
            for task in _iter_tasks(doc):
                for module, purl_type in self._MODULES.items():
                    spec = task.get(module)
                    if spec is None:
                        continue
                    names = self._task_names(spec)
                    for name, version in names:
                        distro = "debian" if purl_type == "deb" else ("rhel" if purl_type == "rpm" else None)
                        purl = make_purl(purl_type, name, version, namespace=distro) if version else None
                        yield Finding(
                            claim=ComponentClaim(
                                ctype="os-package" if distro else "library", name=name,
                                version=version, purl=purl, ecosystem=purl_type, namespace=distro,
                                attrs=(("predicted", f"ansible-{module}"),),
                            ),
                            evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                                   captured=f"{module}: {name} {version or ''}".strip()),),
                            edges=(EdgeClaim(kind=EdgeType.DEPENDS_ON, src=ref_project(_proj(entry.path)),
                                             dst=ref_purl(purl) if (version and purl) else ref_family(purl_type, name),
                                             scope=Scope.RUNTIME, direct=False),),
                        )

    def _task_names(self, spec: Any) -> list[tuple[str, str | None]]:
        raw: list[str] = []
        if isinstance(spec, str):
            raw = [spec]
        elif isinstance(spec, dict):
            n = spec.get("name") or spec.get("pkg")
            if isinstance(n, list):
                raw = [str(x) for x in n]
            elif n:
                raw = [str(n)]
        elif isinstance(spec, list):
            raw = [str(x) for x in spec]
        out: list[tuple[str, str | None]] = []
        for item in raw:
            if "{{" in item:
                continue  # unresolved jinja
            name, version = item, None
            if "=" in item:
                name, _, version = item.partition("=")
            out.append((name.strip(), version))
        return out


def _iter_tasks(doc: Any) -> Iterable[dict[str, Any]]:
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, dict):
                if "tasks" in item and isinstance(item["tasks"], list):
                    yield from (t for t in item["tasks"] if isinstance(t, dict))
                else:
                    yield item
    elif isinstance(doc, dict) and isinstance(doc.get("tasks"), list):
        yield from (t for t in doc["tasks"] if isinstance(t, dict))


def _proj(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else "."


# -- CFN helpers ------------------------------------------------------------------------


def _load_cfn(text: str) -> Any:
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    try:
        return yaml.load(text, Loader=_CfnLoader)
    except yaml.YAMLError:
        return None


class _CfnLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _cfn_intrinsic(loader: yaml.Loader, tag_suffix: str, node: yaml.Node) -> Any:
    name = "Fn::" + tag_suffix if tag_suffix != "Ref" else "Ref"
    if isinstance(node, yaml.ScalarNode):
        return {name: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {name: loader.construct_sequence(node)}
    return {name: loader.construct_mapping(node)}


_CfnLoader.add_multi_constructor("!", _cfn_intrinsic)


def _resolve_intrinsic(value: Any, params: dict[str, Any]) -> Any:
    """Partial-eval Ref/Fn::Sub against parameter defaults."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "Ref" in value:
            return params.get(value["Ref"], f"<unresolved:Ref {value['Ref']}>")
        if "Fn::Sub" in value:
            tmpl = value["Fn::Sub"]
            tmpl = tmpl[0] if isinstance(tmpl, list) else tmpl
            return re.sub(r"\$\{(\w+)\}",
                          lambda m: str(params.get(m.group(1), f"<unresolved:{m.group(1)}>")),
                          str(tmpl))
    return value


def _find_image(props: dict[str, Any]) -> Any:
    if "ImageUri" in props:
        return props["ImageUri"]
    if "Code" in props and isinstance(props["Code"], dict):
        return props["Code"].get("ImageUri")
    for cd in props.get("ContainerDefinitions", []) or []:
        if isinstance(cd, dict) and cd.get("Image"):
            return cd["Image"]
    return None


register(CfnCataloger())
register(BicepCataloger())
register(AnsibleRequirementsCataloger())
register(AnsiblePlaybookCataloger())
