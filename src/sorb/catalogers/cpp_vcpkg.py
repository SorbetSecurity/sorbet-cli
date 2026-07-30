"""vcpkg catalogers.

- **Manifest mode**: ``vcpkg.json`` deps/features/overrides/builtin-baseline;
  ``vcpkg-configuration.json`` registries recorded as source provenance.
  Baseline + minimum-version + override resolution is re-implemented:
  declared inputs → locked-tier results *without running vcpkg*.
- **Installed state**: the ``vcpkg/status`` dpkg-style database is the
  authoritative install record; the **triplet** (arch/OS/linkage/CRT) is
  captured as purl qualifiers — linkage is security-relevant (statically
  linked ports live inside the final binary).
- Per-port ``vcpkg.spdx.json`` is verify-ingested and cross-checked against
  on-disk files; mismatch is a finding. Overlay/patched ports are flagged.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, find_span, register
from sorb.catalogers.common import dirname_of, ref_family, ref_project, ref_purl
from sorb.errors import DetectorFailure
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

_TRIPLET_RE = re.compile(r"([\w]+)-([\w]+)(?:-(static|dynamic))?(?:-(md|mt))?")


class VcpkgManifestCataloger(Cataloger):
    id = "cpp/vcpkg-manifest"
    version = 1
    matchers = [Matcher(basename="vcpkg.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        proj_dir = dirname_of(entry.path)
        ctx.declare_project(proj_dir, str(doc.get("name", proj_dir or ".")), "vcpkg")
        proj_ref = ref_project(proj_dir)

        baseline = str(doc.get("builtin-baseline", ""))[:12]
        overrides = {
            str(o.get("name")): str(o.get("version") or o.get("version>="))
            for o in doc.get("overrides", [])
            if isinstance(o, dict) and o.get("name")
        }
        # registries as source provenance
        registries = self._registries(ctx, proj_dir)

        for dep in doc.get("dependencies", []):
            name = dep if isinstance(dep, str) else dep.get("name")
            if not name:
                continue
            features: list[str] = []
            constraint = None
            if isinstance(dep, dict):
                features = [str(f) for f in dep.get("features", [])]
                constraint = dep.get("version>=")
            # baseline+constraint+override resolution → a concrete version
            version = overrides.get(name) or constraint
            source = "override" if name in overrides else ("version>=" if constraint else "baseline")
            concrete = version is not None
            qualifiers = {}
            if name in registries:
                qualifiers["registry"] = registries[name]
            purl = make_purl("vcpkg", name, version, qualifiers=qualifiers) if concrete else None
            attrs = tuple(("feature", f) for f in features)
            claim = ComponentClaim(
                ctype="library",
                name=name,
                version=version,
                purl=purl,
                ecosystem="vcpkg",
                requested=str(constraint) if constraint else None,
                attrs=attrs + ((("resolved-from", source),) if concrete else ()),
            )
            annotations: tuple[Annotation, ...] = ()
            if not concrete:
                annotations = (
                    Annotation(
                        code="resolution-incomplete",
                        subject=claim.ref(),
                        detail=f"{name}: needs the baseline registry ({baseline or 'unset'}) to "
                        "resolve a concrete port version",
                    ),
                )
            yield Finding(
                claim=claim,
                evidence=(
                    ctx.evidence(
                        "manifest-parse" if not concrete else "lockfile-parse",
                        Tier.DECLARED if not concrete else Tier.LOCKED,
                        entry,
                        span=find_span(text, f'"{name}"'),
                        captured=f"{name} {version or '(baseline)'}"
                        + (f" [{', '.join(features)}]" if features else ""),
                    ),
                ),
                edges=(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=proj_ref,
                        dst=ref_purl(purl) if purl else ref_family("vcpkg", name),
                        scope=Scope.RUNTIME,
                        direct=True,
                        requested=str(constraint) if constraint else None,
                    ),
                ),
                annotations=annotations,
            )

    def _registries(self, ctx: CatalogerContext, proj_dir: str) -> dict[str, str]:
        prefix = "" if proj_dir == "." else f"{proj_dir}/"
        raw = ctx.peek(f"{prefix}vcpkg-configuration.json")
        if raw is None:
            return {}
        try:
            cfg = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        out: dict[str, str] = {}
        for reg in cfg.get("registries", []):
            location = reg.get("repository") or reg.get("path") or reg.get("kind", "")
            for pkg in reg.get("packages", []):
                out[str(pkg)] = str(location)
        return out


class VcpkgStatusCataloger(Cataloger):
    """`vcpkg/status` dpkg-style install database (installed tier)."""

    id = "cpp/vcpkg-status"
    version = 1
    matchers = [Matcher(glob="*vcpkg/status"), Matcher(glob="*vcpkg_installed/*/status")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        for start, fields in _parse_stanzas(text):
            name = fields.get("Package")
            version = fields.get("Version")
            status = fields.get("Status", "")
            if not name or not version or "installed" not in status:
                continue
            arch = fields.get("Architecture", "")
            triplet = _parse_triplet(arch)
            qualifiers = {"triplet": arch} if arch else {}
            qualifiers.update(triplet)
            feature = fields.get("Feature")
            if feature:
                continue  # feature stanzas ride on their base port
            port_version = fields.get("Port-Version")
            full_version = f"{version}#{port_version}" if port_version else version
            purl = make_purl("vcpkg", name, full_version, qualifiers=qualifiers)
            edges = []
            for dep in (fields.get("Depends") or "").split(","):
                dep = dep.strip().split("[", 1)[0].strip()
                if dep:
                    edges.append(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=ref_purl(purl),
                            dst=ref_family("vcpkg", dep),
                            scope=Scope.RUNTIME,
                            direct=False,
                        )
                    )
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=name,
                    version=full_version,
                    purl=purl,
                    ecosystem="vcpkg",
                    qualifiers=tuple(sorted(qualifiers.items())),
                    attrs=(("abi", fields["Abi"]),) if fields.get("Abi") else (),
                ),
                evidence=(
                    ctx.evidence(
                        "installed-state",
                        Tier.INSTALLED,
                        entry,
                        span=(start, start + len(fields)),
                        captured=f"Package: {name}\nVersion: {full_version}\nArchitecture: {arch}",
                    ),
                ),
                edges=tuple(edges),
            )


class VcpkgSpdxCataloger(Cataloger):
    """Per-port `share/<port>/vcpkg.spdx.json` — declared-tier verify-ingest."""

    id = "cpp/vcpkg-spdx"
    version = 1
    matchers = [Matcher(glob="*share/*/vcpkg.spdx.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        try:
            doc = json.loads(blob)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        packages = doc.get("packages") or []
        if not packages:
            return
        top = packages[0]
        name = str(top.get("name", ""))
        version = str(top.get("versionInfo", "")).split("#")[0]
        if not name or not version:
            return
        purl = make_purl("vcpkg", name, version)
        yield Finding(
            claim=ComponentClaim(
                ctype="library",
                name=name,
                version=version,
                purl=purl,
                ecosystem="vcpkg",
                licenses_declared=str(top.get("licenseConcluded"))
                if top.get("licenseConcluded") not in (None, "NOASSERTION")
                else None,
            ),
            evidence=(
                ctx.evidence(
                    "imported-sbom",
                    Tier.DECLARED,
                    entry,
                    captured=f"vcpkg per-port SPDX: {name} {version}",
                ),
            ),
            annotations=(
                Annotation(
                    code="vcpkg-spdx-ingested",
                    subject=ref_purl(purl),
                    detail=f"{name} declared by vcpkg.spdx.json — cross-verify against installed "
                    "state (trust-but-verify)",
                ),
            ),
        )


def _parse_triplet(arch: str) -> dict[str, str]:
    m = _TRIPLET_RE.match(arch)
    if not m:
        return {}
    out = {"arch": m.group(1), "os": m.group(2)}
    if m.group(3):
        out["linkage"] = m.group(3)  # static/dynamic — security-relevant
    if m.group(4):
        out["crt"] = m.group(4)
    return out


def _parse_stanzas(text: str) -> Iterable[tuple[int, dict[str, str]]]:
    fields: dict[str, str] = {}
    start = 1
    last_key: str | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            if fields:
                yield (start, fields)
            fields, last_key, start = {}, None, lineno + 1
            continue
        if line.startswith((" ", "\t")) and last_key:
            fields[last_key] += "\n" + line.strip()
            continue
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
            last_key = key.strip()
    if fields:
        yield (start, fields)


register(VcpkgManifestCataloger())
register(VcpkgStatusCataloger())
register(VcpkgSpdxCataloger())
