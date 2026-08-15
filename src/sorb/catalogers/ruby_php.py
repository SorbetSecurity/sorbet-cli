"""Ruby and PHP catalogers.

Ruby: ``Gemfile.lock`` (the ``specs:`` indentation tree IS the resolved graph
— edges come straight from the file), ``*.gemspec`` static parse (declared;
installed tier under ``specifications/``).

PHP: ``composer.json`` (declared), ``composer.lock`` (locked, rich: dist
digests + per-package require edges), ``vendor/composer/installed.json``
(installed — the authoritative post-install state, wins tier over the lock).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

from sorb.catalogers.base import (
    Cataloger,
    CatalogerContext,
    Matcher,
    find_span,
    register,
)
from sorb.catalogers.common import dirname_of, ref_family, ref_project, ref_purl
from sorb.errors import DetectorFailure
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

# -- Ruby --------------------------------------------------------------------------

_SPEC_RE = re.compile(r"^    ([\w\-]+) \(([^)]+)\)$")


def _split_platform(spec: str) -> tuple[str, str | None]:
    """`1.16.5-x86_64-linux` -> ("1.16.5", "x86_64-linux").

    Bundler writes one spec line per platform it resolved for. RubyGems
    versions separate prerelease parts with dots, never dashes, so a dash
    reliably starts the platform - and the platform is not part of the
    version any advisory would name.
    """
    version, dash, platform = spec.partition("-")
    return (version, platform) if dash else (spec, None)
_SPEC_DEP_RE = re.compile(r"^      ([\w\-]+)(?: \(([^)]+)\))?$")
_DIRECT_RE = re.compile(r"^  ([\w\-]+)(?:!| \(([^)]+)\))?")


class GemfileLockCataloger(Cataloger):
    id = "ruby/gemfile-lock"
    version = 1
    matchers = [Matcher(basename="Gemfile.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        ctx.declare_project(proj_dir, proj_dir or ".", "bundler")
        proj_ref = ref_project(proj_dir)

        section = None
        specs: dict[str, tuple[int, str, list[tuple[str, str | None]]]] = {}
        platforms: dict[str, set[str]] = {}
        direct: dict[str, str | None] = {}
        current: str | None = None
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line and not line.startswith(" "):
                section = line.strip()
                current = None
                continue
            if section in ("GEM", "GIT", "PATH"):
                m = _SPEC_RE.match(line)
                if m:
                    name, version = m.group(1), m.group(2)
                    version, platform = _split_platform(version)
                    if platform:
                        platforms.setdefault(name, set()).add(platform)
                    # platform variants of one gem are the same package; the
                    # first spec line owns the dependency list
                    if name not in specs:
                        specs[name] = (lineno, version, [])
                    current = name
                    continue
                dm = _SPEC_DEP_RE.match(line)
                if dm and current is not None:
                    specs[current][2].append((dm.group(1), dm.group(2)))
            elif section == "DEPENDENCIES":
                m = _DIRECT_RE.match(line)
                if m:
                    direct[m.group(1)] = m.group(2)

        for name, (lineno, version, deps) in specs.items():
            purl = make_purl("gem", name, version)
            attrs = (
                ("platforms", ",".join(sorted(platforms[name]))),
            ) if name in platforms else ()
            edges: list[EdgeClaim] = [
                EdgeClaim(
                    kind=EdgeType.DEPENDS_ON,
                    src=ref_purl(purl),
                    dst=ref_family("gem", dep_name),
                    scope=Scope.RUNTIME,
                    direct=False,
                    requested=constraint,
                )
                for dep_name, constraint in deps
            ]
            if name in direct:
                edges.append(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=proj_ref,
                        dst=ref_purl(purl),
                        scope=Scope.RUNTIME,
                        direct=True,
                        requested=direct[name],
                    )
                )
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=name,
                    version=version,
                    purl=purl,
                    ecosystem="gem",
                    attrs=attrs,
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse",
                        Tier.LOCKED,
                        entry,
                        span=(lineno, lineno),
                        captured=f"{name} ({version})",
                    ),
                ),
                edges=tuple(edges),
            )


_GEMSPEC_NAME_RE = re.compile(r"""\.\s*name\s*=\s*['"]([\w\-]+)['"]""")
_GEMSPEC_VERSION_RE = re.compile(r"""\.\s*version\s*=\s*['"]([\w.\-]+)['"]""")


class GemspecCataloger(Cataloger):
    id = "ruby/gemspec"
    version = 1
    matchers = [Matcher(basename="*.gemspec")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        name_m = _GEMSPEC_NAME_RE.search(text)
        version_m = _GEMSPEC_VERSION_RE.search(text)
        if not name_m:
            return
        name = name_m.group(1)
        version = version_m.group(1) if version_m else None
        installed = "specifications/" in entry.path
        yield Finding(
            claim=ComponentClaim(
                ctype="library",
                name=name,
                version=version,
                purl=make_purl("gem", name, version) if version else None,
                ecosystem="gem",
            ),
            evidence=(
                ctx.evidence(
                    "installed-state" if installed else "manifest-parse",
                    Tier.INSTALLED if installed else Tier.DECLARED,
                    entry,
                    span=find_span(text, name_m.group(0)),
                    captured=name_m.group(0).strip(),
                ),
            ),
        )


# -- PHP ----------------------------------------------------------------------------


def _composer_findings(
    ctx: CatalogerContext,
    entry: Entry,
    packages: list[dict[str, object]],
    *,
    tier: Tier,
    technique: str,
    dev: bool,
    text: str,
) -> Iterable[Finding]:
    for pkg in packages:
        name = str(pkg.get("name", ""))
        version = str(pkg.get("version", "")).lstrip("v")
        if not name or not version or "/" not in name:
            continue
        vendor, _, short = name.partition("/")
        hashes: tuple[tuple[str, str], ...] = ()
        dist = pkg.get("dist")
        if isinstance(dist, dict) and dist.get("shasum"):
            hashes = (("sha1", str(dist["shasum"])),)
        require = pkg.get("require")
        require_items = require.items() if isinstance(require, dict) else ()
        edges = [
            EdgeClaim(
                kind=EdgeType.DEPENDS_ON,
                src=ref_purl(make_purl("composer", short, version, namespace=vendor)),
                dst=ref_family("composer", dep),
                scope=Scope.DEV if dev else Scope.RUNTIME,
                direct=False,
                requested=str(constraint),
            )
            for dep, constraint in require_items
            if "/" in dep  # skips php/ext-* platform requirements
        ]
        attrs: tuple[tuple[str, str], ...] = (("dev", "true"),) if dev else ()
        source = pkg.get("source")
        if isinstance(source, dict) and source.get("reference"):
            attrs += (("source-ref", str(source["reference"])),)
        raw_license = pkg.get("license")
        yield Finding(
            claim=ComponentClaim(
                ctype="library",
                name=name,
                version=version,
                purl=make_purl("composer", short, version, namespace=vendor),
                ecosystem="composer",
                namespace=vendor,
                hashes=hashes,
                licenses_declared=" OR ".join(str(x) for x in raw_license)
                if isinstance(raw_license, list) and raw_license
                else None,
                attrs=attrs,
            ),
            evidence=(
                ctx.evidence(
                    technique,
                    tier,
                    entry,
                    span=find_span(text, f'"{name}"'),
                    captured=f"{name} {version}",
                ),
            ),
            edges=tuple(edges),
        )


class ComposerLockCataloger(Cataloger):
    id = "php/composer-lock"
    version = 2  # replaces the original table-driven spec with the full parser
    matchers = [Matcher(basename="composer.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        yield from _composer_findings(
            ctx, entry, doc.get("packages") or [],
            tier=Tier.LOCKED, technique="lockfile-parse", dev=False, text=text,
        )
        yield from _composer_findings(
            ctx, entry, doc.get("packages-dev") or [],
            tier=Tier.LOCKED, technique="lockfile-parse", dev=True, text=text,
        )


class ComposerJsonCataloger(Cataloger):
    id = "php/composer-json"
    version = 1
    matchers = [Matcher(basename="composer.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        if "vendor/" in entry.path:
            return  # vendored composer.json files are installed-state, not project manifests
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        proj_dir = dirname_of(entry.path)
        ctx.declare_project(proj_dir, str(doc.get("name", proj_dir or ".")), "composer")
        proj_ref = ref_project(proj_dir)
        for section, dev in (("require", False), ("require-dev", True)):
            for name, constraint in (doc.get(section) or {}).items():
                if "/" not in name:
                    continue  # php, ext-*, lib-* platform packages
                vendor, _, short = name.partition("/")
                claim = ComponentClaim(
                    ctype="library",
                    name=name,
                    version=None,
                    ecosystem="composer",
                    namespace=vendor,
                    requested=str(constraint),
                    attrs=(("dev", "true"),) if dev else (),
                )
                yield Finding(
                    claim=claim,
                    evidence=(
                        ctx.evidence(
                            "manifest-parse",
                            Tier.DECLARED,
                            entry,
                            span=find_span(text, f'"{name}"'),
                            captured=f'"{name}": "{constraint}"',
                        ),
                    ),
                    edges=(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=proj_ref,
                            dst=ref_family("composer", name),
                            scope=Scope.DEV if dev else Scope.RUNTIME,
                            direct=True,
                            requested=str(constraint),
                        ),
                    ),
                )


class ComposerInstalledCataloger(Cataloger):
    """`vendor/composer/installed.json` — authoritative post-install state."""

    id = "php/composer-installed"
    version = 1
    matchers = [Matcher(glob="*vendor/composer/installed.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        packages = doc.get("packages") if isinstance(doc, dict) else doc  # v2 vs v1
        if not isinstance(packages, list):
            return
        dev_names = set(doc.get("dev-package-names") or []) if isinstance(doc, dict) else set()
        regular = [p for p in packages if str(p.get("name")) not in dev_names]
        dev = [p for p in packages if str(p.get("name")) in dev_names]
        yield from _composer_findings(
            ctx, entry, regular, tier=Tier.INSTALLED, technique="installed-state",
            dev=False, text=text,
        )
        yield from _composer_findings(
            ctx, entry, dev, tier=Tier.INSTALLED, technique="installed-state",
            dev=True, text=text,
        )


register(GemfileLockCataloger())
register(GemspecCataloger())
register(ComposerLockCataloger())
register(ComposerJsonCataloger())
register(ComposerInstalledCataloger())
