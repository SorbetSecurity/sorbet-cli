"""Python catalogers.

- ``python/requirements`` — full PEP 508 lines (extras, markers, URLs,
  ``-r``/``-c`` includes with cycle guard); fully-pinned files with ``--hash``
  lines are treated as locked tier (pip-tools style).
- ``python/pyproject`` — PEP 621 + poetry/pdm/uv tool tables.
- ``python/setup-py`` — static AST only; dynamic → annotation, never silence.
- ``python/poetry-lock``, ``python/uv-lock``, ``python/pipfile-lock``.
- ``python/dist-info`` — installed state: METADATA/RECORD/INSTALLER/direct_url.
"""

from __future__ import annotations

import ast
import json
import re
import tomllib
from collections.abc import Iterable
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from sorb.catalogers.base import (
    Cataloger,
    CatalogerContext,
    Matcher,
    find_span,
    register,
    snippet_at,
)
from sorb.catalogers.common import dirname_of, ref_family, ref_file, ref_project, ref_purl
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


def _pypi_purl(name: str, version: str | None = None) -> str:
    return make_purl("pypi", _norm_name(name), version)


def _norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class RequirementsCataloger(Cataloger):
    id = "python/requirements"
    version = 1
    matchers = [Matcher(basename="requirements*.txt"), Matcher(basename="constraints*.txt")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        yield from self._parse_file(ctx, entry, blob, seen={entry.path})

    def _parse_file(
        self, ctx: CatalogerContext, entry: Entry, blob: bytes, seen: set[str]
    ) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        proj_ref = ref_project(proj_dir)
        ctx.declare_project(proj_dir, proj_dir, "python")

        lines = _logical_lines(text)
        all_pinned = True
        any_hash = "--hash=" in text
        parsed: list[tuple[int, Requirement, str]] = []
        for lineno, line in lines:
            if line.startswith(("-r ", "-c ", "--requirement", "--constraint")):
                inc = line.split(None, 1)[1].strip() if " " in line else ""
                inc_path = (proj_dir + "/" + inc).lstrip("./") if proj_dir != "." else inc
                if inc_path in seen:  # cycle guard
                    continue
                seen.add(inc_path)
                inc_blob = ctx.peek(inc_path)
                if inc_blob is not None:
                    inc_entry = Entry(path=inc_path, size=len(inc_blob), role=entry.role)
                    yield from self._parse_file(ctx, inc_entry, inc_blob, seen)
                continue
            if line.startswith("-"):
                continue
            spec = line.split(" --", 1)[0].strip()  # strip per-line options (--hash=…)
            if not spec:
                continue
            try:
                req = Requirement(spec)
            except InvalidRequirement:
                continue
            pinned = any(s.operator == "==" for s in req.specifier)
            if not pinned:
                all_pinned = False
            parsed.append((lineno, req, spec))

        locked = bool(parsed) and all_pinned and any_hash
        tier = Tier.LOCKED if locked else Tier.DECLARED
        technique = "lockfile-parse" if locked else "manifest-parse"
        for lineno, req, spec in parsed:
            pin = next((s.version for s in req.specifier if s.operator == "=="), None)
            claim = ComponentClaim(
                ctype="library",
                name=_norm_name(req.name),
                version=pin,
                purl=_pypi_purl(req.name, pin) if pin else None,
                ecosystem="pypi",
                requested=str(req.specifier) or None,
            )
            marker = str(req.marker) if req.marker else None
            edge = EdgeClaim(
                kind=EdgeType.DEPENDS_ON,
                src=proj_ref,
                dst=ref_purl(claim.purl) if claim.purl else ref_family("pypi", claim.name),
                scope=Scope.RUNTIME,
                direct=True,
                requested=str(req.specifier) or None,
                marker=marker,
            )
            yield Finding(
                claim=claim,
                evidence=(
                    ctx.evidence(technique, tier, entry, span=(lineno, lineno), captured=spec),
                ),
                edges=(edge,),
            )


def _logical_lines(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    pending = ""
    start = 0
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not line:
            continue
        if not pending:
            start = i
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        out.append((start, (pending + line).strip()))
        pending = ""
    return out


class PyprojectCataloger(Cataloger):
    id = "python/pyproject"
    version = 1
    matchers = [Matcher(basename="pyproject.toml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        try:
            doc = tomllib.loads(blob.decode("utf-8", errors="replace"))
        except tomllib.TOMLDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        project_table = doc.get("project", {})
        poetry = doc.get("tool", {}).get("poetry", {})
        name = project_table.get("name") or poetry.get("name") or proj_dir
        ctx.declare_project(proj_dir, str(name), "python")
        proj_ref = ref_project(proj_dir)

        def emit_pep508(specs: list[str], scope: Scope) -> Iterable[Finding]:
            for spec in specs:
                try:
                    req = Requirement(spec)
                except InvalidRequirement:
                    continue
                claim = ComponentClaim(
                    ctype="library",
                    name=_norm_name(req.name),
                    version=None,
                    ecosystem="pypi",
                    requested=str(req.specifier) or None,
                )
                yield Finding(
                    claim=claim,
                    evidence=(
                        ctx.evidence(
                            "manifest-parse",
                            Tier.DECLARED,
                            entry,
                            span=find_span(text, req.name),
                            captured=spec,
                        ),
                    ),
                    edges=(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=proj_ref,
                            dst=ref_family("pypi", claim.name),
                            scope=scope,
                            direct=True,
                            requested=str(req.specifier) or None,
                            marker=str(req.marker) if req.marker else None,
                        ),
                    ),
                )

        yield from emit_pep508(list(project_table.get("dependencies") or []), Scope.RUNTIME)
        for _group, specs in (project_table.get("optional-dependencies") or {}).items():
            yield from emit_pep508(list(specs), Scope.OPTIONAL)
        for _group, specs in (
            (doc.get("dependency-groups") or {}) if isinstance(doc.get("dependency-groups"), dict) else {}
        ).items():
            specs = [s for s in specs if isinstance(s, str)]
            yield from emit_pep508(specs, Scope.DEV)
        yield from emit_pep508(
            [s for s in (doc.get("build-system", {}).get("requires") or []) if isinstance(s, str)],
            Scope.BUILD,
        )

        # poetry tool table: name → range mappings
        def emit_poetry(deps: dict[str, Any], scope: Scope) -> Iterable[Finding]:
            for dep_name, spec in deps.items():
                if dep_name.lower() == "python":
                    continue
                rng = spec if isinstance(spec, str) else (spec or {}).get("version", "*")
                claim = ComponentClaim(
                    ctype="library",
                    name=_norm_name(dep_name),
                    ecosystem="pypi",
                    requested=str(rng),
                )
                yield Finding(
                    claim=claim,
                    evidence=(
                        ctx.evidence(
                            "manifest-parse",
                            Tier.DECLARED,
                            entry,
                            span=find_span(text, dep_name),
                            captured=f"{dep_name} = {rng!r}",
                        ),
                    ),
                    edges=(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=proj_ref,
                            dst=ref_family("pypi", claim.name),
                            scope=scope,
                            direct=True,
                            requested=str(rng),
                        ),
                    ),
                )

        yield from emit_poetry(poetry.get("dependencies") or {}, Scope.RUNTIME)
        for _gname, group in (poetry.get("group") or {}).items():
            yield from emit_poetry(group.get("dependencies") or {}, Scope.DEV)
        yield from emit_poetry(
            (poetry.get("dev-dependencies") or {}), Scope.DEV  # legacy poetry <1.2
        )


class SetupPyCataloger(Cataloger):
    id = "python/setup-py"
    version = 1
    matchers = [Matcher(basename="setup.py")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return
        proj_dir = dirname_of(entry.path)
        proj_ref = ref_project(proj_dir)
        install_requires: list[str] | None = None
        dynamic = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "install_requires":
                        if isinstance(kw.value, ast.List | ast.Tuple):
                            literals: list[str] = []
                            ok = True
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    literals.append(elt.value)
                                else:
                                    ok = False
                                    break
                            if ok:
                                install_requires = literals
                            else:
                                dynamic = True
                        else:
                            dynamic = True
        if install_requires is None and _looks_like_setup(tree):
            dynamic = True
        if dynamic:
            ctx.warn("SORB-W012", f"{entry.path}: dynamic setup.py — dependencies not extracted")
            yield Finding(
                claim=ComponentClaim(ctype="edge-only", name="__edges__"),
                evidence=(),
                annotations=(
                    Annotation(
                        code="unresolved-dynamic-manifest",
                        subject=ref_file(entry.path),
                        detail="setup.py computes dependencies at build time; use --resolve=native",
                    ),
                ),
            )
        for spec in install_requires or []:
            try:
                req = Requirement(spec)
            except InvalidRequirement:
                continue
            claim = ComponentClaim(
                ctype="library",
                name=_norm_name(req.name),
                ecosystem="pypi",
                requested=str(req.specifier) or None,
            )
            yield Finding(
                claim=claim,
                evidence=(
                    ctx.evidence(
                        "manifest-parse",
                        Tier.DECLARED,
                        entry,
                        span=find_span(text, spec),
                        captured=spec,
                    ),
                ),
                edges=(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=proj_ref,
                        dst=ref_family("pypi", claim.name),
                        scope=Scope.RUNTIME,
                        direct=True,
                        requested=str(req.specifier) or None,
                        marker=str(req.marker) if req.marker else None,
                    ),
                ),
            )


def _looks_like_setup(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if (isinstance(fn, ast.Name) and fn.id == "setup") or (
                isinstance(fn, ast.Attribute) and fn.attr == "setup"
            ):
                return True
    return False


class PoetryLockCataloger(Cataloger):
    id = "python/poetry-lock"
    version = 1
    matchers = [Matcher(basename="poetry.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        try:
            doc = tomllib.loads(blob.decode("utf-8", errors="replace"))
        except tomllib.TOMLDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)

        # Staleness check: manifest deps not present in the lock.
        stale = self._is_stale(ctx, proj_dir, doc)
        extra_mods = ("stale-lockfile",) if stale else ()
        if stale:
            ctx.warn("SORB-W010", f"{entry.path}: lockfile does not match pyproject.toml")

        by_name: dict[str, str] = {}
        for pkg in doc.get("package", []):
            if pkg.get("name") and pkg.get("version"):
                by_name[_norm_name(str(pkg["name"]))] = str(pkg["version"])

        for pkg in doc.get("package", []):
            name = pkg.get("name")
            version = pkg.get("version")
            if not name or not version:
                continue
            nname = _norm_name(str(name))
            hashes: tuple[tuple[str, str], ...] = ()
            files = pkg.get("files") or []
            if files and isinstance(files, list):
                h = files[0].get("hash", "")
                algo, _, hexv = h.partition(":")
                if hexv:
                    hashes = ((algo, hexv),)
            purl = _pypi_purl(nname, str(version))
            edges = []
            for dep_name, _spec in (pkg.get("dependencies") or {}).items():
                dn = _norm_name(str(dep_name))
                if dn in by_name:
                    edges.append(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=ref_purl(purl),
                            dst=ref_purl(_pypi_purl(dn, by_name[dn])),
                            direct=False,
                        )
                    )
            annotations: tuple[Annotation, ...] = ()
            if stale:
                annotations = (
                    Annotation(
                        code="stale-lockfile",
                        subject=ref_purl(purl),
                        detail="poetry.lock does not match pyproject.toml",
                    ),
                )
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=nname,
                    version=str(version),
                    purl=purl,
                    ecosystem="pypi",
                    hashes=hashes,
                    attrs=(("category", str(pkg.get("category", ""))),)
                    if pkg.get("category")
                    else (),
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse",
                        Tier.LOCKED,
                        entry,
                        span=find_span(text, f'name = "{name}"'),
                        captured=snippet_at(text, f'name = "{name}"', context=2),
                        extra_modifiers=extra_mods,
                    ),
                ),
                edges=tuple(edges),
                annotations=annotations,
            )

    def _is_stale(self, ctx: CatalogerContext, proj_dir: str, lock: dict[str, Any]) -> bool:
        pp_path = "pyproject.toml" if proj_dir == "." else f"{proj_dir}/pyproject.toml"
        raw = ctx.peek(pp_path)
        if raw is None:
            return False
        try:
            pp = tomllib.loads(raw.decode("utf-8", errors="replace"))
        except tomllib.TOMLDecodeError:
            return False
        declared: set[str] = set()
        poetry = pp.get("tool", {}).get("poetry", {})
        for dep in poetry.get("dependencies") or {}:
            if dep.lower() != "python":
                declared.add(_norm_name(dep))
        for group in (poetry.get("group") or {}).values():
            for dep in group.get("dependencies") or {}:
                declared.add(_norm_name(dep))
        for spec in pp.get("project", {}).get("dependencies") or []:
            try:
                declared.add(_norm_name(Requirement(spec).name))
            except InvalidRequirement:
                continue
        if not declared:
            return False
        locked = {_norm_name(str(p.get("name", ""))) for p in lock.get("package", [])}
        return not declared.issubset(locked)


class UvLockCataloger(Cataloger):
    id = "python/uv-lock"
    version = 1
    matchers = [Matcher(basename="uv.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        try:
            doc = tomllib.loads(blob.decode("utf-8", errors="replace"))
        except tomllib.TOMLDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        text = blob.decode("utf-8", errors="replace")
        by_name: dict[str, str] = {}
        pkgs = doc.get("package", [])
        for pkg in pkgs:
            if pkg.get("name") and pkg.get("version"):
                by_name[_norm_name(str(pkg["name"]))] = str(pkg["version"])
        for pkg in pkgs:
            name = pkg.get("name")
            version = pkg.get("version")
            if not name or not version:
                continue
            nname = _norm_name(str(name))
            source = pkg.get("source") or {}
            if source.get("virtual") or source.get("editable"):
                continue  # the workspace project itself
            hashes: tuple[tuple[str, str], ...] = ()
            sdist = pkg.get("sdist") or {}
            if isinstance(sdist.get("hash"), str):
                algo, _, hexv = sdist["hash"].partition(":")
                if hexv:
                    hashes = ((algo, hexv),)
            purl = _pypi_purl(nname, str(version))
            edges = []
            for dep in pkg.get("dependencies") or []:
                dn = _norm_name(str(dep.get("name", "") if isinstance(dep, dict) else dep))
                if dn in by_name:
                    edges.append(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=ref_purl(purl),
                            dst=ref_purl(_pypi_purl(dn, by_name[dn])),
                            direct=False,
                        )
                    )
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=nname,
                    version=str(version),
                    purl=purl,
                    ecosystem="pypi",
                    hashes=hashes,
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse",
                        Tier.LOCKED,
                        entry,
                        span=find_span(text, f'name = "{name}"'),
                        captured=snippet_at(text, f'name = "{name}"', context=2),
                    ),
                ),
                edges=tuple(edges),
            )


class PipfileLockCataloger(Cataloger):
    id = "python/pipfile-lock"
    version = 1
    matchers = [Matcher(basename="Pipfile.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        try:
            doc = json.loads(blob)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        text = blob.decode("utf-8", errors="replace")
        for section, scope in (("default", Scope.RUNTIME), ("develop", Scope.DEV)):
            for name, info in (doc.get(section) or {}).items():
                if not isinstance(info, dict):
                    continue
                ver = str(info.get("version", "")).lstrip("=")
                if not ver:
                    continue
                nname = _norm_name(str(name))
                hashes: tuple[tuple[str, str], ...] = ()
                hs = info.get("hashes") or []
                if hs:
                    algo, _, hexv = str(hs[0]).partition(":")
                    if hexv:
                        hashes = ((algo, hexv),)
                yield Finding(
                    claim=ComponentClaim(
                        ctype="library",
                        name=nname,
                        version=ver,
                        purl=_pypi_purl(nname, ver),
                        ecosystem="pypi",
                        hashes=hashes,
                        attrs=(("dev", "true"),) if scope is Scope.DEV else (),
                    ),
                    evidence=(
                        ctx.evidence(
                            "lockfile-parse",
                            Tier.LOCKED,
                            entry,
                            span=find_span(text, f'"{name}"'),
                        ),
                    ),
                )


_DISTINFO_RE = re.compile(r"(^|/)([^/]+)-([^/-]+)\.(dist-info)/METADATA$")


class DistInfoCataloger(Cataloger):
    id = "python/dist-info"
    version = 1
    matchers = [Matcher(glob="*.dist-info/METADATA")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        headers = _parse_email_headers(text)
        name = headers.get("Name")
        version = headers.get("Version")
        if not name or not version:
            return
        nname = _norm_name(name)
        purl = _pypi_purl(nname, version)
        dist_dir = entry.path.rsplit("/", 1)[0]

        edges: list[EdgeClaim] = [
            EdgeClaim(kind=EdgeType.INSTANCE_OF, src=ref_file(entry.path), dst=ref_purl(purl))
        ]
        for req_line in headers.get("Requires-Dist", "").split("\x00"):
            req_line = req_line.strip()
            if not req_line:
                continue
            try:
                req = Requirement(req_line)
            except InvalidRequirement:
                continue
            if req.marker is not None and "extra" in str(req.marker):
                # extras not installed here are not dependencies of this
                # environment (and create phantom cycles like setuptools ⇄ pytest)
                continue
            edges.append(
                EdgeClaim(
                    kind=EdgeType.DEPENDS_ON,
                    src=ref_purl(purl),
                    dst=ref_family("pypi", _norm_name(req.name)),
                    direct=False,
                    requested=str(req.specifier) or None,
                    marker=str(req.marker) if req.marker else None,
                )
            )

        attrs: list[tuple[str, str]] = []
        installer = ctx.peek(f"{dist_dir}/INSTALLER")
        if installer:
            attrs.append(("installer", installer.decode("utf-8", "replace").strip()))
        direct_url = ctx.peek(f"{dist_dir}/direct_url.json")
        if direct_url:
            try:
                du = json.loads(direct_url)
                if du.get("url"):
                    attrs.append(("direct_url", str(du["url"])[:200]))
            except json.JSONDecodeError:
                pass
        record = ctx.peek(f"{dist_dir}/RECORD")
        if record:
            n_files = sum(1 for line in record.decode("utf-8", "replace").splitlines() if line)
            attrs.append(("installed_files", str(n_files)))

        yield Finding(
            claim=ComponentClaim(
                ctype="library",
                name=nname,
                version=version,
                purl=purl,
                ecosystem="pypi",
                licenses_declared=headers.get("License-Expression") or None,
                attrs=tuple(attrs),
            ),
            evidence=(
                ctx.evidence(
                    "installed-state",
                    Tier.INSTALLED,
                    entry,
                    span=(1, 2),
                    captured=f"Name: {name}\nVersion: {version}",
                ),
            ),
            edges=tuple(edges),
        )


def _parse_email_headers(text: str) -> dict[str, str]:
    """RFC822-style headers; repeated keys joined with NUL."""
    out: dict[str, str] = {}
    for line in text.split("\n\n", 1)[0].splitlines():
        if ":" not in line or line.startswith((" ", "\t")):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key in out:
            out[key] += "\x00" + value
        else:
            out[key] = value
    return out


register(RequirementsCataloger())
register(PyprojectCataloger())
register(SetupPyCataloger())
register(PoetryLockCataloger())
register(UvLockCataloger())
register(PipfileLockCataloger())
register(DistInfoCataloger())
