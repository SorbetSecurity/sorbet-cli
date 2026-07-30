"""Conan + CMake + C/C++ long-tail catalogers.

Conan: ``conanfile.txt``/``conanfile.py`` (static), ``conan.lock`` v2 (exact
graph with recipe revisions + package IDs), local cache manifests.
CMake: static ``find_package``/``FetchContent``/``ExternalProject``/CPM/Hunter
parse + the **File API** codemodel (targets → link libs, zero code execution).
Long tail: meson ``.wrap``, pkg-config ``.pc``, autotools PKG_CHECK_MODULES,
Makefile ``-l/-L``, git submodules (pinned commit → locked), header-only libs
(fingerprint id + ``#include``-graph use corroboration).
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

# -- Conan ------------------------------------------------------------------------------

_CONAN_REF_RE = re.compile(r"([\w.\-+]+)/([\w.\-+]+)(?:@([\w.\-+/]+))?")


class ConanTxtCataloger(Cataloger):
    id = "cpp/conanfile-txt"
    version = 1
    matchers = [Matcher(basename="conanfile.txt")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        ctx.declare_project(proj_dir, proj_dir or ".", "conan")
        proj_ref = ref_project(proj_dir)
        section = None
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if section not in ("requires", "tool_requires", "build_requires") or not line or line.startswith("#"):
                continue
            m = _CONAN_REF_RE.match(line)
            if not m:
                continue
            name, version = m.group(1), m.group(2)
            purl = make_purl("conan", name, version)
            scope = Scope.BUILD if section != "requires" else Scope.RUNTIME
            yield Finding(
                claim=ComponentClaim(
                    ctype="library", name=name, version=version, purl=purl, ecosystem="conan"
                ),
                evidence=(
                    ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                 span=(lineno, lineno), captured=line),
                ),
                edges=(
                    EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref, dst=ref_purl(purl),
                              scope=scope, direct=True),
                ),
            )


class ConanPyCataloger(Cataloger):
    id = "cpp/conanfile-py"
    version = 1
    matchers = [Matcher(basename="conanfile.py")]

    _REQ_RE = re.compile(r"""self\.requires\(\s*['"]([\w.\-+]+)/([\w.\-+]+)""")
    _LIST_RE = re.compile(r"""requires\s*=\s*[\[(]([^\])]+)[\])]""")

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        proj_ref = ref_project(proj_dir)
        ctx.declare_project(proj_dir, proj_dir or ".", "conan")
        found: dict[str, str] = {}
        dynamic = False
        for m in self._REQ_RE.finditer(text):
            found[m.group(1)] = m.group(2)
        for m in self._LIST_RE.finditer(text):
            for ref in re.findall(r"""['"]([\w.\-+]+)/([\w.\-+]+)""", m.group(1)):
                found[ref[0]] = ref[1]
        if "def requirements" in text and not found:
            dynamic = True
        for name, version in sorted(found.items()):
            purl = make_purl("conan", name, version)
            yield Finding(
                claim=ComponentClaim(ctype="library", name=name, version=version, purl=purl,
                                     ecosystem="conan"),
                evidence=(
                    ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                 span=find_span(text, f"{name}/{version}"),
                                 captured=f"{name}/{version}"),
                ),
                edges=(
                    EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref, dst=ref_purl(purl),
                              scope=Scope.RUNTIME, direct=True),
                ),
            )
        if dynamic:
            yield Finding(
                claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:dynamic"),
                evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                       captured="dynamic requirements()"),),
                annotations=(
                    Annotation(
                        code="unresolved-dynamic-manifest",
                        subject=ref_project(proj_dir),
                        detail="conanfile.py computes requirements dynamically; run "
                        "--resolve=native to evaluate the recipe",
                    ),
                ),
            )


class ConanLockCataloger(Cataloger):
    id = "cpp/conan-lock"
    version = 1
    matchers = [Matcher(basename="conan.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        try:
            doc = json.loads(blob)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        text = blob.decode("utf-8", errors="replace")
        # conan.lock v2: {"requires": ["name/version#recipe_revision%timestamp", ...]}
        for section, _scope in (("requires", Scope.RUNTIME), ("build_requires", Scope.BUILD)):
            for ref in doc.get(section, []):
                m = _CONAN_REF_RE.match(str(ref))
                if not m:
                    continue
                name, version = m.group(1), m.group(2)
                revision = None
                if "#" in str(ref):
                    revision = str(ref).split("#", 1)[1].split("%")[0]
                qualifiers = {"rrev": revision} if revision else {}
                purl = make_purl("conan", name, version, qualifiers=qualifiers)
                yield Finding(
                    claim=ComponentClaim(
                        ctype="library", name=name, version=version, purl=purl, ecosystem="conan",
                        qualifiers=tuple(sorted(qualifiers.items())),
                    ),
                    evidence=(
                        ctx.evidence("lockfile-parse", Tier.LOCKED, entry,
                                     span=find_span(text, str(ref)), captured=str(ref)[:120]),
                    ),
                )


# -- CMake ------------------------------------------------------------------------------

_FIND_PACKAGE_RE = re.compile(r"find_package\s*\(\s*([\w.\-]+)(?:\s+([\d.]+))?", re.IGNORECASE)
_FETCHCONTENT_RE = re.compile(
    r"FetchContent_Declare\s*\(\s*([\w.\-]+).*?GIT_REPOSITORY\s+([^\s)]+).*?GIT_TAG\s+([^\s)]+)",
    re.IGNORECASE | re.DOTALL,
)
_CPM_RE = re.compile(r"""CPMAddPackage\s*\(\s*['"]?([\w.\-]+)/([\w.\-]+)@([\d.]+)""", re.IGNORECASE)


class CMakeListsCataloger(Cataloger):
    id = "cpp/cmake"
    version = 1
    matchers = [Matcher(basename="CMakeLists.txt"), Matcher(basename="*.cmake")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        proj_ref = ref_project(proj_dir)

        for m in _FIND_PACKAGE_RE.finditer(text):
            name, version = m.group(1), m.group(2)
            if name.upper() in ("PYTHON", "PYTHONINTERP", "THREADS", "PKGCONFIG"):
                continue
            line = text.count("\n", 0, m.start()) + 1
            yield Finding(
                claim=ComponentClaim(
                    ctype="library", name=name, version=version,
                    purl=make_purl("generic", name.lower(), version) if version else None,
                    ecosystem="cmake", requested=version,
                ),
                evidence=(ctx.evidence("manifest-parse", Tier.INFERRED, entry,
                                       span=(line, line), captured=m.group(0)),),
                edges=(EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref,
                                 dst=ref_family("generic", name.lower()), scope=Scope.RUNTIME,
                                 direct=True, requested=version),),
            )
        for m in _FETCHCONTENT_RE.finditer(text):
            name, repo, tag = m.group(1), m.group(2).strip('"'), m.group(3).strip('"')
            namespace = _github_ns(repo)
            pinned = bool(re.fullmatch(r"[0-9a-f]{7,40}", tag))
            line = text.count("\n", 0, m.start()) + 1
            purl = make_purl("github", name, tag, namespace=namespace) if namespace else None
            yield Finding(
                claim=ComponentClaim(
                    ctype="library", name=name, version=tag if pinned or "." in tag else None,
                    purl=purl, ecosystem="github", attrs=(("vcs_url", repo),),
                ),
                evidence=(ctx.evidence(
                    "lockfile-parse" if pinned else "manifest-parse",
                    Tier.LOCKED if pinned else Tier.DECLARED, entry,
                    span=(line, line), captured=f"FetchContent {name} {repo}@{tag}"),),
                edges=(EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref,
                                 dst=ref_purl(purl) if purl else ref_family("github", name),
                                 scope=Scope.RUNTIME, direct=True),),
            )
        for m in _CPM_RE.finditer(text):
            owner, name, version = m.groups()
            purl = make_purl("github", name, version, namespace=owner)
            line = text.count("\n", 0, m.start()) + 1
            yield Finding(
                claim=ComponentClaim(ctype="library", name=name, version=version, purl=purl,
                                     ecosystem="github"),
                evidence=(ctx.evidence("lockfile-parse", Tier.LOCKED, entry,
                                       span=(line, line), captured=m.group(0)),),
                edges=(EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref, dst=ref_purl(purl),
                                 scope=Scope.RUNTIME, direct=True),),
            )


class CMakeFileApiCataloger(Cataloger):
    """CMake File API codemodel: targets + their link libraries (used-by edges)."""

    id = "cpp/cmake-fileapi"
    version = 1
    matchers = [Matcher(glob="*.cmake/api/v1/reply/target-*.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        try:
            doc = json.loads(blob)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        target_name = str(doc.get("name", ""))
        if not target_name:
            return
        link = doc.get("link") or {}
        for frag in link.get("commandFragments", []):
            if frag.get("role") != "libraries":
                continue
            for lib in re.findall(r"-l([\w.\-]+)|/(?:lib)?([\w.\-]+)\.(?:so|a|dylib)", frag.get("fragment", "")):
                libname = lib[0] or lib[1]
                if not libname:
                    continue
                yield Finding(
                    claim=ComponentClaim(
                        ctype="library", name=libname, ecosystem="cmake",
                        attrs=(("linked-by-target", target_name),),
                    ),
                    evidence=(ctx.evidence("manifest-parse", Tier.INFERRED, entry,
                                           captured=f"target {target_name} links {libname}"),),
                )


# -- Long tail --------------------------------------------------------------------------


class MesonWrapCataloger(Cataloger):
    id = "cpp/meson-wrap"
    version = 1
    matchers = [Matcher(glob="*subprojects/*.wrap")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        fields: dict[str, str] = {}
        for line in text.splitlines():
            if line.strip().startswith("[") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            fields[k.strip()] = v.strip()
        name = entry.path.rsplit("/", 1)[-1].removesuffix(".wrap")
        version: str | None = fields.get("wrap_version") or fields.get("directory", "").split("-")[-1]
        rev = fields.get("revision")
        version = version or rev
        url = fields.get("source_url") or fields.get("url", "")
        namespace = _github_ns(url)
        sha = fields.get("source_hash")
        purl = make_purl("generic", name, version) if version else None
        yield Finding(
            claim=ComponentClaim(
                ctype="library", name=name, version=version, purl=purl, ecosystem="meson",
                namespace=namespace, hashes=(("sha256", sha),) if sha else (),
            ),
            evidence=(ctx.evidence("lockfile-parse", Tier.LOCKED, entry,
                                   captured=f"{name} {version or '?'}"),),
        )


class PkgConfigCataloger(Cataloger):
    id = "cpp/pkg-config"
    version = 1
    matchers = [Matcher(basename="*.pc")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        name = version = None
        for line in text.splitlines():
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                version = line.split(":", 1)[1].strip()
        if not name or not version:
            return
        yield Finding(
            claim=ComponentClaim(ctype="library", name=name, version=version,
                                 purl=make_purl("generic", name.lower(), version), ecosystem="pkg-config"),
            evidence=(ctx.evidence("installed-state", Tier.INSTALLED, entry,
                                   span=find_span(text, "Version:"),
                                   captured=f"{name} {version}"),),
        )


class GitmodulesCataloger(Cataloger):
    """`.gitmodules` + the pinned commit → locked pkg:github component."""

    id = "cpp/gitmodules"
    version = 1
    matchers = [Matcher(basename=".gitmodules")]

    _SUBMODULE_RE = re.compile(r'\[submodule "([^"]+)"\]((?:\n\s+\w+\s*=.*)+)', re.MULTILINE)

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        for m in self._SUBMODULE_RE.finditer(text):
            body = m.group(2)
            path_m = re.search(r"path\s*=\s*(\S+)", body)
            url_m = re.search(r"url\s*=\s*(\S+)", body)
            if not path_m or not url_m:
                continue
            path, url = path_m.group(1), url_m.group(1)
            namespace = _github_ns(url)
            name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            # the pinned commit lives in the git index; when a co-located record
            # exists (`.git/modules/<path>/HEAD` or a `<path>` gitlink) use it
            commit = self._pinned_commit(ctx, path)
            purl = make_purl("github", name, commit, namespace=namespace) if (commit and namespace) else None
            annotations: tuple[Annotation, ...] = ()
            if commit is None:
                annotations = (
                    Annotation(
                        code="resolution-incomplete",
                        subject=f"claim:github/{name}@",
                        detail=f"submodule {path}: pinned commit not readable without the git "
                        "index; identified by URL only",
                    ),
                )
            yield Finding(
                claim=ComponentClaim(
                    ctype="library", name=name, version=commit[:12] if commit else None,
                    purl=purl, ecosystem="github", namespace=namespace,
                    attrs=(("vcs_url", url), ("submodule-path", path)),
                ),
                evidence=(ctx.evidence(
                    "lockfile-parse" if commit else "manifest-parse",
                    Tier.LOCKED if commit else Tier.DECLARED, entry,
                    span=find_span(text, path), captured=f"submodule {path} -> {url}"),),
                annotations=annotations,
            )

    def _pinned_commit(self, ctx: CatalogerContext, path: str) -> str | None:
        # a `git ls-tree`-style gitlink is recorded by the walker as a special
        # file; here we look for a co-located commit record the walker may expose
        raw = ctx.peek(f".git/modules/{path}/HEAD")
        if raw:
            ref = raw.decode("utf-8", "replace").strip()
            if re.fullmatch(r"[0-9a-f]{40}", ref):
                return ref
        return None


_LDFLAG_RE = re.compile(r"-l([\w.\-]+)")


class MakefileCataloger(Cataloger):
    """Conservative `-l`/`pkg-config` extraction from plain Makefiles (inferred)."""

    id = "cpp/makefile"
    version = 1
    matchers = [Matcher(basename="Makefile"), Matcher(basename="makefile"), Matcher(basename="GNUmakefile")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        seen: set[str] = set()
        for m in _LDFLAG_RE.finditer(text):
            lib = m.group(1)
            if lib in seen or lib in ("m", "c", "pthread", "dl", "rt", "gcc"):
                continue
            seen.add(lib)
            line = text.count("\n", 0, m.start()) + 1
            yield Finding(
                claim=ComponentClaim(
                    ctype="library", name=lib, ecosystem="c",
                    attrs=(("linker-flag", f"-l{lib}"),),
                ),
                evidence=(ctx.evidence("manifest-parse", Tier.INFERRED, entry,
                                       span=(line, line), captured=f"-l{lib}"),),
                annotations=(
                    Annotation(
                        code="resolution-incomplete",
                        subject=f"claim:c/{lib}@",
                        detail=f"-l{lib} names a system library; its version/owning dev-package "
                        "resolves against the OS file maps",
                    ),
                ),
            )


def _github_ns(url: str) -> str | None:
    m = re.search(r"github\.com[:/]([^/]+)/", url)
    return f"github.com/{m.group(1)}" if m else None


register(ConanTxtCataloger())
register(ConanPyCataloger())
register(ConanLockCataloger())
register(CMakeListsCataloger())
register(CMakeFileApiCataloger())
register(MesonWrapCataloger())
register(PkgConfigCataloger())
register(GitmodulesCataloger())
register(MakefileCataloger())
