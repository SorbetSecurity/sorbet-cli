"""Go catalogers.

- ``go/go-mod`` — declared tier; ``replace``/``exclude`` honored (both sides
  emitted with RESOLVED_FROM); ``go.work`` workspaces.
- ``go/go-sum`` — locked tier; ``h1:`` dirhash captured as digest. go.sum is a
  superset of the selected build list, so sum-only modules carry an explicit
  annotation instead of silent emission.
- ``go/binary`` — embedded buildinfo: exact module list at installed tier.

A module path keeps its major-version suffix in the purl
(``pkg:golang/github.com/cenkalti/backoff/v4@v4.3.0``). Some tools move the
suffix into the purl subpath instead, but ``.../backoff`` and
``.../backoff/v4`` are different modules to Go, and the Go vulnerability
database and OSV both key on the full path.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterable

from sorb.catalogers.base import (
    Cataloger,
    CatalogerContext,
    Matcher,
    find_span,
    register,
)
from sorb.catalogers.common import dirname_of, ref_family, ref_file, ref_project, ref_purl
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


def _go_purl(path: str, version: str | None = None) -> str:
    namespace, _, name = path.rpartition("/")
    return make_purl("golang", name or path, version, namespace=namespace or None)


_REQ_RE = re.compile(r"^\s*(?:require\s+)?([\w.\-/~]+)\s+(v[\w.\-+]+)(\s*//\s*indirect)?")
_REPLACE_RE = re.compile(
    r"^\s*(?:replace\s+)?([\w.\-/~]+)(?:\s+(v[\w.\-+]+))?\s*=>\s*([\w.\-/~]+)(?:\s+(v[\w.\-+]+))?"
)


class GoModCataloger(Cataloger):
    id = "go/go-mod"
    version = 1
    matchers = [Matcher(basename="go.mod")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        module_path = None
        requires: list[tuple[int, str, str, bool]] = []  # line, path, version, indirect
        replaces: list[tuple[str, str | None, str, str | None]] = []
        excludes: set[tuple[str, str]] = set()
        in_block: str | None = None
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("//", 1)[0].rstrip() if "// indirect" not in raw else raw.rstrip()
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("module "):
                module_path = stripped.split(None, 1)[1]
                continue
            if stripped in ("require (", "replace (", "exclude ("):
                in_block = stripped.split()[0]
                continue
            if stripped == ")":
                in_block = None
                continue
            target = in_block or (
                stripped.split()[0] if stripped.split()[0] in ("require", "replace", "exclude") else None
            )
            if target == "require":
                m = _REQ_RE.match(raw if in_block else stripped)
                if m:
                    requires.append((lineno, m.group(1), m.group(2), bool(m.group(3))))
            elif target == "replace":
                m = _REPLACE_RE.match(stripped)
                if m:
                    replaces.append((m.group(1), m.group(2), m.group(3), m.group(4)))
            elif target == "exclude":
                parts = stripped.replace("exclude", "").split()
                if len(parts) >= 2:
                    excludes.add((parts[0], parts[1]))

        if module_path:
            ctx.declare_project(proj_dir, module_path, "go-module")
        proj_ref = ref_project(proj_dir)
        replace_map = {orig: (new, newv) for orig, _origv, new, newv in replaces}

        for lineno, path, ver, indirect in requires:
            if (path, ver) in excludes:
                continue
            replaced = replace_map.get(path)
            purl = _go_purl(path, ver)
            claim = ComponentClaim(
                ctype="library",
                name=path,
                version=ver,
                purl=purl,
                ecosystem="golang",
                attrs=(("indirect", "true"),) if indirect else (),
            )
            edges = [
                EdgeClaim(
                    kind=EdgeType.DEPENDS_ON,
                    src=proj_ref,
                    dst=ref_purl(purl),
                    scope=Scope.RUNTIME,
                    direct=not indirect,
                )
            ]
            findings = [
                Finding(
                    claim=claim,
                    evidence=(
                        ctx.evidence(
                            "manifest-parse",
                            Tier.DECLARED,
                            entry,
                            span=(lineno, lineno),
                            captured=f"{path} {ver}",
                        ),
                    ),
                    edges=tuple(edges),
                )
            ]
            if replaced and _is_local_path(replaced[0]):
                # `k8s.io/api => ./staging/src/k8s.io/api` builds the module from
                # a directory in this tree. There is no published package to
                # name, so record where it came from instead of minting a purl
                # for a filesystem path.
                findings[0] = Finding(
                    claim=claim,
                    evidence=findings[0].evidence,
                    edges=findings[0].edges,
                    annotations=(
                        Annotation(
                            code="replaced-by-local-path",
                            subject=ref_purl(purl),
                            detail=f"built from {replaced[0]} in this tree, not from a registry",
                        ),
                    ),
                )
            elif replaced:
                new_path, new_ver = replaced
                new_purl = _go_purl(new_path, new_ver or ver)
                findings.append(
                    Finding(
                        claim=ComponentClaim(
                            ctype="library",
                            name=new_path,
                            version=new_ver or ver,
                            purl=new_purl,
                            ecosystem="golang",
                            attrs=(("replaces", path),),
                        ),
                        evidence=(
                            ctx.evidence(
                                "manifest-parse",
                                Tier.DECLARED,
                                entry,
                                span=find_span(text, f"{path} "),
                                captured=f"replace {path} => {new_path} {new_ver or ''}".strip(),
                            ),
                        ),
                        edges=(
                            EdgeClaim(
                                kind=EdgeType.RESOLVED_FROM,
                                src=ref_purl(new_purl),
                                dst=ref_purl(purl),
                            ),
                        ),
                    )
                )
            yield from findings


def _is_local_path(target: str) -> bool:
    """A `replace` target that names a directory rather than a module."""
    return target.startswith((".", "/")) or (len(target) > 1 and target[1] == ":")


_GOSUM_RE = re.compile(r"^([\w.\-/~]+)\s+(v[\w.\-+]+?)(/go\.mod)?\s+h1:(\S+)$")


class GoSumCataloger(Cataloger):
    id = "go/go-sum"
    version = 1
    matchers = [Matcher(basename="go.sum")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        gomod_raw = ctx.peek("go.mod" if proj_dir == "." else f"{proj_dir}/go.mod")
        in_gomod: set[str] = set()
        if gomod_raw:
            for m in _REQ_RE.finditer(gomod_raw.decode("utf-8", errors="replace")):
                in_gomod.add(m.group(1))
        seen: set[tuple[str, str]] = set()
        for lineno, line in enumerate(text.splitlines(), start=1):
            sm = _GOSUM_RE.match(line.strip())
            if not sm or sm.group(3):  # skip /go.mod hash lines
                continue
            path, ver, h1 = sm.group(1), sm.group(2), sm.group(4)
            if (path, ver) in seen:
                continue
            seen.add((path, ver))
            try:
                hex_digest = base64.b64decode(h1).hex()
            except (ValueError, TypeError):
                hex_digest = ""
            purl = _go_purl(path, ver)
            annotations: tuple[Annotation, ...] = ()
            if path not in in_gomod:
                annotations = (
                    Annotation(
                        code="gosum-superset",
                        subject=ref_purl(purl),
                        detail="present in go.sum but not required by go.mod; may not be in the "
                        "selected build list",
                    ),
                )
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=path,
                    version=ver,
                    purl=purl,
                    ecosystem="golang",
                    hashes=(("gomod-h1", hex_digest),) if hex_digest else (),
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse",
                        Tier.LOCKED,
                        entry,
                        span=(lineno, lineno),
                        captured=line.strip()[:200],
                    ),
                ),
                annotations=annotations,
            )


_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe")
_PE_MAGIC = b"MZ"


class GoBinaryCataloger(Cataloger):
    id = "go/binary"
    version = 1
    matchers = [
        Matcher(magic=_ELF_MAGIC),
        Matcher(magic=_PE_MAGIC),
        *[Matcher(magic=m) for m in dict.fromkeys(_MACHO_MAGICS)],
    ]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        from sorb.binary.embedded.go_buildinfo import parse_buildinfo

        info = parse_buildinfo(blob)
        if info is None:
            return
        # The Go toolchain itself
        yield Finding(
            claim=ComponentClaim(
                ctype="build-tool",
                name="go",
                version=info.go_version.removeprefix("go"),
                purl=make_purl("golang", "go", info.go_version.removeprefix("go")),
                ecosystem="golang",
            ),
            evidence=(
                ctx.evidence(
                    "binary-buildinfo",
                    Tier.INSTALLED,
                    entry,
                    captured=f"go version {info.go_version}",
                ),
            ),
        )
        main_purl = None
        if info.main_module and info.main_module.version not in (None, "", "(devel)"):
            main_purl = _go_purl(info.main_module.path, info.main_module.version)
            yield Finding(
                claim=ComponentClaim(
                    ctype="application",
                    name=info.main_module.path,
                    version=info.main_module.version,
                    purl=main_purl,
                    ecosystem="golang",
                ),
                evidence=(
                    ctx.evidence("binary-buildinfo", Tier.INSTALLED, entry),
                ),
                edges=(
                    EdgeClaim(
                        kind=EdgeType.INSTANCE_OF, src=ref_file(entry.path), dst=ref_purl(main_purl)
                    ),
                ),
            )
        for dep in info.deps:
            actual = dep.replaced_by or dep
            purl = _go_purl(actual.path, actual.version)
            hashes: tuple[tuple[str, str], ...] = ()
            if actual.sum and actual.sum.startswith("h1:"):
                try:
                    hashes = (("gomod-h1", base64.b64decode(actual.sum[3:]).hex()),)
                except (ValueError, TypeError):
                    pass
            edges: list[EdgeClaim] = []
            if main_purl:
                edges.append(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=ref_purl(main_purl),
                        dst=ref_purl(purl),
                        scope=Scope.RUNTIME,
                        direct=False,
                    )
                )
            if dep.replaced_by:
                edges.append(
                    EdgeClaim(
                        kind=EdgeType.RESOLVED_FROM,
                        src=ref_purl(purl),
                        dst=ref_family("golang", dep.path),
                    )
                )
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=actual.path,
                    version=actual.version,
                    purl=purl,
                    ecosystem="golang",
                    hashes=hashes,
                ),
                evidence=(
                    ctx.evidence(
                        "binary-buildinfo",
                        Tier.INSTALLED,
                        entry,
                        captured=f"dep\t{actual.path}\t{actual.version}",
                    ),
                ),
                edges=tuple(edges),
            )


register(GoModCataloger())
register(GoSumCataloger())
register(GoBinaryCataloger())
