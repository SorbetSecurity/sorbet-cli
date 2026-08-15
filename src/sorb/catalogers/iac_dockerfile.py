"""Dockerfile analyzer + prediction cross-check.

Parses a Dockerfile as build provenance without building: full instruction
list, ``ARG``/``ENV`` substitution with defaults, the multi-stage graph
(``COPY --from`` edges), the ``FROM`` chain (base-image declarations), and
package-install commands inside ``RUN`` (apt/apk/yum/pip/npm command-line
parsing) → **predicted** declared-tier packages. A later image scan
corroborates or contradicts these; a contradiction is a drift finding
(Dockerfile-vs-image).
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.catalogers.common import ref_family, ref_project, ref_purl
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

_INSTR_RE = re.compile(r"^\s*(FROM|RUN|COPY|ADD|ARG|ENV|CMD|ENTRYPOINT|LABEL|EXPOSE|USER|WORKDIR)\b",
                       re.IGNORECASE)
_VAR_RE = re.compile(r"\$\{?(\w+)\}?")

# apt/apk/yum install → (package-manager, purl-type). The operand list stops at
# the next shell command so a second install in the same RUN is still found.
_OPERANDS = r"([^&|;]*)"
_APT_RE = re.compile(r"\b(?:apt-get|apt)\s+(?:-[\w=]+\s+)*install\b" + _OPERANDS)
_APK_RE = re.compile(r"\bapk\s+add\b" + _OPERANDS)
_YUM_RE = re.compile(r"\b(?:yum|dnf|microdnf)\s+(?:-[\w=]+\s+)*install\b" + _OPERANDS)
_PIP_RE = re.compile(r"\bpip3?\s+install\b" + _OPERANDS)
_NPM_RE = re.compile(r"\bnpm\s+(?:install|i|add)\b" + _OPERANDS)


class DockerfileCataloger(Cataloger):
    id = "iac/dockerfile"
    #: 2 — each predicted package cites the continuation line that names it,
    #: not the first line of the RUN instruction.
    version = 2
    matchers = [Matcher(basename="Dockerfile"), Matcher(basename="Dockerfile.*"),
                Matcher(basename="*.dockerfile")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        lines = text.splitlines()
        instructions = _logical_lines(text)
        proj_dir = entry.path.rsplit("/", 1)[0] if "/" in entry.path else "."
        proj_ref = ref_project(proj_dir)
        args: dict[str, str] = {}
        stages: dict[str, int] = {}
        stage_idx = 0

        for lineno, end_lineno, instr in instructions:
            m = _INSTR_RE.match(instr)
            if not m:
                continue
            verb = m.group(1).upper()
            rest = instr[m.end():].strip()
            rest = _subst(rest, args)

            if verb == "ARG":
                key, _, default = rest.partition("=")
                args[key.strip()] = default.strip()
            elif verb == "ENV":
                for k, v in _parse_env(rest):
                    args[k] = v
            elif verb == "FROM":
                yield from self._from(ctx, entry, rest, lineno, stages, stage_idx, proj_ref)
                stage_idx += 1
                as_m = re.search(r"\bAS\s+(\S+)", rest, re.IGNORECASE)
                if as_m:
                    stages[as_m.group(1)] = stage_idx - 1
            elif verb == "COPY" and "--from=" in rest:
                src_m = re.search(r"--from=(\S+)", rest)
                if src_m:
                    yield self._copy_from(ctx, entry, src_m.group(1), lineno)
            elif verb == "RUN":
                yield from self._run_packages(
                    ctx, entry, rest, lineno, proj_ref, lines=lines, end_lineno=end_lineno
                )

    def _from(self, ctx: CatalogerContext, entry: Entry, rest: str, lineno: int,
              stages: dict[str, int], stage_idx: int, proj_ref: str) -> Iterable[Finding]:
        image = rest.split()[0] if rest.split() else ""
        if image in stages or "<unresolved" in image or "$" in image:
            return
        ref = parse_image_reference(image)
        if ref is None:
            return
        purl = ref.purl()
        annotations: tuple[Annotation, ...] = ()
        if ref.floating:
            annotations = (
                Annotation(code="unpinned-image", subject=ref_purl(purl),
                           detail=f"base image {ref.raw} uses a floating tag (not digest-pinned)"),
            )
        yield Finding(
            claim=ComponentClaim(
                ctype="application", name=ref.name(), version=ref.digest or ref.tag,
                purl=purl, ecosystem="oci",
                attrs=(("base-image", "true"), ("image-ref", ref.raw), ("stage", str(stage_idx))),
            ),
            evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                   span=(lineno, lineno), captured=f"FROM {ref.raw}"),),
            edges=(EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref, dst=ref_purl(purl),
                             scope=Scope.BUILD, direct=True),),
            annotations=annotations,
        )

    def _copy_from(self, ctx: CatalogerContext, entry: Entry, source: str, lineno: int) -> Finding:
        return Finding(
            claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:copy-from-{source}"),
            evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                   span=(lineno, lineno), captured=f"COPY --from={source}"),),
            annotations=(
                Annotation(code="multistage-copy", subject=ref_project(entry.path.rsplit("/", 1)[0] if "/" in entry.path else "."),
                           detail=f"COPY --from={source}: build-stage provenance for files appearing "
                           "in the final image without a package manager"),
            ),
        )

    def _run_packages(self, ctx: CatalogerContext, entry: Entry, command: str,
                      lineno: int, proj_ref: str, *, lines: list[str],
                      end_lineno: int) -> Iterable[Finding]:
        for parser, purl_type, distro in (
            (_APT_RE, "deb", "debian"), (_APK_RE, "apk", "alpine"), (_YUM_RE, "rpm", "rhel"),
            (_PIP_RE, "pypi", None), (_NPM_RE, "npm", None),
        ):
            seen: set[tuple[str, str | None]] = set()
            installs = [
                pkg
                for m in parser.finditer(command)  # one RUN may install more than once
                for pkg in _parse_install_args(m.group(1), purl_type)
                if pkg not in seen and not seen.add(pkg)  # type: ignore[func-returns-value]
            ]
            for pkg, version in installs:
                purl = make_purl(purl_type, pkg, version, namespace=distro)
                pkg_line = _declaring_line(lines, lineno, end_lineno, pkg)
                yield Finding(
                    claim=ComponentClaim(
                        ctype="os-package" if distro else "library", name=pkg, version=version,
                        purl=purl if version else None, ecosystem=purl_type, namespace=distro,
                        attrs=(("predicted", "dockerfile-RUN"),),
                    ),
                    evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                           span=(pkg_line, pkg_line),
                                           captured=f"RUN … install {pkg} {version or ''}".strip()),),
                    edges=(EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref,
                                     dst=ref_purl(purl) if version else ref_family(purl_type, pkg),
                                     scope=Scope.RUNTIME, direct=False),),
                    annotations=(
                        Annotation(
                            code="dockerfile-predicted",
                            subject=ref_purl(purl) if version else f"claim:{purl_type}/{pkg}@",
                            detail=f"{pkg} predicted from a Dockerfile RUN; the image scan "
                            "corroborates or contradicts this (drift on mismatch)",
                        ),
                    ),
                )


def _logical_lines(text: str) -> list[tuple[int, int, str]]:
    """Continuation-joined instructions as (first line, last line, text).

    The last line matters: a `RUN apt-get install` spanning eight backslash
    continuations declares each package on its own physical line, and citing
    the instruction's first line sends a reader to the wrong one.
    """
    out: list[tuple[int, int, str]] = []
    pending = ""
    start = 0
    lineno = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if not pending:
                continue
        if pending:
            pending += " " + stripped.rstrip("\\").strip()
        else:
            start = lineno
            pending = stripped.rstrip("\\").strip() if stripped.endswith("\\") else stripped
        if stripped.endswith("\\"):
            continue
        out.append((start, lineno, pending))
        pending = ""
    if pending:
        out.append((start, lineno, pending))
    return out


def _declaring_line(lines: list[str], start: int, end: int, token: str) -> int:
    """The physical line in [start, end] that names `token`, else `start`.

    Package names carry `-`, `.` and `+`, so the boundary has to exclude those
    or `python3` would match inside `python3-pip`.
    """
    pattern = re.compile(rf"(?<![\w.+-]){re.escape(token)}(?![\w.+-])")
    for n in range(max(start, 1), min(end, len(lines)) + 1):
        if pattern.search(lines[n - 1]):
            return n
    return start


def _subst(text: str, args: dict[str, str]) -> str:
    return _VAR_RE.sub(lambda m: args.get(m.group(1), m.group(0)), text)


def _parse_env(rest: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if "=" in rest:
        try:
            for token in shlex.split(rest):
                if "=" in token:
                    k, _, v = token.partition("=")
                    out.append((k, v))
        except ValueError:
            pass
    else:
        parts = rest.split(None, 1)
        if len(parts) == 2:
            out.append((parts[0], parts[1].strip()))
    return out


#: A RUN body is one shell script, and a Dockerfile's line continuations join
#: it into a single logical line. Operands stop at the first of these, or
#: `apt-get install a && mv x y` would report `mv` and `y` as packages.
_SHELL_BREAK = frozenset({"&&", "||", "&", ";", "|", ">", ">>", "<", "<<"})
#: the first PEP 508 comparison operator ends a requirement's name
_PEP508_NAME_RE = re.compile(r"[=<>!~;\s]")


def _parse_install_args(args: str, purl_type: str) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    try:
        tokens = shlex.split(args)
    except ValueError:
        tokens = args.split()
    for tok in tokens:
        if tok in _SHELL_BREAK or tok.endswith(";"):
            break
        if tok.startswith("/") or tok.startswith("./"):
            continue  # a path operand, not a package name
        if tok.startswith("-") or tok in ("\\", "install", "add"):
            continue
        if tok in ("--no-install-recommends", "-y", "--yes"):
            continue
        # apt: pkg=version ; apk: pkg=version ; pip: pkg==version ; npm: pkg@version
        name, version = tok, None
        if purl_type == "pypi":
            # only `==` pins; every other PEP 508 operator states a range, so
            # the name is recorded without inventing a version for it
            name = _PEP508_NAME_RE.split(tok, 1)[0].partition("[")[0]
            if "==" in tok:
                version = tok.partition("==")[2] or None
        elif purl_type == "npm" and "@" in tok and not tok.startswith("@"):
            name, _, version = tok.rpartition("@")
        elif "=" in tok:
            name, _, version = tok.partition("=")
        if re.match(r"^[\w.@/\-]+$", name) and name not in ("apt", "apk", "yum", "dnf", "pip", "pip3", "npm"):
            out.append((name, version or None))
    return out


register(DockerfileCataloger())
