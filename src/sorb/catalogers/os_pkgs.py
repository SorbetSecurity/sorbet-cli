"""OS package database catalogers: dpkg, apk, pacman.

rpm (Berkeley DB / sqlite / ndb header decode) lives separately in
`sorb.catalogers.os_rpm`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.catalogers.common import ref_family, ref_purl
from sorb.ident import make_purl
from sorb.model import ComponentClaim, EdgeClaim, EdgeType, Finding, Scope, Tier
from sorb.source.base import Entry


def _os_release_id(ctx: CatalogerContext, entry: Entry) -> str | None:
    """Find the distro ID from etc/os-release relative to the DB's rootfs."""
    root = entry.path
    for marker in (
        "var/lib/dpkg",
        "lib/apk",
        "var/lib/pacman",
        "usr/lib/apk",
        "var/lib/rpm",
        "usr/lib/sysimage/rpm",
    ):
        if marker in root:
            prefix = root.split(marker, 1)[0]
            for candidate in (f"{prefix}etc/os-release", f"{prefix}usr/lib/os-release"):
                raw = ctx.peek(candidate.lstrip("/"))
                if raw:
                    for line in raw.decode("utf-8", "replace").splitlines():
                        if line.startswith("ID="):
                            return line[3:].strip().strip('"')
    return None


def _parse_stanzas(text: str) -> Iterable[tuple[int, dict[str, str]]]:
    """RFC822-ish stanza parser; yields (start_line, fields)."""
    fields: dict[str, str] = {}
    start = 1
    last_key: str | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            if fields:
                yield (start, fields)
            fields = {}
            last_key = None
            start = lineno + 1
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


_DEP_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][\w.+-]*)")


class DpkgCataloger(Cataloger):
    id = "os/dpkg"
    version = 1
    matchers = [Matcher(glob="*var/lib/dpkg/status"), Matcher(glob="*var/lib/dpkg/status.d/*")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        distro = _os_release_id(ctx, entry) or "debian"
        for start, st in _parse_stanzas(text):
            name = st.get("Package")
            version = st.get("Version")
            if not name or not version:
                continue
            status = st.get("Status", "install ok installed")
            if "installed" not in status:
                continue
            arch = st.get("Architecture", "")
            source_field = st.get("Source", "")
            source_pkg = source_field.split(" ", 1)[0] if source_field else name
            qualifiers = {"arch": arch} if arch else {}
            if distro:
                qualifiers["distro"] = distro
            purl = make_purl("deb", name, version, namespace=distro, qualifiers=qualifiers)
            edges: list[EdgeClaim] = []
            for dep_field in ("Depends", "Pre-Depends"):
                for alt in (st.get(dep_field) or "").split(","):
                    # first alternative of each "a | b" group
                    m = _DEP_NAME_RE.match(alt.split("|", 1)[0])
                    if m:
                        edges.append(
                            EdgeClaim(
                                kind=EdgeType.DEPENDS_ON,
                                src=ref_purl(purl),
                                dst=ref_family("deb", m.group(1)),
                                scope=Scope.RUNTIME,
                                direct=False,
                            )
                        )
            n_lines = len([k for k in st])
            yield Finding(
                claim=ComponentClaim(
                    ctype="os-package",
                    name=name,
                    version=version,
                    purl=purl,
                    ecosystem="deb",
                    namespace=distro,
                    qualifiers=tuple(sorted(qualifiers.items())),
                    licenses_declared=None,
                    attrs=(("source-package", source_pkg),),
                ),
                evidence=(
                    ctx.evidence(
                        "os-package-db",
                        Tier.INSTALLED,
                        entry,
                        span=(start, start + n_lines),
                        captured=f"Package: {name}\nVersion: {version}",
                    ),
                ),
                edges=tuple(edges),
            )


class ApkCataloger(Cataloger):
    id = "os/apk"
    version = 1
    matchers = [Matcher(glob="*lib/apk/db/installed")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        distro = _os_release_id(ctx, entry) or "alpine"
        current: dict[str, str] = {}
        start = 1
        for lineno, line in enumerate(text.splitlines() + [""], start=1):
            if not line.strip():
                if current.get("P") and current.get("V"):
                    yield self._emit(ctx, entry, current, distro, start, lineno)
                current = {}
                start = lineno + 1
                continue
            key, sep, value = line.partition(":")
            if sep and len(key) == 1:
                current[key] = value.strip()

    def _emit(
        self,
        ctx: CatalogerContext,
        entry: Entry,
        st: dict[str, str],
        distro: str,
        start: int,
        end: int,
    ) -> Finding:
        name, version = st["P"], st["V"]
        arch = st.get("A", "")
        qualifiers = {"arch": arch} if arch else {}
        qualifiers["distro"] = distro
        purl = make_purl("apk", name, version, namespace=distro, qualifiers=qualifiers)
        hashes: tuple[tuple[str, str], ...] = ()
        checksum = st.get("C", "")
        if checksum.startswith("Q1"):
            import base64

            try:
                hashes = (("sha1", base64.b64decode(checksum[2:]).hex()),)
            except (ValueError, TypeError):
                pass
        edges = []
        for dep in st.get("D", "").split():
            m = _DEP_NAME_RE.match(dep.lstrip("!").split("=", 1)[0].split("<", 1)[0].split(">", 1)[0])
            if m and not dep.startswith("so:") and not dep.startswith("/"):
                edges.append(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=ref_purl(purl),
                        dst=ref_family("apk", m.group(1)),
                        scope=Scope.RUNTIME,
                        direct=False,
                    )
                )
        return Finding(
            claim=ComponentClaim(
                ctype="os-package",
                name=name,
                version=version,
                purl=purl,
                ecosystem="apk",
                namespace=distro,
                qualifiers=tuple(sorted(qualifiers.items())),
                hashes=hashes,
                licenses_declared=st.get("L") or None,
                attrs=(("origin", st.get("o", name)),),
            ),
            evidence=(
                ctx.evidence(
                    "os-package-db",
                    Tier.INSTALLED,
                    entry,
                    span=(start, end),
                    captured=f"P:{name}\nV:{version}",
                ),
            ),
            edges=tuple(edges),
        )


class PacmanCataloger(Cataloger):
    id = "os/pacman"
    version = 1
    matchers = [Matcher(glob="*var/lib/pacman/local/*/desc")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        sections: dict[str, list[str]] = {}
        key = None
        for line in text.splitlines():
            if line.startswith("%") and line.endswith("%"):
                key = line.strip("%")
                sections[key] = []
            elif key and line.strip():
                sections[key].append(line.strip())
        name = next(iter(sections.get("NAME", [])), None)
        version = next(iter(sections.get("VERSION", [])), None)
        if not name or not version:
            return
        purl = make_purl("alpm", name, version, namespace="arch")
        edges = [
            EdgeClaim(
                kind=EdgeType.DEPENDS_ON,
                src=ref_purl(purl),
                dst=ref_family("alpm", _DEP_NAME_RE.match(d).group(1)),  # type: ignore[union-attr]
                scope=Scope.RUNTIME,
                direct=False,
            )
            for d in sections.get("DEPENDS", [])
            if _DEP_NAME_RE.match(d)
        ]
        yield Finding(
            claim=ComponentClaim(
                ctype="os-package",
                name=name,
                version=version,
                purl=purl,
                ecosystem="alpm",
                namespace="arch",
                licenses_declared=next(iter(sections.get("LICENSE", [])), None),
            ),
            evidence=(
                ctx.evidence(
                    "os-package-db",
                    Tier.INSTALLED,
                    entry,
                    span=(1, len(text.splitlines())),
                    captured=f"%NAME%\n{name}\n%VERSION%\n{version}",
                ),
            ),
            edges=tuple(edges),
        )


register(DpkgCataloger())
register(ApkCataloger())
register(PacmanCataloger())


# -- Gentoo portage ----------------------------------------------------------------------

#: A Gentoo `PF` is `<name>-<version>[-r<rev>]`. The version starts at the first
#: hyphen followed by a digit, which is what separates `docbook-xml-dtd` from
#: `4.1.2-r7` — a name may itself contain hyphens.
_PF_RE = re.compile(r"^(?P<name>.+?)-(?P<version>\d[^-]*(?:[-_][a-z]\w*)*(?:-r\d+)?)$")


class PortageCataloger(Cataloger):
    """Gentoo's VDB: one directory per installed package under `/var/db/pkg`.

    `PF` names the package, and the sibling `CATEGORY` gives the namespace that
    makes it unique — `dev-libs/openssl` and `dev-util/openssl` would otherwise
    collide.
    """

    id = "os/portage"
    version = 1
    matchers = [Matcher(glob="*var/db/pkg/*/*/PF")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        pf = blob.decode("utf-8", errors="replace").strip()
        m = _PF_RE.match(pf)
        if not m:
            return
        name, version = m.group("name"), m.group("version")
        pkg_dir = entry.path.rsplit("/", 1)[0]
        category = _sibling(ctx, pkg_dir, "CATEGORY") or entry.path.split("/")[-3]
        slot = _sibling(ctx, pkg_dir, "SLOT")
        repository = _sibling(ctx, pkg_dir, "repository")
        qualifiers = {k: v for k, v in (("slot", slot), ("repository", repository)) if v}
        purl = make_purl("ebuild", name, version, namespace=category, qualifiers=qualifiers)
        yield Finding(
            claim=ComponentClaim(
                ctype="os-package", name=name, version=version, purl=purl,
                ecosystem="ebuild", namespace=category,
                qualifiers=tuple(sorted(qualifiers.items())),
            ),
            evidence=(
                ctx.evidence("installed-state", Tier.INSTALLED, entry, captured=f"{category}/{pf}"),
            ),
        )


def _sibling(ctx: CatalogerContext, directory: str, name: str) -> str | None:
    raw = ctx.peek(f"{directory}/{name}")
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace").strip() or None


register(PortageCataloger())
