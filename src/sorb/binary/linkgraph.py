"""Native-binary link-graph builder.

For every executable/dylib, resolve its ``DT_NEEDED``/imported libraries
against **the scan target's own filesystem** — honoring RPATH/RUNPATH and the
image/host's ``ld.so.conf`` search order, never the scanning machine's — then
resolve each resolved ``.so``/``.dll`` to its owning package via the
installed-state file maps. Symbol-version requirements (``GLIBC_2.34``)
become minimum-version evidence.

This is a pure resolver over a supplied file index (the walker provides it),
so it is unit-testable against a synthetic rootfs with no real binaries.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from sorb.binary.info import BinaryInfo

#: default ld.so search order when no RPATH/RUNPATH and no ld.so.conf entry
_DEFAULT_LIB_DIRS = ("/lib", "/usr/lib", "/lib64", "/usr/lib64", "/usr/local/lib")


@dataclass
class LinkTarget:
    """One resolved dynamic dependency of a binary."""

    soname: str
    resolved_path: str | None  # the file it links to, in the target fs
    owner_package: str | None = None  # owning package (from file maps)
    via_rpath: bool = False


@dataclass
class LinkResult:
    binary_path: str
    targets: list[LinkTarget] = field(default_factory=list)
    min_versions: dict[str, str] = field(default_factory=dict)  # lib prefix → min symver
    unresolved: list[str] = field(default_factory=list)


def _expand_rpath(rpaths: list[str], origin_dir: str) -> list[str]:
    out: list[str] = []
    for rp in rpaths:
        out.append(rp.replace("$ORIGIN", origin_dir).replace("${ORIGIN}", origin_dir))
    return out


def resolve_links(
    binary_path: str,
    info: BinaryInfo,
    *,
    file_index: set[str],
    extra_lib_dirs: tuple[str, ...] = (),
    file_owner: dict[str, str] | None = None,
) -> LinkResult:
    """Resolve a binary's needed libraries against a target filesystem.

    `file_index` is the set of absolute paths present in the target;
    `file_owner` maps a path to its owning package (from dpkg `.list`, RPM
    RECORD, etc.). Search order: RPATH/RUNPATH → extra (ld.so.conf) → defaults.
    """
    file_owner = file_owner or {}
    result = LinkResult(binary_path=binary_path)
    origin = posixpath.dirname(binary_path)
    rpath_dirs = _expand_rpath(info.rpaths, origin)
    search_dirs = [*rpath_dirs, *extra_lib_dirs, *_DEFAULT_LIB_DIRS]

    for soname in info.needed:
        resolved: str | None = None
        via_rpath = False
        for i, d in enumerate(search_dirs):
            candidate = posixpath.normpath(posixpath.join(d, soname))
            if candidate in file_index:
                resolved = candidate
                via_rpath = i < len(rpath_dirs)
                break
        if resolved is None:
            result.unresolved.append(soname)
        result.targets.append(
            LinkTarget(
                soname=soname,
                resolved_path=resolved,
                owner_package=file_owner.get(resolved) if resolved else None,
                via_rpath=via_rpath,
            )
        )

    # symbol-version requirements → minimum library versions
    for req in info.version_requirements:
        lib, _, ver = req.partition("_")
        if ver and _is_version(ver):
            cur = result.min_versions.get(lib)
            if cur is None or _version_gt(ver, cur):
                result.min_versions[lib] = ver
    return result


def _is_version(s: str) -> bool:
    return all(part.isdigit() for part in s.split(".") if part) and any(c.isdigit() for c in s)


def _version_gt(a: str, b: str) -> bool:
    def parts(v: str) -> list[int]:
        return [int(p) for p in v.split(".") if p.isdigit()]

    return parts(a) > parts(b)
