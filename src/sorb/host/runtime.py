"""Runtime augmentation for live hosts.

"What is running right now, and what is exposed?" We read `/proc` (offline, no
ptrace, privilege-free where readable): each process's executable and loaded
shared libraries (`/proc/<pid>/exe`, `/proc/<pid>/maps`), and the listening TCP
sockets (`/proc/net/tcp[6]`) mapped to their owning process via `/proc/<pid>/fd`.
Each running binary/library is attributed to an installed component; that
component is marked **observed** (OBSERVED tier) with an `OBSERVED_IN` edge
and its listening ports — so `components where observed and version < X` becomes
answerable (the flagship fleet query).

The `/proc` root is taken from the host source root, so a synthetic `/proc`
fixture exercises the whole path deterministically and cross-platform.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from sorb.graph.store import GraphStore
from sorb.model import EdgeType

_MAPS_PATH_RE = re.compile(r"\s(/\S+\.so[.\d]*)$")
_LISTEN_STATE = "0A"  # TCP_LISTEN in /proc/net/tcp

#: soname → owning package aliases, for libraries whose file name isn't the
#: package name (the long tail is data-pack territory; these are the staples).
_SONAME_ALIASES = {
    "ssl": "openssl", "crypto": "openssl", "z": "zlib", "curl": "curl",
    "sqlite3": "sqlite", "xml2": "libxml2", "pcre2-8": "pcre2", "lzma": "xz",
    "bz2": "bzip2", "systemd": "systemd", "pq": "postgresql",
}


@dataclass
class ProcInfo:
    pid: int
    comm: str = ""
    exe: str = ""
    libs: list[str] = field(default_factory=list)


def observe_runtime(store: GraphStore, host_root: Path, source_id: str) -> tuple[int, int]:
    """Mark running components observed. Returns (n_components, n_ports)."""
    proc = host_root / "proc"
    if not proc.is_dir():
        return (0, 0)

    name_index = _name_index(store)
    procs = _enumerate_procs(proc)
    pid_ports = _pid_ports(proc)

    observed: dict[int, dict[str, set[str]]] = {}
    for p in procs:
        ports = pid_ports.get(p.pid, set())
        for path in [p.exe, *p.libs]:
            if not path:
                continue
            cid = _attribute(store, path, name_index)
            if cid is None:
                continue
            rec = observed.setdefault(cid, {"exes": set(), "ports": set()})
            rec["exes"].add(p.exe or p.comm or path)
            rec["ports"].update(str(pt) for pt in ports)

    n_ports = 0
    src_node = store.source_node_id(0)
    for cid, rec in sorted(observed.items()):
        comp = store.component_by_id(cid)
        if comp is None:
            continue
        attrs = dict(comp.attrs)
        attrs["observed"] = "true"
        if rec["ports"]:
            attrs["observed_ports"] = ",".join(sorted(rec["ports"], key=int))
            n_ports += len(rec["ports"])
        store.update_component_attrs(cid, attrs)
        store.add_edge(EdgeType.OBSERVED_IN, cid, src_node,
                       attrs={"exe": sorted(rec["exes"])[0] if rec["exes"] else "",
                              "ports": sorted(rec["ports"], key=int)})
        detail = f"running: {sorted(rec['exes'])[0] if rec['exes'] else '?'}"
        if rec["ports"]:
            detail += f" · listening on {attrs['observed_ports']}"
        store.add_annotation("component", cid, "observed-running", detail)
    return (len(observed), n_ports)


# -- /proc readers ------------------------------------------------------------


def _enumerate_procs(proc: Path) -> list[ProcInfo]:
    out: list[ProcInfo] = []
    try:
        entries = sorted((p for p in proc.iterdir() if p.name.isdigit()),
                         key=lambda p: int(p.name))
    except OSError:
        return out
    for pdir in entries:
        info = ProcInfo(pid=int(pdir.name))
        info.comm = _read_text(pdir / "comm").strip()
        info.exe = _readlink(pdir / "exe")
        info.libs = _maps_libs(pdir / "maps")
        out.append(info)
    return out


def _maps_libs(maps: Path) -> list[str]:
    libs: list[str] = []
    seen: set[str] = set()
    text = _read_text(maps)
    for line in text.splitlines():
        m = _MAPS_PATH_RE.search(line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            libs.append(m.group(1))
    return libs


def _pid_ports(proc: Path) -> dict[int, set[int]]:
    """Map owning pid → set of listening TCP ports."""
    inode_port: dict[str, int] = {}
    for net in ("net/tcp", "net/tcp6"):
        for line in _read_text(proc / net).splitlines()[1:]:
            cols = line.split()
            if len(cols) < 10 or cols[3] != _LISTEN_STATE:
                continue
            local = cols[1]
            inode = cols[9]
            try:
                port = int(local.rsplit(":", 1)[1], 16)
            except (ValueError, IndexError):
                continue
            inode_port[inode] = port
    # inode → pid via /proc/<pid>/fd/* → socket:[inode]
    pid_ports: dict[int, set[int]] = {}
    try:
        pdirs = [p for p in proc.iterdir() if p.name.isdigit()]
    except OSError:
        return pid_ports
    for pdir in pdirs:
        fd = pdir / "fd"
        try:
            fds = list(fd.iterdir())
        except OSError:
            continue
        for link in fds:
            target = _readlink(link)
            m = re.match(r"socket:\[(\d+)\]", target)
            if m and m.group(1) in inode_port:
                pid_ports.setdefault(int(pdir.name), set()).add(inode_port[m.group(1)])
    return pid_ports


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _readlink(path: Path) -> str:
    try:
        # fixtures store the link target in a plain file when symlinks are awkward
        if path.is_symlink():
            import os

            return os.readlink(path)
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    return ""


# -- attribution --------------------------------------------------------------


def _name_index(store: GraphStore) -> dict[str, int]:
    index: dict[str, int] = {}
    for c in store.components():
        if c.attrs.get("excluded"):
            continue
        index.setdefault(c.name.lower(), c.id)
    return index


def _lib_token(path: str) -> str:
    base = path.rsplit("/", 1)[-1]
    if base.startswith("lib"):
        base = base[3:]
    base = re.sub(r"\.so[.\d]*$", "", base)
    base = re.sub(r"[-.]\d+(\.\d+)*$", "", base)
    return base.lower()


def _attribute(store: GraphStore, path: str, name_index: dict[str, int]) -> int | None:
    base = path.rsplit("/", 1)[-1].lower()
    if base in name_index:  # exact basename == component name (nginx, redis-server)
        return name_index[base]
    token = _lib_token(path)
    if token in name_index:
        return name_index[token]
    alias = _SONAME_ALIASES.get(token)
    if alias and alias in name_index:
        return name_index[alias]
    return None
