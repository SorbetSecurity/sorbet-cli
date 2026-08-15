"""Linux sandbox: user namespaces + seccomp + private tmpfs home.

Bubblewrap-style, own implementation via ctypes/libc — no external helper:

- ``CLONE_NEWUSER`` maps the caller to an unprivileged in-namespace uid;
- ``CLONE_NEWNET`` gives an **empty network namespace** — the network-deny
  guarantee is structural (no interfaces exist), not filter-based; with
  ``--allow-net`` the net namespace is simply not unshared (host-level
  allowlisting is the enrichment cache's job — a deliberate coarseness);
- ``CLONE_NEWNS`` + a private tmpfs mounted over the scratch HOME;
- a small **seccomp** BPF blocklist (ptrace, process_vm_*, kexec, module
  loading, reboot) applied via ``prctl(PR_SET_SECCOMP)`` after
  ``PR_SET_NO_NEW_PRIVS`` — hardening on top of the namespaces;
- rlimits + scrubbed environment from the shared spec machinery.

Validated by the escape-test suite on Linux CI; on other
platforms this module only reports unavailability.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import struct
import sys
from pathlib import Path

from sorb.dynamic.sandbox.spec import BrokerResult, SandboxSpec, _popen

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

MS_NOSUID = 2
MS_NODEV = 4

# BPF constants for the seccomp filter program
_BPF_LD, _BPF_W, _BPF_ABS = 0x00, 0x00, 0x20
_BPF_JMP, _BPF_JEQ, _BPF_K = 0x05, 0x10, 0x00
_BPF_RET = 0x06
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_EPERM = 1
_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7

#: syscalls blocked inside the sandbox: (x86_64 nr, aarch64 nr)
_BLOCKED_SYSCALLS = {
    "ptrace": (101, 117),
    "process_vm_readv": (310, 270),
    "process_vm_writev": (311, 271),
    "kexec_load": (246, 104),
    "init_module": (175, 105),
    "finit_module": (313, 273),
    "delete_module": (176, 106),
    "reboot": (169, 142),
    "swapon": (167, 224),
    "swapoff": (168, 225),
}


def linux_sandbox_available() -> tuple[bool, str]:
    if sys.platform != "linux":
        return False, "not Linux"
    try:
        if Path("/proc/sys/kernel/unprivileged_userns_clone").exists():
            if Path("/proc/sys/kernel/unprivileged_userns_clone").read_text().strip() == "0":
                return False, "unprivileged user namespaces disabled by the kernel"
        # probe: can we actually unshare a user namespace?
        pid = os.fork()
        if pid == 0:  # child probe
            try:
                # ctypes returns -1 on failure instead of raising (e.g. EPERM
                # under Ubuntu 24.04's AppArmor userns restriction)
                os._exit(0 if _libc().unshare(CLONE_NEWUSER) == 0 else 1)
            except Exception:  # noqa: BLE001
                os._exit(1)
        _, status = os.waitpid(pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            return False, "user-namespace creation refused (kernel policy or seccomp)"
        return True, "user namespaces"
    except OSError as e:
        return False, f"user-namespace probe failed: {e}"


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def _bpf_filter(arch: int, syscall_numbers: list[int]) -> bytes:
    """sock_filter[] blocking the listed syscalls with EPERM."""
    prog = []

    def ins(code: int, jt: int, jf: int, k: int) -> None:
        prog.append(struct.pack("<HBBI", code, jt, jf, k))

    ins(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 4)  # load arch
    ins(_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, arch)  # right arch? fall through
    ins(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ALLOW)  # foreign arch: allow (ns still guards)
    ins(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, 0)  # load syscall nr
    for nr in syscall_numbers:
        ins(_BPF_JMP | _BPF_JEQ | _BPF_K, 0, 1, nr)
        ins(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM)
    ins(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ALLOW)
    return b"".join(prog)


def _apply_seccomp() -> None:
    import platform as _platform

    machine = _platform.machine()
    if machine in ("x86_64", "amd64"):
        arch, idx = _AUDIT_ARCH_X86_64, 0
    elif machine in ("aarch64", "arm64"):
        arch, idx = _AUDIT_ARCH_AARCH64, 1
    else:
        return  # unknown arch: namespaces still guard; seccomp skipped
    numbers = [nrs[idx] for nrs in _BLOCKED_SYSCALLS.values()]
    filter_bytes = _bpf_filter(arch, numbers)
    buf = ctypes.create_string_buffer(filter_bytes, len(filter_bytes))

    class SockFprog(ctypes.Structure):
        _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.c_void_p))

    prog = SockFprog(len(filter_bytes) // 8, ctypes.cast(buf, ctypes.c_void_p))
    libc = _libc()
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "seccomp filter installation failed")


def run_linux_sandboxed(spec: SandboxSpec, argv: list[str]) -> BrokerResult:
    uid, gid = os.getuid(), os.getgid()
    allow_net = bool(spec.allow_net_hosts)

    def preexec() -> None:
        import resource

        libc = _libc()
        flags = CLONE_NEWUSER | CLONE_NEWNS | (0 if allow_net else CLONE_NEWNET)
        if libc.unshare(flags) != 0:
            raise OSError(ctypes.get_errno(), "unshare failed")
        # map the caller to an unprivileged in-namespace identity
        Path("/proc/self/setgroups").write_text("deny")
        Path("/proc/self/uid_map").write_text(f"{uid} {uid} 1")
        Path("/proc/self/gid_map").write_text(f"{gid} {gid} 1")
        # private tmpfs over the scratch home: writes never reach the real fs
        if (
            libc.mount(b"tmpfs", str(spec.scratch_home).encode(), b"tmpfs",
                       MS_NOSUID | MS_NODEV, b"size=256m") != 0
        ):
            raise OSError(ctypes.get_errno(), "tmpfs mount over scratch home failed")
        # the mount hides whatever the host put here, so populate it afterwards
        spec.materialize_scratch_files()
        resource.setrlimit(resource.RLIMIT_FSIZE, (spec.fsize_bytes, spec.fsize_bytes))
        resource.setrlimit(resource.RLIMIT_AS, (spec.mem_bytes, spec.mem_bytes))
        os.setsid()
        _apply_seccomp()

    return _popen(argv, spec, preexec=preexec)
