"""macOS sandbox via `sandbox-exec` profile generation.

Deny-by-default Seatbelt profile: reads limited to the project, the scratch
home, and the system toolchain roots; writes limited to the project + scratch
home; **all network denied** (loopback included) unless hosts are allowlisted
— an allowlisted host opens outbound network only (Seatbelt cannot filter by
DNS name, so `--allow-net` on macOS opens remote sockets as a unit and
records that coarseness honestly in the profile comment).
"""

from __future__ import annotations

import shutil
from pathlib import Path

from sorb.dynamic.sandbox.spec import BrokerResult, SandboxSpec, _popen, _rlimit_preexec

_SANDBOX_EXEC = "/usr/bin/sandbox-exec"

#: system roots the toolchain needs to read (binaries, libs, frameworks)
_SYSTEM_READ_ROOTS = (
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library",
    "/opt",
    "/private/etc",
    "/private/var/db/timezone",
    "/dev/null",
    "/dev/urandom",
    "/dev/random",
    "/dev/dtracehelper",
)


def macos_sandbox_available() -> tuple[bool, str]:
    if shutil.which(_SANDBOX_EXEC) or Path(_SANDBOX_EXEC).exists():
        return True, "sandbox-exec"
    return False, "sandbox-exec not found (expected at /usr/bin/sandbox-exec)"


def _lit(path: object) -> str:
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


def _resolved(path: object) -> str:
    """Seatbelt matches fully-resolved paths.

    `/tmp` and `/var/folders` are symlinks into `/private` on macOS, so a rule
    written with the unresolved path silently matches nothing.
    """
    try:
        return str(Path(str(path)).resolve())
    except OSError:
        return str(path)


def generate_profile(spec: SandboxSpec) -> str:
    """A Seatbelt (SBPL) profile implementing the SandboxSpec."""
    read_paths = [
        _resolved(spec.project_root),
        _resolved(spec.scratch_home),
        *(_resolved(p) for p in spec.extra_read_paths),
    ]
    write_paths = [_resolved(spec.project_root), _resolved(spec.scratch_home), "/dev/null"]
    lines = [
        "(version 1)",
        "(deny default)",
        "; sorb native-mode sandbox: deny-by-default, project-scoped",
        "(allow process-fork)",
        "(allow process-exec*)",
        "(allow signal (target same-sandbox))",
        "(allow sysctl-read)",
        "(allow mach*)",  # dyld + libSystem services
        "(allow ipc-posix-shm*)",
        "(allow file-read-metadata)",
        "(allow file-ioctl (literal \"/dev/null\"))",
        # the root directory entry itself must be readable to resolve any path
        # (subpath rules don't cover "/"); dyld's shared cache is exempt.
        '(allow file-read* (literal "/"))',
    ]
    for root in _SYSTEM_READ_ROOTS:
        lines.append(f'(allow file-read* file-map-executable (subpath "{_lit(root)}"))')
    for root in read_paths:
        lines.append(f'(allow file-read* file-map-executable (subpath "{_lit(root)}"))')
    for root in write_paths:
        kind = "subpath" if root != "/dev/null" else "literal"
        lines.append(f'(allow file-write* ({kind} "{_lit(root)}"))')
    if spec.allow_net_hosts:
        lines.append(
            f"; --allow-net {','.join(spec.allow_net_hosts)}: Seatbelt cannot filter by "
            "hostname — outbound network opened as a unit (recorded coarseness)"
        )
        lines.append("(allow network-outbound)")
        lines.append("(allow system-socket)")
    # no network rules otherwise: (deny default) denies every socket, loopback included
    return "\n".join(lines) + "\n"


def run_macos_sandboxed(spec: SandboxSpec, argv: list[str]) -> BrokerResult:
    profile = generate_profile(spec)
    profile_path = spec.scratch_home / "sorb-sandbox.sb"
    profile_path.write_text(profile)
    wrapped = [_SANDBOX_EXEC, "-f", str(profile_path), *argv]
    return _popen(wrapped, spec, preexec=_rlimit_preexec(spec))
