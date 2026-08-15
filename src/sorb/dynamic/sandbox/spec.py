"""SandboxSpec + broker protocol + platform dispatch.

The broker pattern: the sandboxed child receives **no ambient
credentials** (scrubbed environment, throwaway HOME) and its machine output
comes back over exactly one channel (captured stdout); the driver parses it
in the parent. Filesystem visibility is the project root (read) plus a
private scratch home (write); the network is denied unless specific hosts
are allowlisted via ``--allow-net``.
"""

from __future__ import annotations

import contextlib
import os
import platform
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sorb.errors import SorbError

#: environment variables that may leak credentials or state — never inherited
_ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "TERM", "TMPDIR")

_DEFAULT_TIMEOUT_S = 300
_DEFAULT_MEM_BYTES = 2 << 30
_DEFAULT_FSIZE_BYTES = 1 << 30


class SandboxUnavailable(SorbError):
    """Platform sandbox primitives missing → native mode refuses (exit 1)."""

    exit_code = 1


@dataclass(frozen=True)
class SandboxSpec:
    """What the child may see and do. Immutable; drivers never widen it."""

    project_root: Path  # readable (and writable: build tools write lock/metadata files)
    scratch_home: Path  # throwaway HOME, writable, wiped by the caller
    allow_net_hosts: tuple[str, ...] = ()  # empty = network fully denied
    extra_env: tuple[tuple[str, str], ...] = ()  # driver-specific, e.g. SORB_TRACE_OUT
    extra_read_paths: tuple[str, ...] = ()  # toolchain roots (read-only)
    #: files the driver needs inside the child's HOME, as (relative path, content).
    #: Declared rather than written by the driver so they land inside whatever
    #: filesystem the child actually sees.
    scratch_files: tuple[tuple[str, str], ...] = ()
    timeout_s: int = _DEFAULT_TIMEOUT_S
    mem_bytes: int = _DEFAULT_MEM_BYTES
    fsize_bytes: int = _DEFAULT_FSIZE_BYTES

    def materialize_scratch_files(self) -> None:
        for rel, content in self.scratch_files:
            path = self.scratch_home / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)

    def child_env(self) -> dict[str, str]:
        """Scrubbed environment: allowlisted vars + throwaway HOME, no creds."""
        env = {k: v for k, v in os.environ.items() if k in _ENV_ALLOWLIST}
        env["HOME"] = str(self.scratch_home)
        env["XDG_CACHE_HOME"] = str(self.scratch_home / ".cache")
        env["XDG_CONFIG_HOME"] = str(self.scratch_home / ".config")
        env.update(dict(self.extra_env))
        return env


@dataclass
class BrokerResult:
    """Outcome of one sandboxed invocation (stdout is the single result pipe)."""

    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


def toolchain_read_paths(*executables: str) -> tuple[str, ...]:
    """Read-only roots a toolchain needs: the interpreter install prefixes and
    the resolved directories of the given executables. Drivers pass these into
    ``SandboxSpec.extra_read_paths`` so the tool can start while the project
    stays the only writable, in-scope tree."""
    roots: set[str] = {sys.base_prefix, sys.prefix}
    for exe in executables:
        resolved = Path(exe)
        try:
            resolved = resolved.resolve()
        except OSError:
            pass
        # the install tree usually sits two levels up from bin/<tool>
        roots.add(str(resolved.parent))
        roots.add(str(resolved.parent.parent))
    return tuple(sorted(r for r in roots if r and r != "/"))


def sandbox_available() -> tuple[bool, str]:
    """Can this platform sandbox a child right now? (available, reason)."""
    system = platform.system()
    if system == "Darwin":
        from sorb.dynamic.sandbox.macos import macos_sandbox_available

        return macos_sandbox_available()
    if system == "Linux":
        from sorb.dynamic.sandbox.linux import linux_sandbox_available

        return linux_sandbox_available()
    if system == "Windows":
        from sorb.dynamic.sandbox.windows import windows_sandbox_available

        return windows_sandbox_available()
    return False, f"no sandbox implementation for {system}"


def run_sandboxed(
    spec: SandboxSpec,
    argv: list[str],
    *,
    dangerously_no_sandbox: bool = False,
) -> BrokerResult:
    """Run `argv` under the platform sandbox (or refuse).

    With ``dangerously_no_sandbox`` the command runs with only the scrubbed
    environment and rlimits — the refusal is the user's explicit choice, and
    the reduced protection is still applied.
    """
    spec.scratch_home.mkdir(parents=True, exist_ok=True)
    available, reason = sandbox_available()
    if not available and not dangerously_no_sandbox:
        raise SandboxUnavailable(
            f"cannot sandbox native-mode child ({reason}); "
            "re-run with --dangerously-no-sandbox to accept running the build "
            "tool unsandboxed, or use the default pure resolvers"
        )
    if available and not dangerously_no_sandbox:
        system = platform.system()
        if system == "Darwin":
            from sorb.dynamic.sandbox.macos import run_macos_sandboxed

            spec.materialize_scratch_files()
            return run_macos_sandboxed(spec, argv)
        if system == "Linux":
            from sorb.dynamic.sandbox.linux import run_linux_sandboxed

            # written inside the namespace instead: a private tmpfs is mounted
            # over the scratch home, which would hide anything written here.
            return run_linux_sandboxed(spec, argv)
    return run_plain(spec, argv)


def run_plain(spec: SandboxSpec, argv: list[str]) -> BrokerResult:
    """Scrubbed-env + rlimit execution (the --dangerously-no-sandbox path)."""
    spec.materialize_scratch_files()
    return _popen(argv, spec, preexec=_rlimit_preexec(spec))


def _rlimit_preexec(spec: SandboxSpec) -> Callable[[], None] | None:
    if sys.platform == "win32":
        return None

    def apply() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_FSIZE, (spec.fsize_bytes, spec.fsize_bytes))
        try:  # RLIMIT_AS is advisory on macOS but harmless
            resource.setrlimit(resource.RLIMIT_AS, (spec.mem_bytes, spec.mem_bytes))
        except (ValueError, OSError):
            pass
        os.setsid()

    return apply


def _reporting_preexec(preexec: Callable[[], None], write_fd: int) -> Callable[[], None]:
    """Wrap the sandbox setup so the child reports *which* step failed.

    CPython collapses everything a `preexec_fn` raises into the opaque
    "Exception occurred in preexec_fn.", which cannot tell a user whether the
    kernel blocked unshare(2), the uid_map write, or the tmpfs mount. The child
    writes its own reason down a pipe before re-raising.
    """

    def run() -> None:
        try:
            preexec()
        except BaseException as exc:  # noqa: BLE001 — reported, then re-raised
            try:
                os.write(write_fd, f"{type(exc).__name__}: {exc}".encode()[:512])
            except OSError:
                pass
            raise

    return run


def _preexec_reason(read_fd: int, write_fd: int) -> str:
    """Whatever the child managed to report before it died."""
    if read_fd == -1:
        return ""
    # The parent's copy of the write end has to go first, or the read blocks
    # waiting on a writer that is this very process.
    with contextlib.suppress(OSError):
        os.close(write_fd)
    try:
        return os.read(read_fd, 512).decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _popen(
    argv: list[str],
    spec: SandboxSpec,
    preexec: Callable[[], None] | None = None,
) -> BrokerResult:
    err_r = err_w = -1
    wrapped = preexec
    if preexec is not None:
        err_r, err_w = os.pipe()
        os.set_inheritable(err_w, True)
        wrapped = _reporting_preexec(preexec, err_w)
    try:
        try:
            proc = subprocess.Popen(
                argv,
                cwd=spec.project_root,
                env=spec.child_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                preexec_fn=wrapped,  # noqa: PLW1509
                pass_fds=(err_w,) if err_w != -1 else (),
            )
        except OSError as e:
            return BrokerResult(exit_code=127, stdout=b"", stderr=str(e).encode())
        except subprocess.SubprocessError as e:
            # The sandbox (namespaces, mounts, seccomp) is built by `preexec_fn`
            # in the forked child, and CPython reports a failure there as
            # SubprocessError — not OSError — so it escaped and killed the whole
            # scan. That is the ordinary case of running inside a container
            # whose seccomp policy blocks unshare(2), i.e. most CI. No sandbox
            # means the build tool does not run: refused, degraded to a warning,
            # never unconfined.
            detail = (
                f"sandbox could not be established: {_preexec_reason(err_r, err_w) or e}. "
                "Refusing to run the build tool unconfined; falling back to "
                "static analysis (--dangerously-no-sandbox overrides, unsafely)"
            )
            return BrokerResult(exit_code=127, stdout=b"", stderr=detail.encode())
    finally:
        for fd in (err_r, err_w):
            if fd != -1:
                with contextlib.suppress(OSError):
                    os.close(fd)
    try:
        stdout, stderr = proc.communicate(timeout=spec.timeout_s)
        return BrokerResult(exit_code=proc.returncode, stdout=stdout, stderr=stderr)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        return BrokerResult(exit_code=-1, stdout=stdout, stderr=stderr, timed_out=True)
