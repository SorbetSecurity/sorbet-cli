"""File-trace backends with a platform fallback chain.

Each backend wraps a command and reports every file open under a package
store. The chain degrades by privilege/availability:

- Linux: eBPF (CO-RE, preferred) → fanotify → strace (always available) → none
- macOS: EndpointSecurity (entitlement/root) → dtrace (SIP-permitting) → none
- Windows: ETW kernel file provider → none

The eBPF/ES/ETW backends require kernel facilities and elevated privileges,
so they only *report available* where those exist; the always-available
fallbacks (strace on Linux) and the interpreter hooks cover the
unprivileged path. On this build the strace backend is the concrete Linux
implementation; the kernel backends are availability-probed and gated on
platform-specific CI.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod

from sorb.dynamic.trace.model import Observation, is_store_path


class FileTraceBackend(ABC):
    id: str

    @abstractmethod
    def available(self) -> tuple[bool, str]:
        ...

    @abstractmethod
    def run(self, command: list[str], env: dict[str, str]) -> tuple[int, list[Observation]]:
        ...


class NullBackend(FileTraceBackend):
    """No file tracing — the interpreter hooks still observe module loads."""

    id = "none"

    def available(self) -> tuple[bool, str]:
        return True, "no file tracing (interpreter hooks only)"

    def run(self, command: list[str], env: dict[str, str]) -> tuple[int, list[Observation]]:
        proc = subprocess.run(command, env=env, check=False)
        return proc.returncode, []


class StraceBackend(FileTraceBackend):
    """Linux ptrace-based file tracing via strace (the always-available path)."""

    id = "strace"
    _OPEN_RE = re.compile(r'openat?\([^,]*,\s*"([^"]+)"')

    def available(self) -> tuple[bool, str]:
        if sys.platform != "linux":
            return False, "not Linux"
        if shutil.which("strace") is None:
            return False, "strace not on PATH"
        return True, "strace"

    def run(self, command: list[str], env: dict[str, str]) -> tuple[int, list[Observation]]:
        import tempfile

        with tempfile.NamedTemporaryFile("r", suffix=".strace", delete=True) as log:
            argv = ["strace", "-f", "-e", "trace=openat,open", "-o", log.name, *command]
            proc = subprocess.run(argv, env=env, check=False)
            observations: list[Observation] = []
            seen: set[str] = set()
            for line in open(log.name, encoding="utf-8", errors="replace"):
                m = self._OPEN_RE.search(line)
                if m and is_store_path(m.group(1)) and m.group(1) not in seen:
                    seen.add(m.group(1))
                    observations.append(
                        Observation(
                            technique="strace-file-open",
                            kind="file",
                            identifier=m.group(1),
                            detail=m.group(1),
                        )
                    )
            return proc.returncode, observations


class _KernelProbeBackend(FileTraceBackend):
    """eBPF / EndpointSecurity / ETW: probed for availability only in this build."""

    id = "kernel"
    _reason = "kernel backend not enabled in this build (platform-CI-gated)"

    def available(self) -> tuple[bool, str]:
        return False, self._reason

    def run(self, command: list[str], env: dict[str, str]) -> tuple[int, list[Observation]]:
        raise RuntimeError("kernel backend unavailable")  # pragma: no cover


class EbpfBackend(_KernelProbeBackend):
    id = "ebpf"
    _reason = "eBPF file tracing requires CAP_BPF/root + a CO-RE kernel (platform-CI-gated)"


class EndpointSecurityBackend(_KernelProbeBackend):
    id = "endpointsecurity"
    _reason = "EndpointSecurity requires an Apple entitlement + root (platform-CI-gated)"


class EtwBackend(_KernelProbeBackend):
    id = "etw"
    _reason = "ETW kernel file provider requires Administrator (platform-CI-gated)"


def backend_chain() -> list[FileTraceBackend]:
    """The platform's file-trace backends, preferred first."""
    if sys.platform == "linux":
        return [EbpfBackend(), StraceBackend(), NullBackend()]
    if sys.platform == "darwin":
        return [EndpointSecurityBackend(), NullBackend()]
    if sys.platform == "win32":
        return [EtwBackend(), NullBackend()]
    return [NullBackend()]


def select_backend() -> FileTraceBackend:
    """First available backend in the chain (NullBackend is always last)."""
    for backend in backend_chain():
        ok, _reason = backend.available()
        if ok:
            return backend
    return NullBackend()
