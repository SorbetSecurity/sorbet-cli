"""Native-driver framework.

A ``NativeDriver`` knows three things: whether it applies to a project, how to
build the sandboxed command, and how to parse that command's machine output
into a ``NativeResolution``. The framework runs the command via the sandbox
broker and hands stdout to the parser — so parsers are unit-tested against
recorded output and drivers are integration-tested where the toolchain
exists.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from sorb.dynamic.sandbox import (
    SandboxSpec,
    run_sandboxed,
    toolchain_read_paths,
)
from sorb.errors import SubsystemDegraded


@dataclass(frozen=True, slots=True)
class ResolvedDep:
    """One concretely-resolved dependency from a native toolchain."""

    ecosystem: str
    name: str
    version: str
    namespace: str | None = None
    scope: str = "runtime"  # runtime|dev|test|build|provided
    direct: bool = False
    parent: str | None = None  # dependent's "name" for edge building
    requested: str | None = None
    purl_type: str | None = None  # when != ecosystem (e.g. maven vs "jvm")


@dataclass
class NativeResolution:
    """Native toolchain output normalized for the cataloger bridge."""

    driver_id: str
    deps: list[ResolvedDep] = field(default_factory=list)
    project_name: str | None = None
    project_kind: str = "native"
    warnings: list[str] = field(default_factory=list)
    raw_ok: bool = True


class NativeDriver(ABC):
    id: str  # "gradle", "maven", "pep517", …
    ecosystem: str
    #: executables this driver needs on PATH inside the sandbox
    tools: tuple[str, ...] = ()

    @abstractmethod
    def applies_to(self, project_root: Path) -> bool:
        """Does this driver own the project at `project_root`?"""

    @abstractmethod
    def build_command(self, project_root: Path, scratch_home: Path) -> list[str]:
        """The argv to run inside the sandbox."""

    @abstractmethod
    def parse(self, stdout: bytes, stderr: bytes) -> NativeResolution:
        """Parse the toolchain's machine output into a NativeResolution."""

    def tool_available(self) -> bool:
        return all(shutil.which(t) is not None for t in self.tools)

    def extra_env(self, project_root: Path, scratch_home: Path) -> tuple[tuple[str, str], ...]:
        return ()

    def extra_read_paths(self) -> tuple[str, ...]:
        return toolchain_read_paths(*[shutil.which(t) or t for t in self.tools])

    def scratch_files(self) -> tuple[tuple[str, str], ...]:
        """Helper scripts to place in the child's HOME, as (relative path, content).

        Declared rather than written directly: the sandbox may give the child a
        different filesystem than the host, so only it knows where they land.
        """
        return ()


DRIVERS: list[NativeDriver] = []


def _register(driver: NativeDriver) -> NativeDriver:
    DRIVERS.append(driver)
    return driver


def driver_for(project_root: Path) -> NativeDriver | None:
    _ensure_loaded()
    for driver in DRIVERS:
        if driver.applies_to(project_root):
            return driver
    return None


_LOADED = False


def _ensure_loaded() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    from sorb.dynamic.drivers import ecosystems  # noqa: F401  (registration side effects)


def run_native_driver(
    driver: NativeDriver,
    project_root: Path,
    *,
    scratch_home: Path,
    allow_net_hosts: tuple[str, ...] = (),
    dangerously_no_sandbox: bool = False,
) -> NativeResolution:
    """Run a driver's command in the sandbox and parse its output.

    Raises ``SubsystemDegraded`` when the toolchain is absent (the caller
    falls back to pure/declared-tier resolution — never a guess).
    """
    if not driver.tool_available():
        raise SubsystemDegraded(
            f"native driver {driver.id!r} needs {', '.join(driver.tools)} on PATH; "
            "falling back to static analysis"
        )
    spec = SandboxSpec(
        project_root=project_root,
        scratch_home=scratch_home,
        allow_net_hosts=allow_net_hosts,
        extra_env=driver.extra_env(project_root, scratch_home),
        extra_read_paths=driver.extra_read_paths(),
        scratch_files=driver.scratch_files(),
    )
    argv = driver.build_command(project_root, scratch_home)
    result = run_sandboxed(spec, argv, dangerously_no_sandbox=dangerously_no_sandbox)
    resolution = driver.parse(result.stdout, result.stderr)
    if result.timed_out:
        resolution.warnings.append(f"{driver.id}: native resolution timed out")
        resolution.raw_ok = False
    elif result.exit_code != 0 and not resolution.deps:
        resolution.warnings.append(
            f"{driver.id}: toolchain exited {result.exit_code} with no parseable output "
            f"({result.stderr.decode('utf-8', 'replace')[:200].strip()})"
        )
        resolution.raw_ok = False
    return resolution
