"""Concrete native drivers (Gradle/Maven, PEP 517, npm/yarn/pnpm,
Swift, sbt, Bazel).

Each driver: `applies_to` (project markers), `build_command` (sandboxed argv),
`parse` (machine output → NativeResolution). The parsers are the unit-tested
surface; the commands run only under `--resolve=native`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from sorb.dynamic.drivers.base import NativeDriver, NativeResolution, ResolvedDep, _register


def _has_any(root: Path, *names: str) -> bool:
    return any((root / n).exists() for n in names)


# -- Maven -------------------------------------------------------------------------------

_MVN_TREE_LINE = re.compile(
    r"([\w.\-]+):([\w.\-]+):([\w.\-]+):([\w.\-]+)(?::([\w.\-]+))?"
)


class MavenDriver(NativeDriver):
    id = "maven"
    ecosystem = "maven"
    tools = ("mvn",)

    def applies_to(self, project_root: Path) -> bool:
        return (project_root / "pom.xml").exists()

    def build_command(self, project_root: Path, scratch_home: Path) -> list[str]:
        return [
            "mvn", "-q", "-o", "--batch-mode",
            "org.apache.maven.plugins:maven-dependency-plugin:3.6.1:tree",
            "-DoutputType=text", "-DappendOutput=true",
        ]

    def parse(self, stdout: bytes, stderr: bytes) -> NativeResolution:
        res = NativeResolution(driver_id=self.id, project_kind="maven-module")
        stack: list[tuple[int, str]] = []  # (indent depth, "g:a")
        for raw in stdout.decode("utf-8", "replace").splitlines():
            line = raw.rstrip()
            m = _MVN_TREE_LINE.search(line)
            if not m:
                continue
            group, artifact, _packaging, version = m.group(1), m.group(2), m.group(3), m.group(4)
            scope = m.group(5) or "compile"
            depth = (len(line) - len(line.lstrip(" |+\\-"))) // 3
            ga = f"{group}:{artifact}"
            if depth == 0:
                res.project_name = ga
                stack = [(0, ga)]
                continue
            while stack and stack[-1][0] >= depth:
                stack.pop()
            parent = stack[-1][1] if stack else res.project_name
            res.deps.append(
                ResolvedDep(
                    ecosystem="maven",
                    name=ga,
                    version=version,
                    namespace=group,
                    scope=_maven_scope(scope),
                    direct=depth == 1,
                    parent=parent if depth > 1 else None,
                )
            )
            stack.append((depth, ga))
        return res


def _maven_scope(scope: str) -> str:
    return {"test": "test", "provided": "provided", "runtime": "runtime"}.get(scope, "runtime")


# -- Gradle ------------------------------------------------------------------------------

_GRADLE_INIT_SCRIPT = """
allprojects {
    tasks.register("sorbDeps") {
        doLast {
            def out = [:]
            configurations.findAll { it.canBeResolved }.each { cfg ->
                try {
                    cfg.resolvedConfiguration.lenientConfiguration.allModuleDependencies.each { d ->
                        def key = "${d.moduleGroup}:${d.moduleName}:${d.moduleVersion}"
                        out[key] = cfg.name
                    }
                } catch (ignored) {}
            }
            println "SORB_DEPS_JSON:" + groovy.json.JsonOutput.toJson(out)
        }
    }
}
"""


class GradleDriver(NativeDriver):
    id = "gradle"
    ecosystem = "maven"
    tools = ("gradle",)

    def applies_to(self, project_root: Path) -> bool:
        return _has_any(project_root, "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")

    def extra_env(self, project_root: Path, scratch_home: Path) -> tuple[tuple[str, str], ...]:
        return (("GRADLE_USER_HOME", str(scratch_home / ".gradle")),)

    def scratch_files(self) -> tuple[tuple[str, str], ...]:
        return (("sorb-init.gradle", _GRADLE_INIT_SCRIPT),)

    def build_command(self, project_root: Path, scratch_home: Path) -> list[str]:
        init_script = scratch_home / "sorb-init.gradle"
        return ["gradle", "--offline", "-q", "--init-script", str(init_script), "sorbDeps"]

    def parse(self, stdout: bytes, stderr: bytes) -> NativeResolution:
        res = NativeResolution(driver_id=self.id, project_kind="gradle-project")
        for line in stdout.decode("utf-8", "replace").splitlines():
            if not line.startswith("SORB_DEPS_JSON:"):
                continue
            try:
                mapping = json.loads(line[len("SORB_DEPS_JSON:"):])
            except json.JSONDecodeError:
                continue
            for key, config in sorted(mapping.items()):
                parts = key.split(":")
                if len(parts) != 3:
                    continue
                group, artifact, version = parts
                res.deps.append(
                    ResolvedDep(
                        ecosystem="maven",
                        name=f"{group}:{artifact}",
                        version=version,
                        namespace=group,
                        scope="test" if "test" in config.lower() else "runtime",
                        direct=False,
                    )
                )
        return res


# -- PEP 517: resolves the dynamic setup.py case ------------------------------------------


class Pep517Driver(NativeDriver):
    id = "pep517"
    ecosystem = "pypi"
    tools = ()  # runs the current interpreter; build backend resolved in-sandbox

    def applies_to(self, project_root: Path) -> bool:
        return _has_any(project_root, "setup.py", "pyproject.toml", "setup.cfg")

    def scratch_files(self) -> tuple[tuple[str, str], ...]:
        return (("sorb_pep517.py", _PEP517_RUNNER),)

    def build_command(self, project_root: Path, scratch_home: Path) -> list[str]:
        import sys

        return [sys.executable, str(scratch_home / "sorb_pep517.py"), str(project_root)]

    def extra_read_paths(self) -> tuple[str, ...]:
        from sorb.dynamic.sandbox import toolchain_read_paths

        return toolchain_read_paths()

    def parse(self, stdout: bytes, stderr: bytes) -> NativeResolution:
        res = NativeResolution(driver_id=self.id, project_kind="python")
        text = stdout.decode("utf-8", "replace")
        marker = "SORB_METADATA_JSON:"
        for line in text.splitlines():
            if not line.startswith(marker):
                continue
            try:
                doc = json.loads(line[len(marker):])
            except json.JSONDecodeError:
                continue
            res.project_name = doc.get("name")
            for req in doc.get("requires_dist", []):
                parsed = _parse_requirement(str(req))
                if parsed is None:
                    continue
                name, version, requested, marker_expr = parsed
                res.deps.append(
                    ResolvedDep(
                        ecosystem="pypi",
                        name=name,
                        version=version or "",
                        scope="runtime",
                        direct=True,
                        requested=requested,
                    )
                )
        if res.project_name is None and "SORB_PEP517_ERROR:" in text:
            res.raw_ok = False
            res.warnings.append(
                "pep517: build backend could not produce metadata: "
                + text.split("SORB_PEP517_ERROR:", 1)[1].strip()[:200]
            )
        return res


_PEP517_RUNNER = '''\
import json, sys, os, tempfile, email.parser, contextlib

# Build backends chatter on stdout; stdout is the result channel, so everything
# but the marker line goes to stderr.
quiet = contextlib.redirect_stdout(sys.stderr)


def emit(name, reqs):
    sys.__stdout__.write("SORB_METADATA_JSON:" + json.dumps(
        {"name": name, "requires_dist": list(reqs or [])}) + "\\n")
    sys.exit(0)


def read_metadata(dist_info):
    with open(os.path.join(dist_info, "METADATA"), "rb") as f:
        msg = email.parser.BytesParser().parse(f)
    return msg.get("Name"), msg.get_all("Requires-Dist")


def declared_backend():
    try:
        import tomllib
    except ImportError:
        return None
    try:
        with open("pyproject.toml", "rb") as f:
            table = tomllib.load(f).get("build-system") or {}
    except (OSError, ValueError):
        return None
    return table.get("build-backend") or "setuptools.build_meta"


project = sys.argv[1]
os.chdir(project)
errors = []

# 1. `build` drives any backend and honours build-system.requires.
try:
    import build
    builder = build.ProjectBuilder(project)
    # The metadata directory lives only as long as the temp dir, so it has to
    # be read inside the block.
    with quiet, tempfile.TemporaryDirectory() as td:
        emit(*read_metadata(builder.metadata_path(td)))
except SystemExit:
    raise
except Exception as e:
    errors.append("build: " + repr(e))

# 2. No `build` installed: call the declared backend's PEP 517 hook directly.
try:
    import importlib
    name = declared_backend()
    if name:
        backend = importlib.import_module(name.split(":", 1)[0])
        if ":" in name:
            backend = getattr(backend, name.split(":", 1)[1])
        with quiet, tempfile.TemporaryDirectory() as td:
            dist_info = backend.prepare_metadata_for_build_wheel(td)
            emit(*read_metadata(os.path.join(td, dist_info)))
except SystemExit:
    raise
except Exception as e:
    errors.append("backend: " + repr(e))

# 3. Legacy setup.py: capture the setup() call without running a build.
if os.path.exists(os.path.join(project, "setup.py")):
    try:
        import runpy
        import setuptools
        captured = {}
        orig_setup = setuptools.setup
        def fake_setup(**kw):
            captured.update(kw)
        setuptools.setup = fake_setup
        try:
            with quiet:
                runpy.run_path(os.path.join(project, "setup.py"), run_name="__main__")
        finally:
            setuptools.setup = orig_setup
        emit(captured.get("name"), captured.get("install_requires"))
    except SystemExit:
        raise
    except Exception as e:
        errors.append("setup.py: " + repr(e))

sys.__stdout__.write("SORB_PEP517_ERROR:" + "; ".join(errors[-2:]) + "\\n")
'''


def _parse_requirement(req: str) -> tuple[str, str | None, str | None, str | None] | None:
    """(name, pinned version, requested spec, marker) from a PEP 508 string."""
    from packaging.requirements import InvalidRequirement, Requirement

    try:
        parsed = Requirement(req)
    except InvalidRequirement:
        m = re.match(r"^([A-Za-z0-9._\-]+)", req)
        return (m.group(1), None, None, None) if m else None
    pinned = None
    for spec in parsed.specifier:
        if spec.operator == "==":
            pinned = spec.version
    return (
        parsed.name,
        pinned,
        str(parsed.specifier) or None,
        str(parsed.marker) if parsed.marker else None,
    )


# -- npm / yarn / pnpm --------------------------------------------------------------------


class NpmLsDriver(NativeDriver):
    id = "npm"
    ecosystem = "npm"
    tools = ("npm",)

    def applies_to(self, project_root: Path) -> bool:
        return (project_root / "package.json").exists() and not _has_any(
            project_root, "pnpm-lock.yaml", "yarn.lock"
        )

    def build_command(self, project_root: Path, scratch_home: Path) -> list[str]:
        return ["npm", "ls", "--all", "--json", "--package-lock-only"]

    def parse(self, stdout: bytes, stderr: bytes) -> NativeResolution:
        res = NativeResolution(driver_id=self.id, project_kind="npm")
        try:
            doc = json.loads(stdout.decode("utf-8", "replace") or "{}")
        except json.JSONDecodeError:
            res.raw_ok = False
            return res
        res.project_name = doc.get("name")

        def walk(node: dict[str, object], parent: str | None, direct: bool) -> None:
            deps = node.get("dependencies")
            for name, info in (deps.items() if isinstance(deps, dict) else ()):
                if not isinstance(info, dict):
                    continue
                version = str(info.get("version", ""))
                if version:
                    res.deps.append(
                        ResolvedDep(
                            ecosystem="npm", name=name, version=version,
                            scope="dev" if info.get("dev") else "runtime",
                            direct=direct, parent=parent,
                        )
                    )
                    walk(info, name, False)

        walk(doc, res.project_name, True)
        return res


class PnpmLsDriver(NpmLsDriver):
    id = "pnpm"
    tools = ("pnpm",)

    def applies_to(self, project_root: Path) -> bool:
        return (project_root / "pnpm-lock.yaml").exists()

    def build_command(self, project_root: Path, scratch_home: Path) -> list[str]:
        return ["pnpm", "ls", "--depth", "Infinity", "--json"]

    def parse(self, stdout: bytes, stderr: bytes) -> NativeResolution:
        res = NativeResolution(driver_id=self.id, project_kind="pnpm")
        try:
            docs = json.loads(stdout.decode("utf-8", "replace") or "[]")
        except json.JSONDecodeError:
            res.raw_ok = False
            return res
        for project in docs if isinstance(docs, list) else [docs]:
            res.project_name = res.project_name or project.get("name")
            for section, scope in (("dependencies", "runtime"), ("devDependencies", "dev")):
                for name, info in (project.get(section) or {}).items():
                    if isinstance(info, dict) and info.get("version"):
                        res.deps.append(
                            ResolvedDep(
                                ecosystem="npm", name=name, version=str(info["version"]),
                                scope=scope, direct=True,
                            )
                        )
        return res


# -- Swift --------------------------------------------------------------------------------


class SwiftDriver(NativeDriver):
    id = "swift"
    ecosystem = "swift"
    tools = ("swift",)

    def applies_to(self, project_root: Path) -> bool:
        return (project_root / "Package.swift").exists()

    def build_command(self, project_root: Path, scratch_home: Path) -> list[str]:
        return ["swift", "package", "show-dependencies", "--format", "json"]

    def parse(self, stdout: bytes, stderr: bytes) -> NativeResolution:
        res = NativeResolution(driver_id=self.id, project_kind="swift")
        try:
            doc = json.loads(stdout.decode("utf-8", "replace") or "{}")
        except json.JSONDecodeError:
            res.raw_ok = False
            return res
        res.project_name = doc.get("name")

        def walk(node: dict[str, object], parent: str | None, direct: bool) -> None:
            children = node.get("dependencies")
            for dep in (children if isinstance(children, list) else []):
                name = dep.get("identity") or dep.get("name")
                version = dep.get("version")
                if name and version and version != "unspecified":
                    res.deps.append(
                        ResolvedDep(
                            ecosystem="swift", name=str(name), version=str(version),
                            scope="runtime", direct=direct, parent=parent,
                            namespace=_swift_ns(dep.get("url", "")),
                        )
                    )
                walk(dep, str(name), False)

        walk(doc, res.project_name, True)
        return res


def _swift_ns(url: str) -> str | None:
    m = re.search(r"github\.com[:/]([^/]+)/", url)
    return f"github.com/{m.group(1)}" if m else None


# -- sbt ----------------------------------------------------------------------------------


class SbtDriver(NativeDriver):
    id = "sbt"
    ecosystem = "maven"
    tools = ("sbt",)

    def applies_to(self, project_root: Path) -> bool:
        return (project_root / "build.sbt").exists()

    def build_command(self, project_root: Path, scratch_home: Path) -> list[str]:
        return ["sbt", "--batch", "-Dsbt.log.noformat=true", "dependencyList"]

    def parse(self, stdout: bytes, stderr: bytes) -> NativeResolution:
        res = NativeResolution(driver_id=self.id, project_kind="sbt")
        line_re = re.compile(r"\[info\]\s+([\w.\-]+):([\w.\-]+):([\w.\-]+)")
        for line in stdout.decode("utf-8", "replace").splitlines():
            m = line_re.search(line)
            if m:
                group, artifact, version = m.groups()
                res.deps.append(
                    ResolvedDep(
                        ecosystem="maven", name=f"{group}:{artifact}", version=version,
                        namespace=group, scope="runtime", direct=False,
                    )
                )
        return res


# -- Bazel: workspace topology ------------------------------------------------------------


class BazelDriver(NativeDriver):
    id = "bazel"
    ecosystem = "bazel"
    tools = ("bazel",)

    def applies_to(self, project_root: Path) -> bool:
        return _has_any(project_root, "MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel")

    def build_command(self, project_root: Path, scratch_home: Path) -> list[str]:
        return ["bazel", "mod", "graph", "--output", "json"]

    def parse(self, stdout: bytes, stderr: bytes) -> NativeResolution:
        res = NativeResolution(driver_id=self.id, project_kind="bazel-workspace")
        try:
            doc = json.loads(stdout.decode("utf-8", "replace") or "{}")
        except json.JSONDecodeError:
            res.raw_ok = False
            return res

        def walk(node: dict[str, object], parent: str | None, direct: bool) -> None:
            key = str(node.get("key", ""))
            if "@" in key:
                name, _, version = key.partition("@")
                if name and version:
                    res.deps.append(
                        ResolvedDep(
                            ecosystem="bazel", name=name, version=version,
                            scope="build", direct=direct, parent=parent,
                        )
                    )
                    parent = name
            children = node.get("dependencies")
            for child in children if isinstance(children, list) else []:
                if isinstance(child, dict):
                    walk(child, parent, bool(node.get("root", False)))

        walk(doc, None, True)
        return res


for _driver in (
    MavenDriver(), GradleDriver(), Pep517Driver(), NpmLsDriver(), PnpmLsDriver(),
    SwiftDriver(), SbtDriver(), BazelDriver(),
):
    _register(_driver)
