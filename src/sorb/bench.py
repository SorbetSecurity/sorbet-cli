"""Benchmark harness & perf gates.

A dependency-free, in-process harness (no pytest-benchmark) covering the
scenario rows — walk, hash, full scan, emit, query — over synthetic corpora it
generates deterministically. Two gates ride on top: a **regression gate** that
fails when a scenario is >N% slower than a recorded baseline, and a **startup
gate** (`sorb --help` < 300 ms). Wall-clock numbers are noisy, so gates compare
best-of-K and use a generous threshold; the harness exists to catch a *deliberate*
slowdown, not micro-jitter.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_ITERATIONS = 3
REGRESSION_THRESHOLD = 0.10  # >10% slower than baseline fails the gate
# Windows gets headroom: process creation plus Defender scanning inflates
# cold starts by ~50% on comparable hardware
STARTUP_BUDGET_MS = 450.0 if sys.platform == "win32" else 300.0


@dataclass(frozen=True, slots=True)
class BenchResult:
    name: str
    iterations: int
    best_ms: float
    mean_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "iterations": self.iterations,
                "best_ms": round(self.best_ms, 3), "mean_ms": round(self.mean_ms, 3)}


def timed(name: str, fn: Callable[[], Any], iterations: int = DEFAULT_ITERATIONS) -> BenchResult:
    samples: list[float] = []
    for _ in range(max(1, iterations)):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return BenchResult(name=name, iterations=len(samples),
                       best_ms=min(samples), mean_ms=sum(samples) / len(samples))


# -- synthetic corpus generators ---------------------------------------------------------


def synthetic_monorepo(root: Path, *, projects: int = 20, deps: int = 15) -> Path:
    """Deterministically generate a polyglot monorepo (npm + pip + go workspaces)."""
    root.mkdir(parents=True, exist_ok=True)
    for i in range(projects):
        proj = root / f"pkg{i:03d}"
        proj.mkdir(exist_ok=True)
        pkg = {
            "name": f"pkg{i:03d}", "version": "1.0.0",
            "dependencies": {f"dep-{j}": f"1.{j}.0" for j in range(deps)},
        }
        (proj / "package.json").write_text(json.dumps(pkg))
        (proj / "requirements.txt").write_text(
            "".join(f"lib{j}=={j}.0.0\n" for j in range(deps))
        )
        (proj / "go.mod").write_text(
            f"module example.com/pkg{i:03d}\n\ngo 1.21\n\nrequire (\n"
            + "".join(f"\tgithub.com/x/dep{j} v0.{j}.0\n" for j in range(deps)) + ")\n"
        )
    return root


# -- scenarios ---------------------------------------------------------------------------


def run_suite(root: Path | None = None, *, iterations: int = DEFAULT_ITERATIONS) -> list[BenchResult]:
    """Run every benchmark scenario over a synthetic corpus. Returns timings."""
    import tempfile

    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan
    from sorb.emit.cyclonedx import emit_cyclonedx
    from sorb.graph.store import GraphStore
    from sorb.query import run_query
    from sorb.source.dir import DirSource

    results: list[BenchResult] = []
    with tempfile.TemporaryDirectory(prefix="sorb-bench-") as tmp:
        tmpd = Path(tmp)
        corpus = root or synthetic_monorepo(tmpd / "corpus")
        cfg = load_config(flags={}, env={}, user_config_path=tmpd / "nc.toml")

        results.append(timed("walk", lambda: list(DirSource(corpus).walk()), iterations))
        src = DirSource(corpus)
        files = [e.path for e in src.walk()]
        results.append(timed("hash", lambda: [src.digest(p) for p in files], iterations))

        store_path = tmpd / "bench.sorb.db"
        results.append(timed(
            "scan", lambda: run_scan(str(corpus), cfg, store_path=store_path), iterations))
        store = GraphStore.open_readonly(store_path)
        try:
            results.append(timed("emit-cyclonedx",
                                 lambda: emit_cyclonedx(store, reproducible=True), iterations))
            results.append(timed("query",
                                 lambda: run_query(store, "components | count by ecosystem"), iterations))
        finally:
            store.close()
    return results


# -- gates -------------------------------------------------------------------------------


def check_regression(
    current: list[BenchResult] | dict[str, float],
    baseline: dict[str, float],
    *,
    threshold: float = REGRESSION_THRESHOLD,
) -> list[str]:
    """Return a list of regression messages (empty = pass). A scenario is a
    regression if its best time is >threshold slower than the baseline."""
    cur = ({r.name: r.best_ms for r in current}
           if isinstance(current, list) else dict(current))
    out: list[str] = []
    for name, base_ms in baseline.items():
        now = cur.get(name)
        if now is None or base_ms <= 0:
            continue
        ratio = now / base_ms
        if ratio > 1 + threshold:
            out.append(f"{name}: {now:.1f}ms vs baseline {base_ms:.1f}ms "
                       f"(+{(ratio - 1) * 100:.0f}%, > {threshold * 100:.0f}% budget)")
    return out


def sorb_binary() -> str | None:
    """Locate the `sorb` entry point to time.

    Prefers the executable running this process, so a venv or bundle install
    measures itself rather than whatever happens to be on PATH.
    """
    import shutil
    import sys

    argv0 = Path(sys.argv[0])
    if argv0.name.startswith("sorb") and argv0.is_file():
        return str(argv0.resolve())
    return shutil.which("sorb")


def startup_ms(binary: str | None = None) -> float:
    """Wall-clock of `sorb --help` (best of two, first warms caches).

    Raises `SubsystemDegraded` when no `sorb` entry point can be located, so
    the caller can report a skipped gate instead of dying on a missing file.
    """
    import subprocess

    from sorb.errors import SubsystemDegraded

    binary = binary or sorb_binary()
    if binary is None:
        raise SubsystemDegraded(
            "cannot time startup: no `sorb` executable found on PATH or in argv[0] "
            "(pass --no-startup, or run the installed entry point)"
        )
    subprocess.run([binary, "--help"], capture_output=True)
    best = float("inf")
    for _ in range(2):
        t0 = time.perf_counter()
        try:
            subprocess.run([binary, "--help"], capture_output=True, check=True)
        except (OSError, subprocess.CalledProcessError) as e:
            raise SubsystemDegraded(f"cannot time startup: `{binary} --help` failed: {e}") from e
        best = min(best, (time.perf_counter() - t0) * 1000)
    return best


def write_baseline(results: list[BenchResult], path: Path) -> None:
    path.write_text(json.dumps({r.name: r.best_ms for r in results}, indent=2, sort_keys=True))
