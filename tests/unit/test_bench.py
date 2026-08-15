"""Benchmark harness & perf gates: scenarios run, a deliberate slowdown
is caught, and the startup gate holds."""

from __future__ import annotations

from pathlib import Path

import pytest

from sorb.bench import (
    STARTUP_BUDGET_MS,
    BenchResult,
    check_regression,
    run_suite,
    sorb_binary,
    startup_ms,
    synthetic_monorepo,
    timed,
)


def test_synthetic_monorepo_is_scannable(tmp_path: Path) -> None:
    root = synthetic_monorepo(tmp_path / "m", projects=3, deps=2)
    assert (root / "pkg000" / "package.json").is_file()
    assert (root / "pkg002" / "go.mod").is_file()


def test_run_suite_covers_the_scenario_rows(tmp_path: Path) -> None:
    corpus = synthetic_monorepo(tmp_path / "c", projects=4, deps=3)
    results = run_suite(corpus, iterations=1)
    names = {r.name for r in results}
    assert {"walk", "hash", "scan", "emit-cyclonedx", "query"} <= names
    assert all(r.best_ms >= 0 for r in results)


def test_timed_reports_best_and_mean() -> None:
    r = timed("noop", lambda: sum(range(1000)), iterations=3)
    assert r.iterations == 3 and r.best_ms <= r.mean_ms + 1e-6


def test_regression_gate_catches_a_slowdown() -> None:
    baseline = {"scan": 100.0, "walk": 10.0}
    current = [BenchResult("scan", 3, 130.0, 135.0), BenchResult("walk", 3, 10.5, 11.0)]
    regressions = check_regression(current, baseline)  # scan +30%, walk +5%
    assert len(regressions) == 1 and "scan" in regressions[0]


def test_regression_gate_passes_within_budget() -> None:
    baseline = {"scan": 100.0}
    current = [BenchResult("scan", 3, 105.0, 106.0)]  # +5% < 10% budget
    assert check_regression(current, baseline) == []


def test_startup_gate() -> None:
    binary = sorb_binary()
    if binary is None:
        pytest.skip("no sorb entry point on PATH or argv[0]")
    st = startup_ms(binary)
    assert st < STARTUP_BUDGET_MS, f"sorb --help took {st:.0f}ms (budget {STARTUP_BUDGET_MS:.0f}ms)"


def test_bench_cli_runs(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from sorb.cli.main import app

    baseline = tmp_path / "base.json"
    res = CliRunner().invoke(app, ["bench", "--iterations", "1", "--no-startup", "--write", str(baseline)])
    assert res.exit_code == 0
    assert "scan" in res.output and baseline.is_file()
