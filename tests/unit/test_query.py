"""Query DSL parser, safe SQL compilation, and three worked query
examples on the polyglot corpus fixture."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.graph.store import GraphStore
from sorb.query import QueryError, parse_query, run_query
from sorb.query.parser import BoolExpr, Comparison, ComponentsQuery, PathsQuery

# -- parser -----------------------------------------------------------------------------


def test_parse_components_where() -> None:
    q = parse_query('components where purl ~ "pkg:npm/*" and confidence < 0.9')
    assert isinstance(q, ComponentsQuery)
    assert isinstance(q.condition, BoolExpr) and q.condition.op == "and"
    left = q.condition.left
    assert isinstance(left, Comparison) and left.field == "purl" and left.op == "~"
    assert left.value == "pkg:npm/*"


def test_parse_count_by_and_paths() -> None:
    q = parse_query("components where scope = runtime | count by ecosystem")
    assert isinstance(q, ComponentsQuery) and q.count_by == "ecosystem"
    p = parse_query("paths from project:apps/web to pkg:npm/minimist@0.0.8")
    assert isinstance(p, PathsQuery)
    assert p.src == "project:apps/web" and p.dst == "pkg:npm/minimist@0.0.8"
    # `.` names the root project here as it does everywhere else in the CLI
    root = parse_query("paths from . to pkg:npm/lodash@4.17.21")
    assert isinstance(root, PathsQuery) and root.src == "."
    quoted = parse_query('paths from "./apps/web" to pkg:npm/lodash@4.17.21')
    assert isinstance(quoted, PathsQuery) and quoted.src == "./apps/web"


def test_parse_errors_carry_position() -> None:
    with pytest.raises(QueryError) as e:
        parse_query("components where confidence <")
    assert e.value.pos >= 0
    with pytest.raises(QueryError) as e2:
        parse_query("select * from components")  # not our grammar
    assert "components" in str(e2.value)
    with pytest.raises(QueryError):
        parse_query("components where 3 = 4")  # 3 isn't a field


# -- engine over the corpus fixture -----------------------------------------------------


@pytest.fixture()
def scanned(tmp_path: Path):
    fixture = Path(__file__).parent.parent / "corpus" / "fixtures" / "polyglot"
    proj = tmp_path / "polyglot"
    shutil.copytree(fixture, proj, ignore=shutil.ignore_patterns(".sorb"))
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(proj), cfg, store_path=tmp_path / "run.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    yield store
    store.close()


def test_example_1_glob_and_confidence(scanned) -> None:
    """Glob filter + confidence threshold on components."""
    result = run_query(scanned, 'components where purl ~ "pkg:npm/*" and confidence < 0.9')
    assert result.kind == "components"
    assert result.rows, "npm components with confidence < 0.9 exist in the fixture"
    for row in result.rows:
        assert row["purl"].startswith("pkg:npm/")
        assert row["confidence"] < 0.9


def test_example_3_count_by(scanned) -> None:
    """Count-by aggregation."""
    result = run_query(scanned, "components where scope = runtime | count by ecosystem")
    assert result.kind == "aggregation"
    buckets = {r["ecosystem"]: r["count"] for r in result.rows}
    assert buckets  # at least one runtime ecosystem
    assert all(isinstance(v, int) and v > 0 for v in buckets.values())


def test_example_2_paths(scanned) -> None:
    """Paths from a project to a package."""
    result = run_query(scanned, "paths from project:apps/web to pkg:npm/lodash@4.17.21")
    assert result.kind == "paths"
    assert result.rows, "there is a path from apps/web to lodash"
    for row in result.rows:
        assert row["path"][0]["kind"] in ("project", "source")


def test_tier_name_query(scanned) -> None:
    result = run_query(scanned, "components where tier = installed")
    assert result.rows and all(r["tier"] == "installed" for r in result.rows)


def test_injection_is_parameterized(scanned) -> None:
    """A quoted string that looks like SQL injection matches nothing and does
    no harm — it is bound as a literal, never interpolated."""
    before = len(run_query(scanned, "components").rows)
    malicious = "components where name = \"'; DROP TABLE components; --\""
    result = run_query(scanned, malicious)
    assert result.rows == []  # no component is literally named that
    after = len(run_query(scanned, "components").rows)
    assert after == before  # the table still exists, untouched


def test_unknown_field_errors(scanned) -> None:
    with pytest.raises(QueryError, match="unknown field"):
        run_query(scanned, "components where nonsense_field = 1")


def test_cli_query(scanned, tmp_path, monkeypatch) -> None:
    from typer.testing import CliRunner

    from sorb.cli.main import app

    runner = CliRunner()
    # point the CLI at the scanned db directly
    db = [p for p in tmp_path.glob("*.sorb.db")][0]
    res = runner.invoke(app, ["query", "components where scope = runtime | count by ecosystem",
                              "--run", str(db)])
    assert res.exit_code == 0, res.output
    assert "ecosystem" in res.output and "count" in res.output
    bad = runner.invoke(app, ["query", "components where x <", "--run", str(db)])
    assert bad.exit_code == 3  # usage error, position-annotated
