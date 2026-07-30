"""Golden-corpus harness.

Targets come from ``manifest.json``: local fixture trees now; remote targets
(fetched and pinned by digest, never committed) join as the corpus grows.
For every target the harness scans, compares against ``expected.json`` ground
truth, and computes precision / recall / metadata-completeness — overall and
per detector. The CI gate consumes the report; thresholds start advisory and
flip to blocking when the corpus reaches size (see ``GATE``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).parent

#: gate thresholds — seed values, re-measured as the corpus grows
#: (advisory below `blocking_at_targets`). Completeness sits at
#: 0.85 while fixtures deliberately include unresolved declared-only
#: components (honesty rule: no version is better than a guessed one).
GATE = {"precision": 0.98, "recall": 0.95, "completeness": 0.85, "blocking_at_targets": 10}


@dataclass
class TargetReport:
    name: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    completeness: float = 1.0
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    per_detector: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0


@dataclass
class CorpusReport:
    targets: list[TargetReport] = field(default_factory=list)

    @property
    def precision(self) -> float:
        tp = sum(t.tp for t in self.targets)
        fp = sum(t.fp for t in self.targets)
        return tp / (tp + fp) if (tp + fp) else 1.0

    @property
    def recall(self) -> float:
        tp = sum(t.tp for t in self.targets)
        fn = sum(t.fn for t in self.targets)
        return tp / (tp + fn) if (tp + fn) else 1.0

    @property
    def completeness(self) -> float:
        if not self.targets:
            return 1.0
        return sum(t.completeness for t in self.targets) / len(self.targets)

    def gate_failures(self) -> list[str]:
        failures = []
        if self.precision < GATE["precision"]:
            failures.append(f"precision {self.precision:.4f} < {GATE['precision']}")
        if self.recall < GATE["recall"]:
            failures.append(f"recall {self.recall:.4f} < {GATE['recall']}")
        if self.completeness < GATE["completeness"]:
            failures.append(f"metadata completeness {self.completeness:.4f} < {GATE['completeness']}")
        return failures

    @property
    def advisory(self) -> bool:
        return len(self.targets) < int(GATE["blocking_at_targets"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "completeness": round(self.completeness, 4),
            "advisory": self.advisory,
            "gate_failures": self.gate_failures(),
            "targets": [
                {
                    "name": t.name,
                    "precision": round(t.precision, 4),
                    "recall": round(t.recall, 4),
                    "completeness": round(t.completeness, 4),
                    "missing": t.missing,
                    "unexpected": t.unexpected,
                    "per_detector": t.per_detector,
                }
                for t in self.targets
            ],
        }


def _component_key(name: str, version: str | None) -> str:
    return f"{name}@{version or '?'}"


#: Fixture trees deliberately contain gitignored paths (a `.gitignore`, installed
#: `node_modules`/`.venv` state). They are stored under these neutral names so a
#: plain `git add` tracks them, and renamed into place when a pristine copy is
#: materialized for a scan.
_STORAGE_NAMES = {"gitignore": ".gitignore", "_node_modules": "node_modules", "_venv": ".venv"}


def materialize_fixture(src: Path, dst: Path) -> Path:
    """Copy a fixture tree to ``dst``, restoring the gitignored path names."""
    import shutil

    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".sorb"))
    stored = [p for p in dst.rglob("*") if p.name in _STORAGE_NAMES]
    for p in sorted(stored, key=lambda p: len(p.parts), reverse=True):
        p.rename(p.with_name(_STORAGE_NAMES[p.name]))
    return dst


def evaluate_target(name: str, target_dir: Path, expected_file: Path, work_dir: Path) -> TargetReport:
    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan
    from sorb.graph.store import GraphStore

    expected = json.loads(expected_file.read_text())
    want = {
        _component_key(e["name"], e.get("version")) for e in expected["components"]
    }
    # scan a pristine copy: fixtures in-repo must never grow .sorb workspaces
    scan_dir = work_dir / f"target-{name}"
    materialize_fixture(target_dir, scan_dir)
    cfg = load_config(flags={}, env={}, user_config_path=work_dir / "no-config.toml")
    result = run_scan(str(scan_dir), cfg, store_path=work_dir / f"{name}.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    report = TargetReport(name=name)
    try:
        emitted = list(store.components())  # expected.json is authored over the full set
        got: dict[str, Any] = {}
        complete = 0
        for c in emitted:
            key = _component_key(c.name, c.version)
            got[key] = c
            evidence = store.evidence_for_component(c.id)
            detectors = {str(e["detector"]) for e in evidence}
            hit = key in want
            for d in detectors:
                slot = report.per_detector.setdefault(d, {"tp": 0, "fp": 0})
                slot["tp" if hit else "fp"] += 1
            if c.version and evidence and (c.purl or c.attrs.get("ecosystem")):
                complete += 1
        report.completeness = complete / len(emitted) if emitted else 1.0
        report.tp = len(want & got.keys())
        report.fp = len(got.keys() - want)
        report.fn = len(want - got.keys())
        report.missing = sorted(want - got.keys())
        report.unexpected = sorted(got.keys() - want)
    finally:
        store.close()
    return report


def run_corpus(manifest_path: Path, work_dir: Path) -> CorpusReport:
    manifest = json.loads(manifest_path.read_text())
    report = CorpusReport()
    for target in manifest["targets"]:
        target_dir = CORPUS_DIR / target["path"]
        expected = CORPUS_DIR / target["expected"]
        report.targets.append(
            evaluate_target(str(target["name"]), target_dir, expected, work_dir)
        )
    return report
