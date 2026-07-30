"""Differential harness vs Syft/Trivy/cdxgen.

Competitor tools are invoked when available on PATH (the scheduled CI job
pins them in containers); otherwise the committed, normalized outputs under
``fixtures/`` are used, so the comparison logic and the triage-ledger gate
run everywhere. Comparison is purl-level; every disagreement must be covered
by a ledger entry (our-fn / their-fp / their-fn / intentional + rationale) — a
new unexplained disagreement fails the scheduled job.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

DIFFERENTIAL_DIR = Path(__file__).parent
LEDGER_PATH = DIFFERENTIAL_DIR / "ledger.json"

TOOLS = {
    "syft": ["syft", "{target}", "-o", "cyclonedx-json"],
    "trivy": ["trivy", "fs", "--format", "cyclonedx", "{target}"],
    "cdxgen": ["cdxgen", "-o", "/dev/stdout", "{target}"],
}


def normalize_purls(cyclonedx_doc: dict) -> set[str]:
    """purl-level normalization: identity comparison only, qualifiers dropped
    (tools disagree wildly on qualifier hygiene, not on identity)."""
    out: set[str] = set()
    for comp in cyclonedx_doc.get("components") or []:
        purl = comp.get("purl")
        if not purl:
            continue
        out.add(str(purl).split("?", 1)[0])
    return out


def run_competitor(tool: str, target: Path) -> dict | None:
    """Invoke a competitor tool if present; None when unavailable."""
    if shutil.which(TOOLS[tool][0]) is None:
        return None
    argv = [a.format(target=str(target)) for a in TOOLS[tool]]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=300, check=False)
        if proc.returncode != 0:
            return None
        doc: dict = json.loads(proc.stdout)
        return doc
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def load_fixture_output(tool: str, target_name: str) -> dict | None:
    """Committed normalized competitor output (offline path)."""
    p = DIFFERENTIAL_DIR / "fixtures" / f"{tool}-{target_name}.cdx.json"
    if not p.is_file():
        return None
    doc: dict = json.loads(p.read_text())
    return doc


@dataclass(frozen=True)
class Disagreement:
    target: str
    tool: str
    kind: str  # "only-ours" | "only-theirs"
    purl: str


@dataclass
class LedgerEntry:
    target: str
    tool: str
    kind: str
    purl: str
    verdict: str  # "our-fn" | "their-fp" | "their-fn" | "intentional"
    rationale: str


def load_ledger(path: Path = LEDGER_PATH) -> list[LedgerEntry]:
    doc = json.loads(path.read_text())
    return [LedgerEntry(**e) for e in doc["entries"]]


@dataclass
class DifferentialReport:
    target: str
    tool: str
    agreements: int = 0
    disagreements: list[Disagreement] = field(default_factory=list)

    def unexplained(self, ledger: list[LedgerEntry]) -> list[Disagreement]:
        covered = {(e.target, e.tool, e.kind, e.purl) for e in ledger}
        return [
            d
            for d in self.disagreements
            if (d.target, d.tool, d.kind, d.purl) not in covered
        ]


def compare(target_name: str, tool: str, ours: set[str], theirs: set[str]) -> DifferentialReport:
    report = DifferentialReport(target=target_name, tool=tool)
    report.agreements = len(ours & theirs)
    for purl in sorted(ours - theirs):
        report.disagreements.append(
            Disagreement(target=target_name, tool=tool, kind="only-ours", purl=purl)
        )
    for purl in sorted(theirs - ours):
        report.disagreements.append(
            Disagreement(target=target_name, tool=tool, kind="only-theirs", purl=purl)
        )
    return report


def refresh_fixtures(target_name: str = "polyglot") -> list[str]:
    """Re-record the committed competitor outputs from tools on PATH.

    Run by the scheduled differential job so the fixtures track the versions it
    pins. Tools that are absent are left alone rather than emptied.
    """
    import sys

    sys.path.insert(0, str(DIFFERENTIAL_DIR.parent / "corpus"))
    from corpus_harness import materialize_fixture  # noqa: PLC0415

    refreshed: list[str] = []
    fixtures = DIFFERENTIAL_DIR / "fixtures"
    fixtures.mkdir(exist_ok=True)
    source = DIFFERENTIAL_DIR.parent / "corpus" / "fixtures" / target_name
    with tempfile.TemporaryDirectory(prefix="sorb-differential-") as tmp:
        scan_dir = materialize_fixture(source, Path(tmp) / target_name)
        for tool in TOOLS:
            doc = run_competitor(tool, scan_dir)
            if doc is None:
                continue
            # keep only identity: the gate compares purls, and full competitor
            # output would make the fixture a moving target
            slim = {
                "components": [
                    {"type": c.get("type", "library"), "name": c.get("name"), "purl": c["purl"]}
                    for c in doc.get("components") or []
                    if c.get("purl")
                ]
            }
            slim["components"].sort(key=lambda c: c["purl"])
            path = fixtures / f"{tool}-{target_name}.cdx.json"
            path.write_text(json.dumps(slim, indent=2) + "\n")
            refreshed.append(str(path))
    return refreshed


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refresh", action="store_true", help="re-record fixtures from tools on PATH"
    )
    parser.add_argument("--target", default="polyglot")
    args = parser.parse_args()
    if args.refresh:
        written = refresh_fixtures(args.target)
        print("\n".join(written) if written else "no competitor tools on PATH — nothing refreshed")
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
