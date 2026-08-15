"""Results workspace & run registry.

``<project>/.sorb/results/<run-id>.sorb.db`` per run; ``index.json`` maps each
subject to its lineage of runs. Identical re-scans reuse the serial and are
recorded as such; changed documents record why they were re-issued
(subject-changed vs tooling-changed).
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class RunRecord:
    run_id: str
    serial: str
    created: str
    reason: str
    detectors_fingerprint: str


def results_dir_for(target: Path | None) -> Path:
    if target is not None and target.is_dir() and os.access(target, os.W_OK):
        return target / ".sorb" / "results"
    return Path.home() / ".sorb" / "results"


def new_run_id() -> str:
    t = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    suffix = os.urandom(3).hex()
    return f"{t}-{suffix}"


def _index_path(results_dir: Path) -> Path:
    return results_dir / "index.json"


def _load_index(results_dir: Path) -> dict[str, Any]:
    p = _index_path(results_dir)
    if p.is_file():
        try:
            loaded: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
            return loaded
        except json.JSONDecodeError:
            pass
    return {"version": 1, "subjects": {}}


def register_run(
    results_dir: Path,
    subject: str,
    run_id: str,
    serial: str,
    detectors_fingerprint: str,
) -> tuple[str, str | None, int]:
    """Record a run in the registry.

    Returns (reissue_reason, superseded_serial, document_version): the
    document version counts *distinct serials* in the subject's lineage
    — an identical re-scan is the same document, same version.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    index = _load_index(results_dir)
    lineage: list[dict[str, Any]] = index["subjects"].setdefault(subject, [])
    reason = "initial"
    superseded: str | None = None
    if lineage:
        last = lineage[-1]
        superseded = last["serial"]
        if last["serial"] == serial:
            reason = "identical (serial reused)"
            superseded = None
        elif last.get("detectors_fingerprint") != detectors_fingerprint:
            reason = "tooling-changed"
        else:
            reason = "subject-changed"
    distinct: list[str] = []
    for entry in lineage:
        if not distinct or distinct[-1] != entry["serial"]:
            distinct.append(str(entry["serial"]))
    if not distinct or distinct[-1] != serial:
        distinct.append(serial)
    doc_version = len(distinct)
    lineage.append(
        {
            "run_id": run_id,
            "serial": serial,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reason": reason,
            "detectors_fingerprint": detectors_fingerprint,
            "doc_version": doc_version,
        }
    )
    _index_path(results_dir).write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return reason, superseded, doc_version


def latest_run_db(results_dir: Path, subject: str | None = None) -> Path | None:
    index = _load_index(results_dir)
    subjects = index.get("subjects", {})
    candidates: list[tuple[str, str]] = []
    for subj, lineage in subjects.items():
        if subject is not None and subj != subject:
            continue
        if lineage:
            candidates.append((lineage[-1]["created"], lineage[-1]["run_id"]))
    if not candidates:
        # fall back to newest .sorb.db file
        if results_dir.is_dir():
            dbs = sorted(results_dir.glob("*.sorb.db"))
            return dbs[-1] if dbs else None
        return None
    candidates.sort()
    db = results_dir / f"{candidates[-1][1]}.sorb.db"
    return db if db.is_file() else None
