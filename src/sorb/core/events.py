"""Progress bus: one typed event stream feeding every renderer —
TTY, NDJSON logs, and (later) the UI's SSE endpoint — so they never disagree.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, dataclass
from typing import Protocol, TextIO


@dataclass(frozen=True, slots=True)
class ScanStarted:
    target: str
    subject: str


@dataclass(frozen=True, slots=True)
class StageProgress:
    stage: str
    detail: str = ""
    count: int = 0


@dataclass(frozen=True, slots=True)
class FindingCount:
    files_walked: int
    findings: int


@dataclass(frozen=True, slots=True)
class WarningRaised:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class StageCompleted:
    stage: str
    duration_s: float
    detail: str = ""


Event = ScanStarted | StageProgress | FindingCount | WarningRaised | StageCompleted


class EventSink(Protocol):
    def __call__(self, event: Event) -> None: ...


class ProgressBus:
    def __init__(self) -> None:
        self._sinks: list[EventSink] = []

    def subscribe(self, sink: EventSink) -> None:
        self._sinks.append(sink)

    def emit(self, event: Event) -> None:
        for sink in self._sinks:
            sink(event)


def ndjson_sink(stream: TextIO | None = None) -> EventSink:
    out = stream or sys.stderr

    def sink(event: Event) -> None:
        payload = {"event": type(event).__name__, "ts": round(time.time(), 3), **asdict(event)}
        out.write(json.dumps(payload, sort_keys=True) + "\n")
        out.flush()

    return sink


def tty_sink(stream: TextIO | None = None) -> EventSink:
    """Minimal live status renderer for TTYs."""
    out = stream or sys.stderr

    def sink(event: Event) -> None:
        if isinstance(event, ScanStarted):
            out.write(f"  Scanning {event.subject}\n")
        elif isinstance(event, StageProgress) and event.detail:
            out.write(f"  {event.detail}\n")
        elif isinstance(event, StageCompleted):
            detail = f" · {event.detail}" if event.detail else ""
            out.write(f"  ✔ {event.stage} ({event.duration_s:.1f}s){detail}\n")
        elif isinstance(event, WarningRaised):
            out.write(f"  ⚠ {event.message} — run `sorb explain-warning {event.code}`\n")
        out.flush()

    return sink
