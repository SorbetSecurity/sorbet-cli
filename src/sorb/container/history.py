"""Layer ⇄ image-history ⇄ Dockerfile linking.

The image config's ``history`` entries map 1:1 onto layers once
``empty_layer`` entries are skipped. When a Dockerfile is provided (or
co-located with the scan), its instructions are cross-linked so
``sorb explain`` can say *"introduced by layer 4 — RUN apt-get install -y
curl (Dockerfile:12)"*.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_NOP_RE = re.compile(r"^/bin/sh -c #\(nop\)\s+")
_SHELL_RE = re.compile(r"^/bin/sh -c ")
_BUILDKIT_SUFFIX = re.compile(r"\s*#\s*buildkit\s*$")

_DOCKERFILE_INSTR = (
    "FROM", "RUN", "CMD", "LABEL", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT",
    "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL",
)


@dataclass(frozen=True, slots=True)
class LayerHistory:
    ordinal: int
    created_by: str  # raw history string ("" when the config carried none)
    command: str  # normalized instruction, e.g. "RUN apt-get install -y curl"
    dockerfile_line: int | None = None


def normalize_created_by(raw: str) -> str:
    """Normalize a history `created_by` into Dockerfile-instruction shape."""
    s = _BUILDKIT_SUFFIX.sub("", raw.strip())
    m = _NOP_RE.match(s)
    if m:
        return s[m.end() :].strip()
    m2 = _SHELL_RE.match(s)
    if m2:
        return f"RUN {s[m2.end():].strip()}"
    return s


def link_history(config: dict[str, Any], n_layers: int) -> list[LayerHistory]:
    """Align non-empty history entries with layer ordinals."""
    out: list[LayerHistory] = []
    ordinal = 0
    for h in config.get("history", []) or []:
        if h.get("empty_layer"):
            continue
        if ordinal >= n_layers:
            break
        raw = str(h.get("created_by", ""))
        out.append(
            LayerHistory(ordinal=ordinal, created_by=raw, command=normalize_created_by(raw))
        )
        ordinal += 1
    while ordinal < n_layers:  # config with fewer history entries than layers
        out.append(LayerHistory(ordinal=ordinal, created_by="", command=""))
        ordinal += 1
    return out


def _dockerfile_instructions(text: str) -> list[tuple[int, str]]:
    """(line, instruction-text) pairs, continuation lines folded in."""
    out: list[tuple[int, str]] = []
    pending: str | None = None
    start_line = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if pending is not None:
            pending += " " + line.rstrip("\\").strip()
            if not line.endswith("\\"):
                out.append((start_line, pending))
                pending = None
            continue
        if not line or line.startswith("#"):
            continue
        word = line.split(None, 1)[0].upper()
        if word in _DOCKERFILE_INSTR:
            if line.endswith("\\"):
                pending = line.rstrip("\\").strip()
                start_line = lineno
            else:
                out.append((lineno, line))
    if pending is not None:
        out.append((start_line, pending))
    return out


def _squeeze(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def link_dockerfile(history: list[LayerHistory], dockerfile_text: str) -> list[LayerHistory]:
    """Cross-link history commands to Dockerfile lines (best-effort, no guessing:
    only exact normalized matches are linked)."""
    instructions = _dockerfile_instructions(dockerfile_text)
    used: set[int] = set()
    linked: list[LayerHistory] = []
    for h in history:
        line: int | None = None
        if h.command:
            want = _squeeze(h.command)
            for lineno, instr in instructions:
                if lineno in used:
                    continue
                if _squeeze(instr) == want:
                    line = lineno
                    used.add(lineno)
                    break
        linked.append(
            LayerHistory(
                ordinal=h.ordinal,
                created_by=h.created_by,
                command=h.command,
                dockerfile_line=line,
            )
        )
    return linked
