"""Trace runner: inject hooks + run a file-trace backend.

Combines the privilege-free interpreter hooks (Python/Node) with the platform
file-trace backend, collects both streams of observations, and returns a
``TraceResult`` for the mapper. The hooks write NDJSON to a shared
``SORB_TRACE_OUT`` file; the backend parses its own syscall stream.
"""

from __future__ import annotations

import json
import os
import tempfile
from importlib import resources
from pathlib import Path

from sorb.dynamic.trace.backends import FileTraceBackend, backend_chain, select_backend
from sorb.dynamic.trace.model import Observation, TraceResult


def _hooks_dir() -> Path:
    return Path(str(resources.files("sorb.dynamic.trace") / "hooks"))


def available_backends() -> list[tuple[str, bool, str]]:
    """(id, available, reason) for every backend in the platform chain."""
    out = []
    for backend in backend_chain():
        ok, reason = backend.available()
        out.append((backend.id, ok, reason))
    return out


def _inject_hooks(env: dict[str, str], out_file: str) -> list[str]:
    """Wire the interpreter hooks into the child's environment. Returns the
    hook ids that were armed."""
    hooks_dir = _hooks_dir()
    env["SORB_TRACE_OUT"] = out_file
    armed: list[str] = []

    # Python: sitecustomize via PYTHONPATH
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(hooks_dir) + (os.pathsep + existing if existing else "")
    armed.append("python-import-hook")

    # Node: --require probe via NODE_OPTIONS
    node_probe = hooks_dir / "node_probe.cjs"
    if node_probe.exists():
        node_opts = env.get("NODE_OPTIONS", "")
        env["NODE_OPTIONS"] = (f"--require {node_probe} " + node_opts).strip()
        armed.append("node-require-probe")

    return armed


def run_trace(
    command: list[str],
    *,
    backend: FileTraceBackend | None = None,
    env: dict[str, str] | None = None,
) -> TraceResult:
    """Run `command` with interpreter hooks + a file-trace backend."""
    if not command:
        raise ValueError("nothing to trace: empty command")
    child_env = dict(os.environ if env is None else env)
    backend = backend or select_backend()

    with tempfile.TemporaryDirectory(prefix="sorb-trace-") as tmp:
        out_file = os.path.join(tmp, "observations.ndjson")
        Path(out_file).touch()
        armed = _inject_hooks(child_env, out_file)

        exit_code, file_obs = backend.run(command, child_env)

        hook_obs: list[Observation] = []
        for line in Path(out_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            hook_obs.append(
                Observation(
                    technique=str(rec.get("technique", "interpreter-hook")),
                    kind=str(rec.get("kind", "module")),
                    identifier=str(rec.get("identifier", "")),
                    detail=str(rec.get("detail", "")),
                    ecosystem=rec.get("ecosystem"),
                )
            )

    # dedup by (technique, kind, identifier)
    merged: dict[tuple[str, str, str], Observation] = {}
    for obs in [*hook_obs, *file_obs]:
        merged.setdefault((obs.technique, obs.kind, obs.identifier), obs)

    return TraceResult(
        command=command,
        exit_code=exit_code,
        backend=backend.id,
        hooks=armed,
        observations=list(merged.values()),
    )
