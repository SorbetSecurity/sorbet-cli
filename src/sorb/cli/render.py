"""Output rendering and policy evaluation shared by several commands."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:
    from sorb.graph.store import GraphStore

from sorb.errors import UsageError

_FORMATS = (
    "cyclonedx-json",
    "spdx-json",
    "spdx3-json",
    "sorb",
    "table",
    "tree",
    "summary",
)


def _render_outputs(
    store_path: Path | None,
    outputs: list[str],
    files: list[str],
    reproducible: bool,
    store: GraphStore | None = None,
) -> None:
    from sorb.emit.base import emitter_for
    from sorb.emit.cyclonedx import emit_cyclonedx
    from sorb.emit.human import render_summary, render_table, render_tree
    from sorb.emit.native import export_native
    from sorb.emit.spdx import emit_spdx
    from sorb.graph.store import GraphStore

    owns_store = store is None
    if store is None:
        assert store_path is not None
        store = GraphStore.open_readonly(store_path)
    try:
        for i, fmt in enumerate(outputs):
            plugin_emitter = None if fmt in _FORMATS else emitter_for(fmt)
            if fmt not in _FORMATS and plugin_emitter is None:
                raise UsageError(f"unknown output format {fmt!r} (expected one of {', '.join(_FORMATS)})")
            if plugin_emitter is not None:
                data = plugin_emitter.emit(store, reproducible=reproducible)
            elif fmt == "cyclonedx-json":
                data = emit_cyclonedx(store, reproducible=reproducible)
            elif fmt == "spdx-json":
                data = emit_spdx(store, reproducible=reproducible)
            elif fmt == "spdx3-json":
                from sorb.emit.spdx3 import emit_spdx3

                data = emit_spdx3(store, reproducible=reproducible)
            elif fmt == "sorb":
                data = export_native(store)
            elif fmt == "table":
                data = (render_table(store) + "\n").encode()
            elif fmt == "tree":
                data = (render_tree(store) + "\n").encode()
            else:
                data = (render_summary(store) + "\n").encode()
            dest = files[i] if i < len(files) else None
            if dest:
                Path(dest).write_bytes(data)
                suffix = {"cyclonedx-json": "CycloneDX 1.6", "spdx-json": "SPDX 2.3", "sorb": "sorb native"}.get(fmt, fmt)
                typer.echo(f"  {dest} written ({suffix}) · full details: sorb explain", err=True)
            else:
                sys.stdout.write(data.decode("utf-8", "replace"))
    finally:
        if owns_store:
            store.close()


def _policy_failed(store_path: Path, fail_on: tuple[str, ...]) -> bool:
    from sorb.graph.store import GraphStore

    token_map = {
        "drift": ("drift:",),
        "phantom-deps": ("drift:installed-not-declared", "drift:observed-not-declared"),
        "stale-lockfile": ("stale-lockfile",),
        "version-conflict": ("version-conflict",),
        "unidentified": ("unidentified-binaries",),
        "unpinned-images": ("unpinned-image",),
    }
    store = GraphStore.open_readonly(store_path)
    try:
        codes = {a["code"] for a in store.all_annotations()}
        comps_excluded = any(
            c.attrs.get("excluded") for c in store.components()
        )
        for token in fail_on:
            token = token.strip()
            if token == "low-confidence" and comps_excluded:
                return True
            for prefix in token_map.get(token, (token,)):
                if any(c.startswith(prefix) for c in codes):
                    return True
        return False
    finally:
        store.close()


def _print_drift_report(store_path: Path) -> None:
    from sorb.graph.store import GraphStore
    from sorb.warnings import ANNOTATION_WARNING_CODES

    store = GraphStore.open_readonly(store_path)
    try:
        drift = [a for a in store.all_annotations() if a["code"].startswith("drift:")]
        typer.echo("")
        typer.echo(f"Drift report — {len(drift)} finding(s):")
        for a in drift:
            code = ANNOTATION_WARNING_CODES.get(a["code"], "")
            subject = ""
            if a["subject_kind"] == "component":
                comp = store.component_by_id(a["subject_id"])
                subject = comp.display_ref() if comp else ""
            typer.echo(f"  ⚠ [{code}] {a['code']}  {subject}  {a['detail']}")
    finally:
        store.close()
