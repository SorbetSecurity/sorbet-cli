"""Post-walk augmentation for live-host scans.

Orchestration lives in `sorb.core` (L2) because it drives the `ProgressBus` and
`Config`; the actual host-domain readers it calls — container sub-target
discovery and `/proc` runtime observation — live in `sorb.host` (L3, invoked
downward). Runs after reconcile, when components exist. Both jobs are read-only
and offline.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from sorb.core.events import ProgressBus, StageCompleted
from sorb.graph.store import GraphStore

if TYPE_CHECKING:
    from sorb.core.config import Config
    from sorb.source.host import LiveHostSource


def augment_host(
    store: GraphStore, source: LiveHostSource, config: Config, bus: ProgressBus
) -> None:
    root = source.host_root

    # -- container sub-targets ------------------------------------------------
    from sorb.host.containers import discover_subtargets

    subs = discover_subtargets(root)
    if subs:
        store.set_meta(
            "subtargets",
            json.dumps([{"kind": s.kind, "ref": s.ref, "runtime": s.runtime,
                         "detail": s.detail} for s in subs]),
        )
        for s in subs:
            store.add_annotation(
                "run", 0, "container-subtarget",
                f"{s.runtime} {s.kind}: {s.ref}" + (f" ({s.detail})" if s.detail else ""),
            )
        bus.emit(StageCompleted(
            stage="host-discovery", duration_s=0.0,
            detail=f"{len(subs)} container sub-target(s) — scan with `sorb scan <ref>`",
        ))

    # -- runtime observation --------------------------------------------------
    from sorb.host.runtime import observe_runtime

    n_obs, n_sock = observe_runtime(store, root, source.root().id)
    store.commit()
    if n_obs or n_sock:
        bus.emit(StageCompleted(
            stage="runtime", duration_s=0.0,
            detail=f"{n_obs} component(s) observed running, {n_sock} listening socket(s) mapped",
        ))
