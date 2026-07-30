"""sorb Python import-hook.

Shipped as data and injected by placing its directory on ``PYTHONPATH`` (so
Python runs it as ``sitecustomize`` at startup, no privileges needed). It
installs a ``sys.meta_path`` finder that observes every imported top-level
module, maps it back to its installed distribution via
``importlib.metadata.packages_distributions``, and appends one NDJSON record
per newly-seen distribution to the file named by ``$SORB_TRACE_OUT``.
"""

from __future__ import annotations

import json
import os
import sys


def _install() -> None:
    out_path = os.environ.get("SORB_TRACE_OUT")
    if not out_path:
        return
    try:
        import importlib.metadata as im
    except ImportError:  # pragma: no cover
        return

    try:
        module_to_dists = im.packages_distributions()
    except Exception:  # noqa: BLE001 — never break the traced program
        module_to_dists = {}

    seen: set[str] = set()

    def record(top: str) -> None:
        for dist in module_to_dists.get(top, ()):  # type: ignore[union-attr]
            if dist in seen:
                continue
            seen.add(dist)
            try:
                version = im.version(dist)
            except Exception:  # noqa: BLE001
                version = ""
            try:
                with open(out_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "technique": "python-import-hook",
                        "kind": "module",
                        "identifier": dist,
                        "detail": version,
                        "ecosystem": "pypi",
                    }) + "\n")
            except OSError:
                pass

    class _Finder:
        def find_module(self, fullname, path=None):  # noqa: ANN001 — legacy protocol shim
            return None

        def find_spec(self, fullname, path=None, target=None):  # noqa: ANN001
            if "." not in fullname:
                record(fullname)
            return None

    # record already-imported top-level modules, then watch new ones
    for name in list(sys.modules):
        if "." not in name:
            record(name)
    sys.meta_path.insert(0, _Finder())


_install()
