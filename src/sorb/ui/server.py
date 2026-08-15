"""Embedded Graph API + SPA host.

FastAPI application factory. Every read endpoint opens its own **read-only**
SQLite connection (WAL) and closes it — stateless, safe to run while a scan
writes the same store. `fastapi`/`uvicorn`/`starlette` are imported here (and only
here) so the base CLI keeps its <300 ms startup budget: this
module is imported lazily from `sorb ui` / `sorb serve`.

Security lives in one middleware: bearer-token auth + Host/Origin
validation (DNS-rebinding defense). The static SPA is served under a strict CSP
that forbids every external origin, so the promise of an offline, air-gapped
explorer is structurally enforced, not merely intended.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from importlib import resources
from pathlib import Path
from typing import Any

# NOTE: fastapi/starlette are imported at module top *deliberately* — this module
# is itself imported lazily (only from `sorb ui` / `sorb serve`), so it never runs
# during normal CLI startup and the <300 ms budget is preserved. The
# imports must be at module scope so FastAPI can resolve the `Request`/`Response`
# annotations on the route handlers (which `from __future__ import annotations`
# turns into forward references it looks up in this module's globals).
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from starlette.middleware.base import BaseHTTPMiddleware

from sorb.core.events import ProgressBus
from sorb.graph.store import GraphStore
from sorb.ui.config import ServerConfig
from sorb.ui.sse import EventStream

_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "worker-src 'self' blob:; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "object-src 'none'"
)


class ServerState:
    """Shared, request-independent server state."""

    def __init__(self, config: ServerConfig, bus: ProgressBus | None = None) -> None:
        self.config = config
        self.bus = bus or ProgressBus()
        self.events: EventStream | None = None
        self.port = config.port
        self.scan_status = "idle"  # idle | scanning | done | error
        self.results_dir = config.results_dir or _default_results_dir(config)
        #: set by `sorb.ui.runner`, which owns the scan config and the worker
        #: thread; absent when the app is created without a runner.
        self.scan_launcher: Callable[[str], None] | None = None
        self._current_db: Path | None = None
        if config.run and (config.run.endswith(".sorb.db")):
            self._current_db = Path(config.run)

    # -- run resolution -----------------------------------------------------

    def set_current_db(self, path: Path) -> None:
        self._current_db = path

    def allowed_hosts(self) -> set[str]:
        return self.config.allowed_hosts(self.port)

    def db_for(self, run_id: str) -> Path | None:
        if run_id in ("current", "latest"):
            if self._current_db and self._current_db.is_file():
                return self._current_db
            from sorb.core.workspace import latest_run_db

            return latest_run_db(self.results_dir)
        candidate = self.results_dir / f"{run_id}.sorb.db"
        if candidate.is_file():
            return candidate
        if self._current_db and run_id in (self._current_db.stem, self._current_db.name):
            return self._current_db
        return None

    def open(self, run_id: str) -> GraphStore:
        db = self.db_for(run_id)
        if db is None:
            raise HTTPException(status_code=404, detail=f"no such run: {run_id}")
        return GraphStore.open_readonly(db)


def _default_results_dir(config: ServerConfig) -> Path:
    from sorb.core.workspace import results_dir_for

    target = Path(config.target).resolve() if config.target else Path.cwd()
    return results_dir_for(target)


def create_app(config: ServerConfig, *, bus: ProgressBus | None = None) -> FastAPI:
    """Build the FastAPI app for a validated `ServerConfig`."""
    state = ServerState(config, bus)
    app = FastAPI(title="sorbet graph API", version="0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.sorb = state

    # -- security middleware: Host/Origin + bearer token ---------------------

    class SecurityMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: Any) -> Response:
            host = (request.headers.get("host") or "").lower()
            allowed = {h.lower() for h in state.allowed_hosts()}
            bare = host.split(":", 1)[0]
            if host and host not in allowed and bare not in allowed:
                return PlainTextResponse("Host not allowed (DNS-rebinding defense)", status_code=400)
            origin = request.headers.get("origin")
            if origin is not None:
                o = origin.split("//", 1)[-1].lower()
                if o not in allowed and o.split(":", 1)[0] not in allowed:
                    return PlainTextResponse("Origin not allowed", status_code=403)

            token = _extract_token(request)
            authed = not config.require_token or (
                token is not None and secrets.compare_digest(token, config.token)
            )
            if not authed:
                return PlainTextResponse("missing or invalid session token", status_code=401)

            response: Response = await call_next(request)
            response.headers["Content-Security-Policy"] = _CSP
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Frame-Options"] = "DENY"
            # If a valid token arrived by query param, pin it as a cookie so
            # subsequent asset/API loads authenticate without re-passing it.
            query_token = request.query_params.get("token")
            if (
                config.require_token
                and query_token is not None
                and secrets.compare_digest(query_token, config.token)
            ):
                response.set_cookie(
                    "sorb_token", config.token, httponly=True, samesite="strict", path="/"
                )
            return response

    app.add_middleware(SecurityMiddleware)

    _register_api(app, state)
    _register_spa(app, state)
    return app


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:].strip()
    q = request.query_params.get("token")
    if q:
        return q
    return request.cookies.get("sorb_token")


# -- API routes -------------------------------------------------------------------------


def _register_api(app: FastAPI, state: ServerState) -> None:
    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "scan_status": state.scan_status}

    @app.get("/api/runs")
    def list_runs() -> dict[str, Any]:
        return {"runs": _runs_index(state)}

    @app.get("/api/runs/{run_id}")
    def run_summary(run_id: str) -> dict[str, Any]:
        store = state.open(run_id)
        try:
            counters = store.counters()
            return {
                "run": run_id,
                "counters": counters,
                "serial": store.get_meta("content_serial"),
                "layers": len(store.layers()),
                "annotations": len(store.all_annotations()),
            }
        finally:
            store.close()

    @app.get("/api/runs/{run_id}/components")
    def components(run_id: str, filter: str | None = None, cursor: str | None = None,
                   limit: int = 200) -> dict[str, Any]:
        from sorb.query import QueryError, run_query

        store = state.open(run_id)
        try:
            expr = filter or "components"
            if not expr.strip().startswith(("components", "paths")):
                expr = f"components where {expr}"
            try:
                result = run_query(store, expr)
            except QueryError as e:
                raise HTTPException(status_code=400, detail=str(e)) from e
            rows = result.rows
            offset = _decode_cursor(cursor)
            limit = max(1, min(limit, 1000))
            page = rows[offset : offset + limit]
            next_cursor = _encode_cursor(offset + limit) if offset + limit < len(rows) else None
            return {
                "kind": result.kind,
                "columns": result.columns,
                "total": len(rows),
                "rows": page,
                "cursor": next_cursor,
            }
        finally:
            store.close()

    @app.get("/api/runs/{run_id}/component/{key:path}")
    def component_detail(run_id: str, key: str) -> dict[str, Any]:
        store = state.open(run_id)
        try:
            comp = None
            matches = store.find_component(key)
            if matches:
                comp = matches[0]
            elif key.isdigit():
                comp = store.component_by_id(int(key))
            if comp is None:
                raise HTTPException(status_code=404, detail=f"no component: {key}")
            return _component_detail_json(store, comp.id)
        finally:
            store.close()

    @app.get("/api/runs/{run_id}/explain")
    def explain_endpoint(run_id: str, ref: str) -> dict[str, Any]:
        from sorb.core.explain import explain

        store = state.open(run_id)
        try:
            text = explain(store, ref)
            if text is None:
                raise HTTPException(status_code=404, detail=f"no component matches {ref!r}")
            comps = store.find_component(ref)
            return {
                "ref": ref,
                "text": text,  # byte-for-byte the CLI `explain` output (parity)
                "components": [_component_detail_json(store, c.id) for c in comps[:5]],
            }
        finally:
            store.close()

    @app.get("/api/runs/{run_id}/deps")
    def deps_endpoint(
        run_id: str, node: str = "root", budget: int = 500, dir: str = "down"  # noqa: A002 — query param name
    ) -> dict[str, Any]:
        from sorb.ui.lod import deps

        if node != "root" and not node.isdigit():
            raise HTTPException(status_code=400, detail="node must be 'root' or a component id")
        if dir not in ("down", "up"):
            raise HTTPException(status_code=400, detail="dir must be 'down' or 'up'")
        store = state.open(run_id)
        try:
            return deps(
                store, node=node, node_budget=max(1, min(budget, 5000)), direction=dir
            ).to_dict()
        finally:
            store.close()

    @app.get("/api/runs/{run_id}/lod")
    def lod_endpoint(run_id: str, cluster: str = "ecosystem", expand: str | None = None,
                     budget: int = 2000) -> dict[str, Any]:
        from sorb.ui.lod import lod

        store = state.open(run_id)
        try:
            resp = lod(store, cluster_by=cluster, expand=expand, node_budget=max(1, min(budget, 20000)))
            return resp.to_dict()
        finally:
            store.close()

    @app.get("/api/runs/{run_id}/layers")
    def layers_endpoint(run_id: str) -> dict[str, Any]:
        store = state.open(run_id)
        try:
            return _layers_json(store)
        finally:
            store.close()

    @app.get("/api/runs/{run_id}/drift")
    def drift_endpoint(run_id: str) -> dict[str, Any]:
        store = state.open(run_id)
        try:
            return _drift_json(store)
        finally:
            store.close()

    @app.get("/api/runs/{run_id}/fleet")
    def fleet_endpoint(run_id: str) -> dict[str, Any]:
        store = state.open(run_id)
        try:
            return _fleet_json(store)
        finally:
            store.close()

    @app.get("/api/diff")
    def diff_endpoint(a: str, b: str) -> dict[str, Any]:
        from sorb.core.diff import diff_stores

        store_a, store_b = state.open(a), state.open(b)
        try:
            return _diff_json(diff_stores(store_a, store_b), a, b)
        finally:
            store_a.close()
            store_b.close()

    @app.post("/api/query")
    async def query_endpoint(request: Request) -> dict[str, Any]:
        from sorb.query import QueryError, run_query

        body = await request.json()
        expr = str(body.get("query", ""))
        run_id = str(body.get("run", "current"))
        store = state.open(run_id)
        try:
            result = run_query(store, expr)
        except QueryError as e:
            raise HTTPException(status_code=400, detail={"message": str(e), "pos": e.pos}) from e
        finally:
            store.close()
        return {"kind": result.kind, "columns": result.columns, "rows": result.rows}

    @app.post("/api/export", response_model=None)
    async def export_endpoint(request: Request) -> Response:
        from sorb.ui.export import export_sbom, selection_from_query

        body = await request.json()
        fmt = str(body.get("format", "cyclonedx"))
        run_id = str(body.get("run", "current"))
        db = state.db_for(run_id)
        if db is None:
            raise HTTPException(status_code=404, detail=f"no such run: {run_id}")
        ids = body.get("component_ids")
        if ids is None and body.get("query"):
            ids = selection_from_query(db, str(body["query"]))
        try:
            payload, media_type, filename = export_sbom(
                db, fmt, component_ids=ids,
                include_excluded=bool(body.get("include_excluded")),
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return Response(
            content=payload, media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # -- project corrections: false positives & missing components -----------

    def _corrections_root() -> Path | None:
        t = state.config.target
        if t and Path(t).is_dir():
            return Path(t).resolve()
        return None

    @app.get("/api/corrections")
    def corrections_get() -> dict[str, Any]:
        from sorb.core.corrections import corrections_path, load_corrections

        root = _corrections_root()
        if root is None:
            return {"enabled": False, "corrections": []}
        return {
            "enabled": True,
            "path": str(corrections_path(root)),
            "corrections": [e.to_dict() for e in load_corrections(root)],
        }

    @app.post("/api/corrections")
    async def corrections_post(request: Request) -> dict[str, Any]:
        from sorb.core.corrections import (
            KINDS,
            Correction,
            add_correction,
            remove_correction,
        )

        root = _corrections_root()
        if root is None:
            raise HTTPException(
                status_code=400,
                detail="no project open — corrections need a project directory "
                "(serve with `sorb ui <target-dir>`)",
            )
        body = await request.json()
        op = str(body.get("op", "add"))
        kind = str(body.get("kind", ""))
        ref = str(body.get("ref", "")).strip()
        if kind not in KINDS or not ref:
            raise HTTPException(status_code=400, detail=f"kind must be one of {KINDS}, ref required")
        if op == "remove":
            changed = remove_correction(root, kind, ref)
        elif op == "add":
            changed = add_correction(root, Correction(
                kind=kind, ref=ref, reason=str(body.get("reason", "")),
                ecosystem=str(body.get("ecosystem", "")), scope=str(body.get("scope", "")),
            ))
        else:
            raise HTTPException(status_code=400, detail="op must be add or remove")
        return {"changed": changed, **corrections_get()}

    @app.get("/api/events", response_model=None)
    async def events_endpoint() -> StreamingResponse:
        if state.events is None:
            state.events = EventStream(state.bus)
        stream = state.events

        async def gen() -> Any:
            async for chunk in stream.subscribe():
                yield chunk

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.post("/api/scan")
    async def scan_endpoint(request: Request) -> dict[str, Any]:
        if not state.config.allow_scan:
            raise HTTPException(status_code=403, detail="scanning disabled — start with --allow-scan")
        body = await request.json()
        target = str(body.get("target", ""))
        if not target or "://" in target and not target.startswith(("image:", "oci:", "dir:")):
            raise HTTPException(status_code=400, detail="only local targets may be scanned")
        if state.scan_launcher is None:
            raise HTTPException(
                status_code=503,
                detail="this server cannot start scans — launch it with `sorb ui` or `sorb serve`",
            )
        if state.scan_status == "scanning":
            raise HTTPException(status_code=409, detail="a scan is already running")
        state.scan_status = "scanning"
        try:
            state.scan_launcher(target)
        except Exception as e:
            state.scan_status = "error"
            raise HTTPException(status_code=500, detail=f"could not start scan: {e}") from e
        return {"accepted": True, "target": target, "events": "/api/events"}


# -- SPA (static assets) ----------------------------------------------------------------


def _register_spa(app: FastAPI, state: ServerState) -> None:
    assets = resources.files("sorb.ui") / "assets"

    _MEDIA_BY_SUFFIX = {
        ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".json": "application/json",
        ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2",
        ".map": "application/json", ".ico": "image/x-icon",
    }

    def _read_index() -> str:
        index = assets / "index.html"
        if index.is_file():
            return index.read_text(encoding="utf-8")
        return _FALLBACK_INDEX

    @app.get("/", response_class=HTMLResponse, response_model=None)
    def spa_root() -> HTMLResponse:
        return HTMLResponse(_read_index())

    @app.get("/assets/{path:path}", response_model=None)
    def spa_assets(path: str) -> Response:
        if ".." in path or path.startswith("/"):
            raise HTTPException(status_code=404, detail="not found")
        target = assets / path
        if not target.is_file():
            raise HTTPException(status_code=404, detail="not found")
        suffix = Path(path).suffix.lower()
        media = _MEDIA_BY_SUFFIX.get(suffix, "application/octet-stream")
        return Response(content=target.read_bytes(), media_type=media)


# -- JSON shaping (shared, so /explain parity + inspector agree) ------------------------


def _component_detail_json(store: GraphStore, cid: int) -> dict[str, Any]:
    detail = store.component_detail(cid)
    if detail is None:
        return {}
    c = detail.component
    paths = store.paths_to_roots(cid)
    return {
        "id": c.id,
        "ref": c.display_ref(),
        "purl": c.purl,
        "name": c.name,
        "version": c.version,
        "ctype": c.ctype,
        "tier": c.tier.label,
        "confidence": round(c.confidence, 4),
        "qualifiers": c.qualifiers,
        "hashes": c.hashes,
        "attrs": c.attrs,
        "evidence": detail.evidence,
        "annotations": detail.annotations,
        "paths": [
            [
                {"kind": s.kind, "label": s.label, "component_id": s.component_id,
                 "edge_attrs": s.edge_attrs}
                for s in path
            ]
            for path in paths
        ],
    }


def _layers_json(store: GraphStore) -> dict[str, Any]:
    """Per-layer stack: churn, components introduced, and base-image origin.

    Counted in one pass: file states are read once for the whole image, not
    once per layer.
    """
    from collections import Counter

    added: Counter[str] = Counter()
    removed: Counter[str] = Counter()
    modified: Counter[str] = Counter()
    for f in store.file_states(None):
        bucket = {"added": added, "removed": removed, "modified": modified}.get(f["state"])
        if bucket is not None:
            bucket[str(f["layer_digest"])] += 1

    comps: Counter[int] = Counter()
    from_base: Counter[int] = Counter()
    for c in store.components():
        if c.attrs.get("excluded"):
            continue
        ordinal = c.attrs.get("layer_ordinal")
        if ordinal is None:
            continue
        comps[int(ordinal)] += 1
        if c.attrs.get("from_base_image"):
            from_base[int(ordinal)] += 1

    out = []
    for layer in store.layers():
        digest, ordinal = str(layer["digest"]), int(layer["ordinal"])
        out.append({
            "digest": digest,
            "ordinal": ordinal,
            "created_by": layer["created_by"],
            "added": added[digest],
            "modified": modified[digest],
            "removed": removed[digest],
            "components": comps[ordinal],
            "from_base_image": from_base[ordinal] > 0,
        })
    return {"layers": out}


#: drift/findings annotation codes → human category (findings board)
_DRIFT_CODES = {
    "drift:declared-not-installed": "phantom / declared-not-installed",
    "drift:installed-not-declared": "unaccounted installed",
    "drift:locked-vs-installed": "lock ≠ installed",
    "drift:observed-not-declared": "observed but undeclared",
    "declared-never-observed": "declared, never observed",
    "stale-lockfile": "stale lockfile",
    "version-conflict": "version conflict",
    "unpinned-image": "unpinned image",
    "drift:dockerfile-vs-image": "dockerfile ≠ image",
    "weak-crypto": "weak crypto",
    "ml-pickle-risk": "ML pickle risk",
    "private-key-present": "private key present",
}


def _drift_json(store: GraphStore) -> dict[str, Any]:
    by_id = {c.id: c for c in store.components()}
    groups: dict[str, list[dict[str, Any]]] = {}
    for a in store.all_annotations():
        code = a["code"]
        if code not in _DRIFT_CODES:
            continue
        subject = ""
        if a["subject_kind"] == "component":
            comp = by_id.get(int(a["subject_id"]))
            subject = comp.display_ref() if comp else f"component#{a['subject_id']}"
        groups.setdefault(code, []).append({
            "subject": subject, "detail": a["detail"],
            "component_id": a["subject_id"] if a["subject_kind"] == "component" else None,
        })
    findings = [
        {"code": code, "category": _DRIFT_CODES[code], "count": len(items), "items": items}
        for code, items in sorted(groups.items(), key=lambda kv: -len(kv[1]))
    ]
    return {"findings": findings, "total": sum(len(g) for g in groups.values())}


def _fleet_json(store: GraphStore) -> dict[str, Any]:
    """Per-host rollup from a fleet store's `seen_in` provenance."""
    import json as _json

    hosts: dict[str, dict[str, Any]] = {}
    observed_components = 0
    skew: dict[str, dict[str, set[str]]] = {}
    for c in store.components():
        if c.attrs.get("excluded"):
            continue
        seen = _json.loads(c.attrs.get("seen_in", "[]")) if c.attrs.get("seen_in") else []
        if c.attrs.get("observed") == "true":
            observed_components += 1
        is_pkg = c.attrs.get("ecosystem") != "crypto"
        for entry in seen:
            src = entry.get("source", "?")
            h = hosts.setdefault(src, {"host": src, "components": 0, "observed": 0})
            h["components"] += 1
            if entry.get("observed"):
                h["observed"] += 1
            if is_pkg and c.version:
                skew.setdefault(c.name, {}).setdefault(src, set()).add(c.version)
    version_skew = []
    for name, per in sorted(skew.items()):
        if len({v for vs in per.values() for v in vs}) > 1:
            version_skew.append({"name": name,
                                 "versions": {s: sorted(vs) for s, vs in per.items()}})
    return {
        "is_fleet": bool(store.get_meta("fleet_sources")),
        "sources": _json.loads(store.get_meta("fleet_sources") or "[]"),
        "hosts": sorted(hosts.values(), key=lambda h: -h["components"]),
        "observed_components": observed_components,
        "version_skew": version_skew[:100],
        "version_skew_total": len(version_skew),
    }


def _diff_json(result: Any, a: str, b: str) -> dict[str, Any]:
    return {
        "a": a, "b": b, "empty": result.empty,
        "added": [{"name": n, "version": v, "ecosystem": e} for n, v, e in result.added],
        "removed": [{"name": n, "version": v, "ecosystem": e} for n, v, e in result.removed],
        "version_changes": [
            {"name": ch.name, "from": ch.old, "to": ch.new, "direction": ch.direction}
            for ch in result.version_changes
        ],
        "layers_added": result.layers_added,
        "layers_removed": result.layers_removed,
    }


def _runs_index(state: ServerState) -> list[dict[str, Any]]:
    from sorb.core.workspace import _load_index  # noqa: PLC2701 — internal reader, read-only

    runs: list[dict[str, Any]] = []
    index = _load_index(state.results_dir)
    for subject, lineage in index.get("subjects", {}).items():
        for entry in lineage:
            runs.append({
                "run": entry["run_id"], "subject": subject, "serial": entry.get("serial"),
                "created": entry.get("created"), "reason": entry.get("reason"),
                "doc_version": entry.get("doc_version"),
            })
    runs.sort(key=lambda r: str(r.get("created") or ""), reverse=True)
    # an explicitly opened store (`sorb ui file.sorb.db`) is not in the
    # workspace index — pin it first, or the SPA silently switches to runs[0]
    opened = state._current_db
    if opened and opened.is_file() and opened.parent != state.results_dir:
        import sqlite3

        subject = None
        try:
            store = GraphStore.open_readonly(opened)
            try:
                subject = store.get_meta("subject")
            finally:
                store.close()
        except (OSError, sqlite3.Error):
            pass
        runs.insert(0, {"run": "current", "subject": subject or opened.name,
                        "serial": None, "created": None, "reason": "opened", "doc_version": 1})
    return runs


def _encode_cursor(offset: int) -> str:
    import base64

    return base64.urlsafe_b64encode(str(offset).encode()).decode()


def _decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    import base64

    try:
        return max(0, int(base64.urlsafe_b64decode(cursor.encode()).decode()))
    except (ValueError, TypeError):
        return 0


_FALLBACK_INDEX = """<!doctype html><meta charset=utf-8>
<title>sorbet</title>
<p>The sorbet UI assets are not built into this install. The Graph API is live at
<code>/api/…</code>. Build the SPA with the release pipeline to get the explorer.</p>
"""
