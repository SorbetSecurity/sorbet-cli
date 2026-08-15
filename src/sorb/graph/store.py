"""GraphStore: the run store.

One SQLite file per run; WAL mode; single writer (the pipeline), any number of
read-only connections (UI, `explain`, `query`). Migrations are forward-only
SQL scripts in ``sorb/graph/migrations/NNN_*.sql``.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from sorb.model import (
    EdgeType,
    EvidenceRecord,
    Finding,
    ProjectClaim,
    Tier,
    claim_to_dict,
    evidence_to_dict,
)

SCHEMA_VERSION = 2

_MIGRATION_RE = re.compile(r"^(\d{3})_.*\.sql$")


def _migrations() -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for entry in (resources.files("sorb") / "graph" / "migrations").iterdir():
        m = _MIGRATION_RE.match(entry.name)
        if m:
            out.append((int(m.group(1)), entry.read_text(encoding="utf-8")))
    return sorted(out)


@dataclass(frozen=True, slots=True)
class Component:
    """Canonical, post-reconcile entity. Constructed only by sorb.graph."""

    id: int
    purl: str | None
    ctype: str
    name: str
    version: str | None
    qualifiers: dict[str, str]
    hashes: dict[str, str]
    confidence: float
    tier_cap: int
    attrs: dict[str, Any]

    @property
    def tier(self) -> Tier:
        return Tier(self.tier_cap)

    def display_ref(self) -> str:
        if self.purl:
            return self.purl
        v = f"@{self.version}" if self.version else ""
        return f"{self.name}{v}"


@dataclass(frozen=True, slots=True)
class ComponentDetail:
    component: Component
    evidence: list[dict[str, Any]]
    annotations: list[dict[str, Any]]


@dataclass(frozen=True, slots=True)
class PathStep:
    """One node on a provenance path."""

    kind: str  # "project" | "component" | "source"
    label: str
    component_id: int | None = None
    edge_attrs: dict[str, Any] = field(default_factory=dict)


class GraphStore:
    """Write + read API over one run database."""

    def __init__(self, conn: sqlite3.Connection, *, writable: bool):
        self._conn = conn
        self._writable = writable
        conn.row_factory = sqlite3.Row

    # -- lifecycle ----------------------------------------------------------

    @classmethod
    def create(cls, path: str | Path) -> GraphStore:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        store = cls(conn, writable=True)
        store._migrate()
        return store

    @classmethod
    def open_readonly(cls, path: str | Path) -> GraphStore:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(path)
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        return cls(conn, writable=False)

    @classmethod
    def open_rw(cls, path: str | Path) -> GraphStore:
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA journal_mode=WAL")
        store = cls(conn, writable=True)
        store._migrate()
        return store

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> GraphStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _migrate(self) -> None:
        cur = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
        )
        current = 0
        if cur.fetchone():
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()
            current = int(row["value"]) if row else 0
        for version, sql in _migrations():
            if version > current:
                self._conn.executescript(sql)
                self._conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                    (str(version),),
                )
        self._conn.commit()

    def commit(self) -> None:
        self._conn.commit()

    # -- meta ---------------------------------------------------------------

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))

    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def all_meta(self) -> dict[str, str]:
        return {
            r["key"]: r["value"] for r in self._conn.execute("SELECT key, value FROM meta")
        }

    # -- write path ---------------------------------------------------------

    def add_source(self, source_id: str, kind: str, ref: str, provenance: dict[str, Any]) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO sources(id, kind, ref, provenance) VALUES(?,?,?,?)",
            (source_id, kind, ref, json.dumps(provenance, sort_keys=True)),
        )

    def add_file(
        self,
        source_id: str,
        path: str,
        digest: str | None,
        size: int,
        role: str | None,
        coords: dict[str, Any] | None = None,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO files(source_id, path, digest, size, role, coords) VALUES(?,?,?,?,?,?)",
            (source_id, path, digest, size, role, json.dumps(coords or {}, sort_keys=True)),
        )
        return int(cur.lastrowid or 0)

    def add_project(self, p: ProjectClaim, source_id: str) -> int:
        row = self._conn.execute(
            "SELECT id FROM projects WHERE source_id=? AND path=?", (source_id, p.path)
        ).fetchone()
        if row:
            return int(row["id"])
        cur = self._conn.execute(
            "INSERT INTO projects(source_id, path, name, kind) VALUES(?,?,?,?)",
            (source_id, p.path, p.name, p.kind),
        )
        return int(cur.lastrowid or 0)

    def add_finding(self, finding: Finding) -> int:
        detector = finding.evidence[0].detector if finding.evidence else ""
        cur = self._conn.execute(
            "INSERT INTO findings(claim, detector, component_id) VALUES(?,?,NULL)",
            (json.dumps(claim_to_dict(finding.claim), sort_keys=True), detector),
        )
        fid = int(cur.lastrowid or 0)
        for ev in finding.evidence:
            self.add_evidence(fid, ev)
        return fid

    def add_evidence(self, finding_id: int, ev: EvidenceRecord) -> int:
        d = evidence_to_dict(ev)
        cur = self._conn.execute(
            "INSERT INTO evidence(finding_id, technique, tier, detector, location, captured,"
            " confidence, modifiers) VALUES(?,?,?,?,?,?,?,?)",
            (
                finding_id,
                ev.technique,
                int(ev.tier),
                ev.detector,
                json.dumps(d["location"], sort_keys=True),
                ev.captured,
                ev.confidence,
                json.dumps(list(ev.modifiers)),
            ),
        )
        return int(cur.lastrowid or 0)

    def add_component(
        self,
        *,
        purl: str | None,
        ctype: str,
        name: str,
        version: str | None,
        qualifiers: dict[str, str],
        hashes: dict[str, str],
        confidence: float,
        tier_cap: int,
        attrs: dict[str, Any],
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO components(purl, ctype, name, version, qualifiers, hashes,"
            " confidence, tier_cap, attrs) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                purl,
                ctype,
                name,
                version,
                json.dumps(qualifiers, sort_keys=True),
                json.dumps(hashes, sort_keys=True),
                confidence,
                tier_cap,
                json.dumps(attrs, sort_keys=True),
            ),
        )
        return int(cur.lastrowid or 0)

    def link_finding(self, finding_id: int, component_id: int) -> None:
        self._conn.execute(
            "UPDATE findings SET component_id=? WHERE id=?", (component_id, finding_id)
        )

    def add_edge(
        self,
        kind: EdgeType,
        src: int,
        dst: int,
        attrs: dict[str, Any] | None = None,
        evidence_ids: list[int] | None = None,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO edges(kind, src, dst, attrs, evidence_ids) VALUES(?,?,?,?,?)",
            (
                kind.value,
                src,
                dst,
                json.dumps(attrs or {}, sort_keys=True),
                json.dumps(evidence_ids or []),
            ),
        )
        return int(cur.lastrowid or 0)

    def add_layer(
        self, digest: str, source_id: str, ordinal: int, created_by: str | None
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO layers(digest, source_id, ordinal, created_by)"
            " VALUES(?,?,?,?)",
            (digest, source_id, ordinal, created_by),
        )

    def add_file_state(
        self, source_id: str, path: str, layer_digest: str, ordinal: int, state: str
    ) -> None:
        self._conn.execute(
            "INSERT INTO file_states(source_id, path, layer_digest, ordinal, state)"
            " VALUES(?,?,?,?,?)",
            (source_id, path, layer_digest, ordinal, state),
        )

    def update_component_attrs(self, cid: int, attrs: dict[str, Any]) -> None:
        self._conn.execute(
            "UPDATE components SET attrs=? WHERE id=?",
            (json.dumps(attrs, sort_keys=True), cid),
        )

    def add_annotation(
        self,
        subject_kind: str,
        subject_id: int,
        code: str,
        detail: str = "",
        attrs: dict[str, Any] | None = None,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO annotations(subject_kind, subject_id, code, detail, attrs)"
            " VALUES(?,?,?,?,?)",
            (subject_kind, subject_id, code, detail, json.dumps(attrs or {}, sort_keys=True)),
        )
        return int(cur.lastrowid or 0)

    # -- node-id helpers (edges reference a single id space per node kind) ---
    # Node ids in `edges` use tagged ranges: components use their rowid;
    # projects use -(project_id) - 1_000_000; layers use -(ordinal) - 2_000_000;
    # sources use -(1..N) small ids. This keeps the base schema unchanged
    # while allowing typed roots.

    PROJECT_BASE = 1_000_000
    LAYER_BASE = 2_000_000

    def project_node_id(self, project_id: int) -> int:
        return -(project_id + self.PROJECT_BASE)

    def is_project_node(self, node_id: int) -> bool:
        return -self.LAYER_BASE < node_id <= -self.PROJECT_BASE

    def project_id_from_node(self, node_id: int) -> int:
        return -node_id - self.PROJECT_BASE

    def source_node_id(self, source_ordinal: int) -> int:
        return -(source_ordinal + 1)

    def layer_node_id(self, ordinal: int) -> int:
        return -(ordinal + self.LAYER_BASE)

    def is_layer_node(self, node_id: int) -> bool:
        return node_id <= -self.LAYER_BASE

    def layer_ordinal_from_node(self, node_id: int) -> int:
        return -node_id - self.LAYER_BASE

    # -- read path -----------------------------------------------------------

    def _row_to_component(self, row: sqlite3.Row) -> Component:
        return Component(
            id=int(row["id"]),
            purl=row["purl"],
            ctype=row["ctype"],
            name=row["name"],
            version=row["version"],
            qualifiers=json.loads(row["qualifiers"] or "{}"),
            hashes=json.loads(row["hashes"] or "{}"),
            confidence=float(row["confidence"] or 0.0),
            tier_cap=int(row["tier_cap"] or 1),
            attrs=json.loads(row["attrs"] or "{}"),
        )

    def components(self) -> list[Component]:
        rows = self._conn.execute(
            "SELECT * FROM components ORDER BY name, version, id"
        ).fetchall()
        return [self._row_to_component(r) for r in rows]

    def component_by_id(self, cid: int) -> Component | None:
        row = self._conn.execute("SELECT * FROM components WHERE id=?", (cid,)).fetchone()
        return self._row_to_component(row) if row else None

    def find_component(self, ref: str) -> list[Component]:
        """Resolve a purl / name / digest / path reference to components."""
        rows: list[sqlite3.Row] = []
        if ref.startswith("pkg:"):
            rows = self._conn.execute(
                "SELECT * FROM components WHERE purl=?", (ref,)
            ).fetchall()
            if not rows:  # try version-insensitive prefix
                rows = self._conn.execute(
                    "SELECT * FROM components WHERE purl LIKE ?", (ref + "@%",)
                ).fetchall()
        if not rows and re.fullmatch(r"[0-9a-fA-F]{32,128}", ref):
            like = f'%"{ref.lower()}"%'
            rows = self._conn.execute(
                "SELECT * FROM components WHERE hashes LIKE ?", (like,)
            ).fetchall()
        if not rows:
            # name[@version]
            name, _, ver = ref.partition("@")
            if ver:
                rows = self._conn.execute(
                    "SELECT * FROM components WHERE name=? AND version=?", (name, ver)
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM components WHERE name=?", (name,)
                ).fetchall()
        return [self._row_to_component(r) for r in rows]

    def near_matches(self, ref: str, limit: int = 5) -> list[str]:
        name = ref.split("@")[0].split("/")[-1]
        rows = self._conn.execute(
            "SELECT DISTINCT COALESCE(purl, name || COALESCE('@'||version, '')) AS r"
            " FROM components WHERE name LIKE ? ORDER BY r LIMIT ?",
            (f"%{name}%", limit),
        ).fetchall()
        return [r["r"] for r in rows]

    def evidence_for_component(self, cid: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT e.* FROM evidence e JOIN findings f ON e.finding_id = f.id"
            " WHERE f.component_id=? ORDER BY e.tier DESC, e.technique, e.detector,"
            " e.location, e.id",
            (cid,),
        ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "technique": r["technique"],
                    "tier": Tier(int(r["tier"])).label,
                    "detector": r["detector"],
                    "location": json.loads(r["location"]),
                    "captured": r["captured"],
                    "confidence": float(r["confidence"] or 0.0),
                    "modifiers": json.loads(r["modifiers"] or "[]"),
                }
            )
        return out

    def annotations_for(self, subject_kind: str, subject_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM annotations WHERE subject_kind=? AND subject_id=? ORDER BY id",
            (subject_kind, subject_id),
        ).fetchall()
        return [
            {
                "code": r["code"],
                "detail": r["detail"],
                "attrs": json.loads(r["attrs"] or "{}"),
            }
            for r in rows
        ]

    def all_annotations(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM annotations ORDER BY id").fetchall()
        return [
            {
                "subject_kind": r["subject_kind"],
                "subject_id": int(r["subject_id"]),
                "code": r["code"],
                "detail": r["detail"],
                "attrs": json.loads(r["attrs"] or "{}"),
            }
            for r in rows
        ]

    def component_detail(self, cid: int) -> ComponentDetail | None:
        comp = self.component_by_id(cid)
        if comp is None:
            return None
        return ComponentDetail(
            component=comp,
            evidence=self.evidence_for_component(cid),
            annotations=self.annotations_for("component", cid),
        )

    def layers(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM layers ORDER BY ordinal").fetchall()
        return [
            {
                "digest": r["digest"],
                "source_id": r["source_id"],
                "ordinal": int(r["ordinal"]),
                "created_by": r["created_by"],
            }
            for r in rows
        ]

    def file_states(self, path: str | None = None) -> list[dict[str, Any]]:
        if path is not None:
            rows = self._conn.execute(
                "SELECT * FROM file_states WHERE path=? ORDER BY ordinal, id", (path,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM file_states ORDER BY ordinal, id"
            ).fetchall()
        return [
            {
                "path": r["path"],
                "layer_digest": r["layer_digest"],
                "ordinal": int(r["ordinal"]),
                "state": r["state"],
            }
            for r in rows
        ]

    def projects(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM projects ORDER BY path").fetchall()
        return [
            {"id": int(r["id"]), "path": r["path"], "name": r["name"], "kind": r["kind"]}
            for r in rows
        ]

    def edges(self, kind: EdgeType | None = None) -> list[dict[str, Any]]:
        if kind:
            rows = self._conn.execute(
                "SELECT * FROM edges WHERE kind=? ORDER BY id", (kind.value,)
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM edges ORDER BY id").fetchall()
        return [
            {
                "id": int(r["id"]),
                "kind": r["kind"],
                "src": int(r["src"]),
                "dst": int(r["dst"]),
                "attrs": json.loads(r["attrs"] or "{}"),
            }
            for r in rows
        ]

    # -- provenance paths -----------------------------------------------------

    def paths_to_roots(self, cid: int, max_depth: int = 25) -> list[list[PathStep]]:
        """All inbound DEPENDS_ON paths from roots (projects/sources) to `cid`.

        Iterative DFS over reversed edges with a visited set per path
        (cycle-safe), depth-capped.
        """
        # Build reverse adjacency for DEPENDS_ON edges lazily (bounded graphs).
        rows = self._conn.execute(
            "SELECT src, dst, attrs FROM edges WHERE kind=?", (EdgeType.DEPENDS_ON.value,)
        ).fetchall()
        rev: dict[int, list[tuple[int, dict[str, Any]]]] = {}
        for r in rows:
            rev.setdefault(int(r["dst"]), []).append(
                (int(r["src"]), json.loads(r["attrs"] or "{}"))
            )

        paths: list[list[PathStep]] = []

        def step_for(node: int, edge_attrs: dict[str, Any]) -> PathStep:
            if self.is_project_node(node):
                pid = self.project_id_from_node(node)
                row = self._conn.execute(
                    "SELECT path FROM projects WHERE id=?", (pid,)
                ).fetchone()
                label = row["path"] if row else f"project#{pid}"
                return PathStep(kind="project", label=label, edge_attrs=edge_attrs)
            if node < 0:
                row = self._conn.execute("SELECT ref FROM sources LIMIT 1").fetchone()
                label = row["ref"] if row else "source"
                return PathStep(kind="source", label=label, edge_attrs=edge_attrs)
            comp = self.component_by_id(node)
            label = comp.display_ref() if comp else f"component#{node}"
            return PathStep(
                kind="component", label=label, component_id=node, edge_attrs=edge_attrs
            )

        # Upward chains: [(node, attrs-of-edge-from-node-into-the-previous-entry)]
        stack: list[list[tuple[int, dict[str, Any]]]] = [[(cid, {})]]
        while stack:
            chain = stack.pop()
            node = chain[-1][0]
            if len(chain) > max_depth:
                continue
            parents = rev.get(node, [])
            if not parents or node < 0:
                # Root-first, edge attrs shifted onto the child of each edge.
                nodes_root_first = [n for n, _ in reversed(chain)]
                attrs_root_first = [a for _, a in reversed(chain)]
                steps = []
                for i, n in enumerate(nodes_root_first):
                    eattrs = attrs_root_first[i - 1] if i > 0 else {}
                    steps.append(step_for(n, eattrs))
                paths.append(steps)
                continue
            seen = {n for n, _ in chain}
            for parent, eattrs in sorted(parents, key=lambda t: t[0]):
                if parent in seen:  # cycle guard
                    continue
                stack.append(chain + [(parent, eattrs)])
        paths.sort(key=lambda p: [s.label for s in p])
        return paths

    # -- aggregates (dashboard / summary) -------------------------------------

    def counters(self) -> dict[str, Any]:
        """Emission-set counts; graph-retained-but-excluded components (below
        threshold, or removed/superseded during an image build) are reported
        separately — a number the user sees must match the SBOM they get."""
        by_eco: dict[str, int] = {}
        tiers: dict[str, int] = {}
        emitted = []
        retained = 0
        for c in self.components():
            if c.attrs.get("excluded"):
                retained += 1
                continue
            emitted.append(c)
            eco = str(c.attrs.get("ecosystem", ""))
            if not eco and c.purl and c.purl.startswith("pkg:"):
                eco = c.purl[4:].split("/", 1)[0]
            if not eco:
                eco = c.ctype or "unknown"
            by_eco[eco] = by_eco.get(eco, 0) + 1
            t = Tier(c.tier_cap).label
            tiers[t] = tiers.get(t, 0) + 1
        n_high = sum(1 for c in emitted if c.confidence >= 0.9)
        return {
            "components": len(emitted),
            "high_confidence": n_high,
            "excluded": retained,
            "by_ecosystem": dict(sorted(by_eco.items())),
            "by_tier": dict(sorted(tiers.items())),
        }
