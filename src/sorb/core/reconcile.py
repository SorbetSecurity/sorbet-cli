"""Reconciliation engine.

Deterministic, pure function of the finding set. Steps: BUCKET (union-find
over identity keys) → family attach for versionless declared claims → SCORE
(noisy-OR capped by tier) → PIN (highest tier wins; SUPERSEDES; same-tier
conflicts annotated) → EDGES (merge; direct/transitive; scope propagation)
→ DRIFT → EMIT-SET (thresholds route to the low-confidence inventory).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sorb.graph.store import GraphStore
from sorb.ident import cpe_for, family_key, identity_keys, versionless_purl
from sorb.model import (
    TIER_CONFIDENCE_CAP,
    ComponentClaim,
    EdgeType,
    EvidenceRecord,
    Finding,
    ProjectClaim,
    Tier,
)

#: Ecosystems where one environment holds at most one version of a package —
#: findings merge at family level and the highest tier pins the version.
#: Conan belongs here: a graph resolves each reference to exactly one version,
#: and without it a `conanfile.txt` declaration and the `conan.lock` entry for
#: the same package become two components, because the lock's purl carries a
#: recipe revision (`?rrev=`) the manifest cannot know.
#: vcpkg is here too, but only because `family_key` folds the triplet into a
#: vcpkg family: one port has one version *per triplet*, and without the merge
#: the per-port SPDX (`1.3.2`) and the install database (`1.3.2#1`) are two
#: components describing the same installed library.
SINGLE_VERSION_ECOS = {
    "pypi", "deb", "apk", "alpm", "conda", "composer", "pub", "conan", "vcpkg",
}

_ORPHAN_MODIFIER = 0.8

#: A marker gating a dependency behind one of the *dependent's* own extras
#: (``extra == "all"``). Environment markers (``python_version < "3.11"``,
#: ``sys_platform == "win32"``) say *where* a real dependency applies and are
#: deliberately not matched here — those edges stay in the reachability walk.
_EXTRA_MARKER_RE = re.compile(r"\bextra\s*==")


def _extras_gated(edge_attrs: dict[str, Any]) -> bool:
    """True when this edge only exists if the consumer asked for an extra."""
    marker = edge_attrs.get("marker")
    return marker is not None and _EXTRA_MARKER_RE.search(str(marker)) is not None


@dataclass
class ReconcileStats:
    components: int = 0
    merged_findings: int = 0
    dropped_edges: int = 0
    excluded_low_confidence: int = 0
    drift_annotations: list[dict[str, str]] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[int, int] = {}

    def find(self, x: int) -> int:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _variant_of(claim: ComponentClaim) -> str:
    """The build variant that makes two same-named packages different things.

    Only vcpkg has one today: the triplet decides architecture and, crucially,
    static vs dynamic linkage. Everything else has a single variant.
    """
    qualifiers = dict(claim.qualifiers)
    return qualifiers.get("triplet", "")


def _eco_of(claim: ComponentClaim) -> str:
    if claim.ecosystem:
        return claim.ecosystem
    if claim.purl and claim.purl.startswith("pkg:"):
        return claim.purl[4:].split("/", 1)[0]
    return claim.ctype


def reconcile(
    store: GraphStore,
    findings: list[tuple[int, Finding]],
    projects: list[ProjectClaim],
    source_id: str,
    *,
    min_confidence: float = 0.8,
    paranoid: bool = False,
    scope_filter: str = "all",
) -> ReconcileStats:
    stats = ReconcileStats()

    real = [(fid, f) for fid, f in findings if f.claim.ctype != "edge-only"]
    edge_only = [(fid, f) for fid, f in findings if f.claim.ctype == "edge-only"]

    # ---- 1. BUCKET: union-find over identity keys ---------------------------
    uf = _UnionFind()
    by_key: dict[str, int] = {}
    versioned_idx: list[int] = []
    versionless_idx: list[int] = []
    for i, (_fid, f) in enumerate(real):
        uf.find(i)
        (versioned_idx if f.claim.version else versionless_idx).append(i)
        for key in identity_keys(f.claim):
            if key in by_key:
                uf.union(i, by_key[key])
            else:
                by_key[key] = i

    # Single-version ecosystems: merge whole families (highest tier pins).
    fam_of: dict[int, str] = {}
    for i, (_fid, f) in enumerate(real):
        fam_of[i] = f"{_eco_of(f.claim)}::{family_key(f.claim)}"
    fam_members: dict[str, list[int]] = defaultdict(list)
    for i in versioned_idx:
        fam_members[fam_of[i]].append(i)
    for fam, members in fam_members.items():
        eco = fam.split("::", 1)[0]
        if eco not in SINGLE_VERSION_ECOS:
            continue
        # "One version per environment" is per *variant* where an ecosystem has
        # them: a vcpkg port is installed once per triplet, and the triplet
        # carries linkage, so an x64-windows build and an x64-windows-static
        # build of one port are different artifacts. The family stays
        # variant-free so a versionless manifest claim still attaches to it.
        by_variant: dict[str, list[int]] = defaultdict(list)
        for i in members:
            by_variant[_variant_of(real[i][1].claim)].append(i)
        for group in by_variant.values():
            for other in group[1:]:
                uf.union(group[0], other)

    # ---- 2. family attach for versionless (declared) claims ------------------
    versionless_by_fam: dict[str, list[int]] = defaultdict(list)
    for i in versionless_idx:
        versionless_by_fam[fam_of[i]].append(i)

    ambiguous: set[int] = set()
    for fam, unresolved in sorted(versionless_by_fam.items()):
        # Claims that name a package without resolving it all describe the same
        # unresolved thing, so they merge with each other first — otherwise a
        # manifest range and a native-resolution range become two components.
        for i in unresolved[1:]:
            uf.union(unresolved[0], i)
        concrete_roots = sorted({uf.find(j) for j in fam_members.get(fam, [])})
        if len(concrete_roots) == 1:
            uf.union(unresolved[0], concrete_roots[0])
        elif len(concrete_roots) > 1:
            ambiguous.update(unresolved)
        # zero concrete → one unresolved component for the family

    buckets: dict[int, list[int]] = defaultdict(list)
    for i in range(len(real)):
        buckets[uf.find(i)].append(i)

    # ---- 3–4. SCORE + PIN per bucket ----------------------------------------
    ref_to_cid: dict[str, int] = {}
    family_to_cids: dict[str, list[int]] = defaultdict(list)
    cid_info: dict[int, dict[str, Any]] = {}
    bucket_items = sorted(
        buckets.items(),
        key=lambda kv: (
            real[kv[0]][1].claim.name.lower(),
            real[kv[0]][1].claim.version or "",
        ),
    )
    for _root, members in bucket_items:
        # version pinning: highest-tier claim with a concrete version wins
        def claim_tier(idx: int) -> Tier:
            evs = real[idx][1].evidence
            return max((e.tier for e in evs), default=Tier.INFERRED)

        def member_key(idx: int) -> tuple[int, str, str, str]:
            c = real[idx][1].claim
            return (int(claim_tier(idx)), c.version or "", c.purl or "", c.name)

        # deterministic regardless of input order
        members = sorted(members, key=member_key, reverse=True)
        claims = [real[i][1].claim for i in members]
        evidence: list[EvidenceRecord] = []
        for i in members:
            evidence.extend(real[i][1].evidence)
        if not evidence:
            continue
        top_tier = max(e.tier for e in evidence)

        pinned_version: str | None = None
        pin_tier = Tier.INFERRED
        superseded_versions: list[tuple[str, Tier]] = []
        conflict_versions: set[str] = set()
        for i in members:
            c = real[i][1].claim
            if not c.version:
                continue
            t = claim_tier(i)
            if pinned_version is None:
                pinned_version, pin_tier = c.version, t
            elif c.version != pinned_version:
                if t == pin_tier:
                    conflict_versions.add(c.version)
                else:
                    superseded_versions.append((c.version, t))

        base = max(claims, key=lambda c: (bool(c.purl), bool(c.version)))
        purl = None
        for c in claims:
            if c.purl and c.version == pinned_version:
                purl = c.purl
                break
        if purl is None:
            purl = next((c.purl for c in claims if c.purl), None)
        if purl is None:
            # Unresolved version: a versionless purl still gives downstream
            # tools an identity to match on. Buckets are already fixed, so this
            # cannot change how claims merged.
            purl = next(
                (p for p in (versionless_purl(c) for c in claims) if p), None
            )
        hashes: dict[str, str] = {}
        qualifiers: dict[str, str] = {}
        attrs: dict[str, Any] = {}
        licenses = None
        for c in sorted(claims, key=lambda c: bool(c.licenses_declared)):
            hashes.update(dict(c.hashes))
            qualifiers.update(dict(c.qualifiers))
            attrs.update(dict(c.attrs))
            if c.licenses_declared:
                licenses = c.licenses_declared
        requested = next((c.requested for c in claims if c.requested), None)
        if requested and not pinned_version:
            attrs["requested"] = requested
        if licenses:
            attrs["licenses_declared"] = licenses

        # noisy-OR capped by highest tier present
        prod = 1.0
        for e in evidence:
            prod *= 1.0 - max(0.0, min(1.0, e.confidence))
        confidence = min(1.0 - prod, TIER_CONFIDENCE_CAP[top_tier])

        tiers_present = sorted({e.tier.label for e in evidence})
        attrs["tiers"] = tiers_present
        attrs["ecosystem"] = _eco_of(base)
        cpe = cpe_for(purl)
        if cpe:
            attrs["cpe"] = cpe

        cid = store.add_component(
            purl=purl,
            ctype=base.ctype,
            name=base.name,
            version=pinned_version,
            qualifiers=qualifiers,
            hashes=hashes,
            confidence=round(confidence, 4),
            tier_cap=int(top_tier),
            attrs=attrs,
        )
        stats.components += 1
        stats.merged_findings += len(members) - 1
        cid_info[cid] = {
            "eco": _eco_of(base),
            "name": base.name,
            "version": pinned_version,
            "tiers": {e.tier for e in evidence},
            "top_tier": top_tier,
            "attrs": attrs,
            "confidence": confidence,
            "ctype": base.ctype,
        }
        family_to_cids[fam_of[members[0]]].append(cid)

        for i in members:
            fid = real[i][0]
            store.link_finding(fid, cid)
            claim_ref = real[i][1].claim.ref()
            ref_to_cid.setdefault(claim_ref, cid)
        if purl:
            ref_to_cid.setdefault(f"purl:{purl}", cid)

        subject_ref = f"purl:{purl}" if purl else base.name
        if conflict_versions and _eco_of(base) in SINGLE_VERSION_ECOS:
            store.add_annotation(
                "component",
                cid,
                "version-conflict",
                f"same-tier sources disagree: {pinned_version} vs "
                f"{', '.join(sorted(conflict_versions))}",
            )
            stats.warnings.append(
                ("SORB-W020", f"{base.name}: version conflict {pinned_version} vs {sorted(conflict_versions)}")
            )
        for lost_version, lost_tier in superseded_versions:
            store.add_annotation(
                "component",
                cid,
                "drift:locked-vs-installed"
                if {pin_tier, lost_tier} == {Tier.LOCKED, Tier.INSTALLED}
                else "superseded-version",
                f"{lost_tier.label} said {lost_version}; pinned {pinned_version} "
                f"({pin_tier.label} wins)",
            )
            if {pin_tier, lost_tier} == {Tier.LOCKED, Tier.INSTALLED}:
                stats.drift_annotations.append(
                    {
                        "code": "drift:locked-vs-installed",
                        "subject": subject_ref,
                        "detail": f"lock says {lost_version if lost_tier is Tier.LOCKED else pinned_version}, "
                        f"installed is {pinned_version if pin_tier is Tier.INSTALLED else lost_version}",
                    }
                )
                stats.warnings.append(("SORB-W032", f"{base.name}: locked-vs-installed drift"))

    # per-finding annotations from catalogers
    for _fid, f in real + edge_only:
        for ann in f.annotations:
            acid = ref_to_cid.get(ann.subject)
            if acid is not None:
                store.add_annotation("component", acid, ann.code, ann.detail, dict(ann.attrs))
            else:
                store.add_annotation("run", 0, ann.code, f"{ann.subject}: {ann.detail}", dict(ann.attrs))
    for i in sorted(ambiguous):
        f = real[i][1]
        acid = ref_to_cid.get(f.claim.ref())
        if acid is not None:
            store.add_annotation(
                "component",
                acid,
                "ambiguous-declared",
                f"declared {f.claim.name} matches multiple concrete versions",
            )

    # ---- projects ------------------------------------------------------------
    proj_node: dict[str, int] = {}
    for p in projects:
        pid = store.add_project(p, source_id)
        proj_node[p.path] = store.project_node_id(pid)

    def resolve_ref(ref: str) -> int | None:
        if ref in ref_to_cid:
            return ref_to_cid[ref]
        if ref.startswith("project:"):
            path = ref.split(":", 1)[1] or "."
            if path not in proj_node:
                pid = store.add_project(ProjectClaim(path=path, name=path, kind="auto"), source_id)
                proj_node[path] = store.project_node_id(pid)
            return proj_node[path]
        if ref.startswith("family:"):
            eco_name = ref.split(":", 1)[1]
            eco, _, name = eco_name.partition("/")
            candidates = [
                cid
                for cid, info in cid_info.items()
                if info["eco"] == eco and info["name"].lower() == name.lower()
            ]
            if len(candidates) == 1:
                return candidates[0]
            if candidates:
                # multiple versions: prefer the single highest-tier one
                best = sorted(
                    candidates,
                    key=lambda c: (int(cid_info[c]["top_tier"]), cid_info[c]["version"] or ""),
                    reverse=True,
                )
                return best[0]
            return None
        if ref.startswith("resource:"):
            name = ref.split(":", 1)[1]
            for cid, info in cid_info.items():
                if info["ctype"] == "resource" and info["name"] == name:
                    return cid
            return None
        if ref.startswith("purl:") and "@" not in ref:
            return None
        return None

    # ---- 6. EDGES: merge claims, resolve refs, dedup --------------------------
    merged_edges: dict[tuple[str, int, int], dict[str, Any]] = {}
    instance_paths: dict[int, list[str]] = defaultdict(list)
    for _fid, f in real + edge_only:
        for ec in f.edges:
            if ec.kind is EdgeType.INSTANCE_OF:
                icid = resolve_ref(ec.dst)
                if icid is not None and ec.src.startswith("file:"):
                    instance_paths[icid].append(ec.src.split(":", 1)[1])
                continue
            src = resolve_ref(ec.src)
            dst = resolve_ref(ec.dst)
            if src is None or dst is None or src == dst:
                stats.dropped_edges += 1
                continue
            ekey = (ec.kind.value, src, dst)
            cur = merged_edges.setdefault(ekey, {})
            if ec.scope and "scope" not in cur:
                cur["scope"] = ec.scope.value
            if ec.direct:
                cur["direct"] = True
            if ec.requested and "requested" not in cur:
                cur["requested"] = ec.requested
            if ec.marker:
                cur["marker"] = ec.marker
            for k, v in ec.attrs:
                cur.setdefault(k, v)

    for (kind, src, dst), attrs in sorted(merged_edges.items()):
        store.add_edge(EdgeType(kind), src, dst, attrs)

    for cid, paths in instance_paths.items():
        info = cid_info.get(cid)
        if info is not None:
            info["attrs"]["instance_paths"] = sorted(set(paths))
            store._conn.execute(  # promote to attrs column
                "UPDATE components SET attrs=? WHERE id=?",
                (_json_dumps(info["attrs"]), cid),
            )

    # ---- 7. scope propagation --------------------------------------------------
    adj: dict[int, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for (kind, src, dst), attrs in merged_edges.items():
        if kind == EdgeType.DEPENDS_ON.value:
            adj[src].append((dst, attrs))

    def reach(roots: set[int], *, follow_extras: bool) -> tuple[set[int], set[int]]:
        """Everything DEPENDS_ON-reachable from `roots`, and what was gated off.

        Unless `follow_extras`, an extras-gated edge is not traversed: a package
        listing a test tool under ``extra == "all"`` does not make that tool a
        dependency of a project that never requested the extra. Those targets
        come back as the second set so they can be scoped optional rather than
        silently promoted to whatever reached them.
        """
        reached: set[int] = set(roots)
        gated: set[int] = set()
        frontier = list(roots)
        while frontier:
            node = frontier.pop()
            for nxt, eattrs in adj.get(node, ()):
                if not follow_extras and _extras_gated(eattrs):
                    gated.add(nxt)
                    continue
                if nxt in reached:
                    continue
                reached.add(nxt)
                frontier.append(nxt)
        return reached, gated

    runtime_roots: set[int] = set()
    dev_roots: set[int] = set()
    optional_roots: set[int] = set()
    build_reach: set[int] = set()
    conditional_only: dict[int, bool] = {}
    for pnode in proj_node.values():
        for child, attrs in adj.get(pnode, ()):
            raw_scope = attrs.get("scope", "runtime")
            if attrs.get("marker"):
                conditional_only.setdefault(child, True)
            else:
                conditional_only[child] = False
            if raw_scope == "build":
                build_reach.add(child)
                continue
            if raw_scope == "optional":
                # An extra nobody asked for is not a runtime dependency: it is
                # declared as available, not as required.
                optional_roots.add(child)
                continue
            (dev_roots if raw_scope in ("dev", "test") else runtime_roots).add(child)

    runtime_reach, runtime_gated = reach(runtime_roots, follow_extras=False)
    dev_reach, dev_gated = reach(dev_roots, follow_extras=False)
    # Opting into an extra does pull in that extra's whole subtree, so the
    # optional walk follows every edge — it is already inside the conditional.
    optional_reach, _ = reach(optional_roots | runtime_gated | dev_gated, follow_extras=True)
    extras_gated = (runtime_gated | dev_gated) - runtime_reach - dev_reach

    for cid, info in cid_info.items():
        if cid in runtime_reach:
            scope = "runtime"
        elif cid in dev_reach or info["attrs"].get("dev") == "true":
            scope = "dev"
        elif cid in build_reach or info["ctype"] == "build-tool":
            scope = "build"
        elif cid in optional_reach:
            scope = "optional"
        elif info["ctype"] in ("os-package", "application"):
            scope = "runtime"
        else:
            scope = None
        if scope:
            info["attrs"]["scope"] = scope
        if conditional_only.get(cid) or cid in extras_gated:
            info["attrs"]["conditional"] = True

    # ---- 5. DRIFT (per family, across tiers) -----------------------------------
    ecosystems_with_manifests = {
        _eco_of(f.claim)
        for _fid, f in real
        if any(e.tier in (Tier.DECLARED, Tier.LOCKED) for e in f.evidence)
    }
    ecosystems_with_installed = _ecosystems_with_installed_state(real)
    for fam, cids in sorted(family_to_cids.items()):
        eco = fam.split("::", 1)[0]
        all_tiers: set[Tier] = set()
        for cid in cids:
            all_tiers |= cid_info[cid]["tiers"]
        declaredish = bool(all_tiers & {Tier.DECLARED, Tier.LOCKED})
        installedish = bool(all_tiers & {Tier.INSTALLED, Tier.OBSERVED})
        name = cid_info[cids[0]]["name"]
        subject = name
        # build tooling, extras and marker-conditional deps are not drift: an
        # extra nobody installed is the normal case, not a missing dependency.
        exempt = all(
            cid_info[cid]["ctype"] == "build-tool"
            or cid_info[cid]["attrs"].get("scope") in ("build", "optional")
            or cid_info[cid]["attrs"].get("conditional")
            or cid_info[cid]["attrs"].get("optional") == "true"
            for cid in cids
        )
        if declaredish and not installedish and not exempt and eco in ecosystems_with_installed:
            for cid in cids:
                store.add_annotation(
                    "component", cid, "drift:declared-not-installed",
                    f"{name} is declared/locked but not present in installed state",
                )
            stats.drift_annotations.append(
                {"code": "drift:declared-not-installed", "subject": subject, "detail": ""}
            )
            stats.warnings.append(("SORB-W030", f"{name}: declared but not installed"))
        if installedish and not declaredish and eco in ecosystems_with_manifests and eco not in (
            "deb", "apk", "alpm",
        ):
            for cid in cids:
                info = cid_info[cid]
                new_conf = round(info["confidence"] * _ORPHAN_MODIFIER, 4)
                store._conn.execute(
                    "UPDATE components SET confidence=? WHERE id=?", (new_conf, cid)
                )
                info["confidence"] = new_conf
                store.add_annotation(
                    "component", cid, "drift:installed-not-declared",
                    f"{name} is installed but no manifest or lockfile accounts for it "
                    f"(confidence x{_ORPHAN_MODIFIER})",
                )
            stats.drift_annotations.append(
                {"code": "drift:installed-not-declared", "subject": subject, "detail": ""}
            )
            stats.warnings.append(("SORB-W031", f"{name}: installed but not declared"))

    # ---- 8. EMIT-SET thresholds --------------------------------------------------
    for cid, info in cid_info.items():
        exclude_reason = None
        top: Tier = info["top_tier"]
        if paranoid and top < Tier.LOCKED:
            exclude_reason = "below locked tier (--paranoid)"
        elif top is Tier.INFERRED and info["confidence"] < min_confidence:
            exclude_reason = f"inferred-only confidence {info['confidence']} < {min_confidence}"
        elif scope_filter != "all" and info["attrs"].get("scope") not in (None, scope_filter):
            exclude_reason = f"scope {info['attrs'].get('scope')} filtered (--scope {scope_filter})"
        if exclude_reason:
            info["attrs"]["excluded"] = exclude_reason
            stats.excluded_low_confidence += 1
        store._conn.execute(
            "UPDATE components SET attrs=? WHERE id=?", (_json_dumps(info["attrs"]), cid)
        )

    store.commit()
    return stats


def _ecosystems_with_installed_state(real: list[tuple[int, Finding]]) -> set[str]:
    """Ecosystems that produced installed-tier evidence anywhere in the scan.

    Drift only means something where installed state was actually observed: a
    package "declared but not installed" is not a finding if nothing in that
    ecosystem was inspected for installed state at all.
    """
    return {
        _eco_of(f.claim)
        for _fid, f in real
        if any(e.tier is Tier.INSTALLED for e in f.evidence)
    }


def _json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, sort_keys=True)
