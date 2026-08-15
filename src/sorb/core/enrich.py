"""Post-reconcile enrichment + resolver verify passes.

Enrichment is **additive-only and source-marked**: it may add description /
homepage / license-corroboration attrs to components, never change identity,
versions, confidence, or edges — an offline scan's output is always a subset
of the online one. Failures degrade to a warning (SORB-W014), never break a
scan. ``--offline`` bypasses it entirely.
"""

from __future__ import annotations

from typing import Any

from sorb.graph.store import GraphStore
from sorb.model import Finding, Tier
from sorb.resolve.npm import verify_lock
from sorb.resolve.provider import RegistryMetadataProvider


def enrich_components(
    store: GraphStore, provider: RegistryMetadataProvider
) -> tuple[int, list[tuple[str, str]]]:
    """Enrich npm components from registry metadata. Returns (enriched, warnings)."""
    warnings: list[tuple[str, str]] = []
    enriched = 0
    failures = 0
    for comp in store.components():
        if comp.attrs.get("ecosystem") != "npm" or not comp.version:
            continue
        if comp.attrs.get("excluded") or comp.attrs.get("state"):
            continue
        doc = provider.npm_metadata(comp.name)
        if doc is None:
            failures += 1
            continue
        entry = (doc.get("versions") or {}).get(comp.version)
        if not isinstance(entry, dict):
            continue
        attrs: dict[str, Any] = dict(comp.attrs)
        changed = False
        for source_key, attr_key in (
            ("description", "description"),
            ("homepage", "homepage"),
            ("license", "license_registry"),
        ):
            value = entry.get(source_key) or doc.get(source_key)
            if value and attr_key not in attrs:  # additive-only, never overwrite
                attrs[attr_key] = str(value)
                changed = True
        if changed:
            attrs["enrichment_source"] = "npm-registry"
            store.update_component_attrs(comp.id, attrs)
            enriched += 1
    if failures:
        warnings.append(
            (
                "SORB-W014",
                f"enrichment metadata unavailable for {failures} component(s) "
                "(registry unreachable or uncached) — output is complete, just less annotated",
            )
        )
    return enriched, warnings


def verify_npm_lock_ranges(
    store: GraphStore, findings: list[tuple[int, Finding]]
) -> list[tuple[str, str]]:
    """Verify mode: locked versions must satisfy declared ranges.

    A lock entry outside its manifest range is drift — annotated on
    the component, never silently re-resolved.
    """
    declared: dict[str, str] = {}
    locked: dict[str, str] = {}
    for _fid, f in findings:
        if f.claim.ecosystem != "npm":
            continue
        tiers = {e.tier for e in f.evidence}
        if Tier.DECLARED in tiers and f.claim.requested:
            declared.setdefault(f.claim.name, f.claim.requested)
        if Tier.LOCKED in tiers and f.claim.version:
            locked.setdefault(f.claim.name, f.claim.version)
    warnings: list[tuple[str, str]] = []
    for check in verify_lock(declared, locked):
        if check.satisfied:
            continue
        detail = (
            f"lockfile pins {check.name}@{check.locked}, outside the manifest "
            f"range {check.requested!r} — the lock is stale or hand-edited"
        )
        for comp in store.find_component(f"{check.name}@{check.locked}"):
            store.add_annotation("component", comp.id, "drift:lock-outside-range", detail)
        warnings.append(("SORB-W035", f"{check.name}: {detail}"))
    return warnings
