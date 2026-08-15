"""Project corrections: user-recorded fixes applied to every scan.

``sorb.corrections.json`` at the project root records components the user has
marked as false positives (excluded from every future emission) and components
the scanner missed (asserted into every future SBOM). The file lives next to
``sorb.toml`` so a team can commit it and the whole project inherits the
corrections; both the CLI (``sorb mark``) and the UI write it.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from sorb.graph.store import GraphStore
from sorb.model import Tier

FILENAME = "sorb.corrections.json"
KINDS = ("false-positive", "missing")


@dataclass
class Correction:
    kind: str  # "false-positive" | "missing"
    ref: str  # purl, name, or name@version
    reason: str = ""
    ecosystem: str = ""
    scope: str = ""

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in asdict(self).items() if v}


def corrections_path(project_root: Path) -> Path:
    return project_root / FILENAME


def load_corrections(project_root: Path) -> list[Correction]:
    p = corrections_path(project_root)
    if not p.is_file():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Correction] = []
    for e in raw.get("corrections", []):
        if isinstance(e, dict) and e.get("kind") in KINDS and e.get("ref"):
            out.append(Correction(
                kind=str(e["kind"]), ref=str(e["ref"]), reason=str(e.get("reason", "")),
                ecosystem=str(e.get("ecosystem", "")), scope=str(e.get("scope", "")),
            ))
    return out


def save_corrections(project_root: Path, entries: list[Correction]) -> Path:
    p = corrections_path(project_root)
    payload = {
        "$comment": "sorb project corrections — applied to every scan of this project; "
        "manage with `sorb mark` or the UI",
        "corrections": [e.to_dict() for e in entries],
    }
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


def add_correction(project_root: Path, entry: Correction) -> bool:
    """Record one correction; returns False if an identical (kind, ref) exists."""
    entries = load_corrections(project_root)
    if any(e.kind == entry.kind and e.ref == entry.ref for e in entries):
        return False
    entries.append(entry)
    save_corrections(project_root, entries)
    return True


def remove_correction(project_root: Path, kind: str, ref: str) -> bool:
    entries = load_corrections(project_root)
    kept = [e for e in entries if not (e.kind == kind and e.ref == ref)]
    if len(kept) == len(entries):
        return False
    save_corrections(project_root, kept)
    return True


def _split_ref(ref: str) -> tuple[str | None, str, str | None]:
    """(purl, name, version) from a purl, name@version, or bare name."""
    if ref.startswith("pkg:"):
        tail = ref.rsplit("/", 1)[-1]
        name, _, version = tail.partition("@")
        return ref, name or tail, version or None
    # npm scopes start with "@": only an "@" past position 0 separates a version
    head, sep, version = ref[1:].rpartition("@")
    if sep:
        return None, ref[0] + head, version
    return None, ref, None


def apply_corrections(store: GraphStore, entries: list[Correction]) -> tuple[int, int]:
    """Apply corrections to a finished scan; returns (fps excluded, missing added)."""
    fps = added = 0
    for e in entries:
        if e.kind == "false-positive":
            for comp in store.find_component(e.ref):
                if comp.attrs.get("excluded"):
                    continue
                attrs = dict(comp.attrs)
                attrs["excluded"] = "user-marked false positive" + (
                    f": {e.reason}" if e.reason else ""
                )
                store._conn.execute(
                    "UPDATE components SET attrs=? WHERE id=?",
                    (json.dumps(attrs, sort_keys=True), comp.id),
                )
                store.add_annotation(
                    "component", comp.id, "user-false-positive",
                    e.reason or "marked via sorb.corrections.json",
                )
                fps += 1
        else:
            if store.find_component(e.ref):
                continue  # the scanner found it on its own this time
            purl, name, version = _split_ref(e.ref)
            attrs = {k: v for k, v in
                     {"ecosystem": e.ecosystem, "scope": e.scope, "asserted": "true"}.items() if v}
            cid = store.add_component(
                purl=purl, ctype="library", name=name, version=version,
                qualifiers={}, hashes={}, confidence=1.0,
                tier_cap=int(Tier.DECLARED), attrs=attrs,
            )
            store.add_annotation(
                "component", cid, "user-asserted",
                e.reason or "added via sorb.corrections.json (scanner missed it)",
            )
            added += 1
    if fps or added:
        store.commit()
    return fps, added
