"""Re-validation of untrusted plugin findings.

Every untrusted tier — WASM and gRPC — returns findings as JSON, and that JSON is
**never trusted**: it is re-parsed and re-validated against the `sorb.model`
schema before it can touch the graph, with hard resource caps (finding count,
evidence per finding, captured-snippet length) so a hostile plugin cannot flood
or bloat the store. Detector ids are forced into the `plugin:<namespace>/…`
space, so a plugin can never impersonate a first-party detector, and confidence
is capped at the base rate its technique earns, so it cannot assert more
certainty than the evidence class allows. Malformed input is rejected
wholesale, never partially ingested.
"""

from __future__ import annotations

import json
from typing import Any

from sorb.model import Finding, finding_from_dict

MAX_FINDINGS = 10_000
MAX_EVIDENCE_PER_FINDING = 64
MAX_CAPTURED = 4096
MAX_NAME = 512
#: applied when a plugin names a technique with no registered base rate
DEFAULT_PLUGIN_TECHNIQUE = "plugin-analysis"


def _confidence_ceiling(technique: str) -> float:
    from sorb.catalogers.base import base_rate

    rate = base_rate(technique)
    return rate if rate is not None else base_rate(DEFAULT_PLUGIN_TECHNIQUE) or 0.5


class PluginValidationError(ValueError):
    """A plugin returned output that failed schema/limits validation."""


def validate_findings_json(data: bytes | str, *, namespace: str) -> list[Finding]:
    """Parse + validate plugin findings JSON into `Finding`s, or raise.

    Shape: ``{"findings": [<finding-dict>, ...]}``. Detector ids are namespaced
    `plugin:<namespace>/…`; oversized or malformed input is rejected.
    """
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise PluginValidationError(f"plugin output is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise PluginValidationError("plugin output must be a JSON object")
    raw_findings = doc.get("findings")
    if not isinstance(raw_findings, list):
        raise PluginValidationError("plugin output must have a 'findings' list")
    if len(raw_findings) > MAX_FINDINGS:
        raise PluginValidationError(f"plugin returned {len(raw_findings)} findings (max {MAX_FINDINGS})")

    out: list[Finding] = []
    for i, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            raise PluginValidationError(f"finding {i} is not an object")
        out.append(_validate_one(item, namespace, i))
    return out


def _validate_one(item: dict[str, Any], namespace: str, index: int) -> Finding:
    claim = item.get("claim")
    if not isinstance(claim, dict) or not claim.get("name"):
        raise PluginValidationError(f"finding {index}: missing claim.name")
    if len(str(claim.get("name"))) > MAX_NAME:
        raise PluginValidationError(f"finding {index}: name too long")
    evidence = item.get("evidence") or []
    if not isinstance(evidence, list) or len(evidence) > MAX_EVIDENCE_PER_FINDING:
        raise PluginValidationError(f"finding {index}: bad/oversized evidence")
    # force plugin namespace + cap snippet length on every evidence record
    for ev in evidence:
        if not isinstance(ev, dict):
            raise PluginValidationError(f"finding {index}: evidence entry not an object")
        det = str(ev.get("detector", "cataloger"))
        ev["detector"] = _namespaced(det, namespace)
        cap = ev.get("captured")
        if isinstance(cap, str) and len(cap) > MAX_CAPTURED:
            ev["captured"] = cap[:MAX_CAPTURED]
        ceiling = _confidence_ceiling(str(ev.get("technique", DEFAULT_PLUGIN_TECHNIQUE)))
        try:
            claimed = float(ev.get("confidence") or 0.0)
        except (TypeError, ValueError):
            claimed = 0.0
        ev["confidence"] = ceiling if claimed <= 0.0 else min(claimed, ceiling)
    try:
        return finding_from_dict(item)
    except (KeyError, TypeError, ValueError) as e:
        raise PluginValidationError(f"finding {index}: schema violation: {e}") from e


def _namespaced(detector: str, namespace: str) -> str:
    base = detector.split("@", 1)[0]
    version = detector.split("@", 1)[1] if "@" in detector else "1"
    if base.startswith("plugin:"):
        base = base[len("plugin:"):]
    base = base.split("/", 1)[-1]  # drop any impersonated namespace
    return f"plugin:{namespace}/{base}@{version}"
