"""Warning-code registry.

Every user-visible warning carries a stable ``SORB-Wxxx`` code documented in
``sorb/data/warnings.toml``; ``sorb explain-warning`` renders entries from the
same registry.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib import resources


@dataclass(frozen=True, slots=True)
class WarningInfo:
    code: str
    title: str
    explanation: str
    remediation: str


def _load() -> dict[str, WarningInfo]:
    data = (resources.files("sorb") / "data" / "warnings.toml").read_bytes()
    raw = tomllib.loads(data.decode("utf-8"))
    return {
        code: WarningInfo(
            code=code,
            title=str(entry["title"]),
            explanation=str(entry["explanation"]),
            remediation=str(entry["remediation"]),
        )
        for code, entry in raw.items()
    }


_REGISTRY: dict[str, WarningInfo] | None = None


def registry() -> dict[str, WarningInfo]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _load()
    return _REGISTRY


def lookup(code: str) -> WarningInfo | None:
    return registry().get(code.upper().strip())


# Annotation code → warning code mapping (annotations stored in the graph use
# the short kebab names; warnings surface the SORB-W code).
ANNOTATION_WARNING_CODES: dict[str, str] = {
    "analysis-gap": "SORB-W001",
    "stale-lockfile": "SORB-W010",
    "orphan-installed-state": "SORB-W011",
    "unresolved-dynamic-manifest": "SORB-W012",
    "resolution-incomplete": "SORB-W013",
    "version-conflict": "SORB-W020",
    "drift:declared-not-installed": "SORB-W030",
    "drift:installed-not-declared": "SORB-W031",
    "drift:locked-vs-installed": "SORB-W032",
    "drift:attestation-mismatch": "SORB-W033",
    "pkgdb-upgraded": "SORB-W034",
    "pkgdb-removed": "SORB-W034",
    "drift:lock-outside-range": "SORB-W035",
    "drift:observed-not-declared": "SORB-W036",
    "declared-never-observed": "SORB-W037",
    "unpinned-image": "SORB-W060",
    "drift:dockerfile-vs-image": "SORB-W061",
    "merge-conflict": "SORB-W021",
    "ambiguous-declared": "SORB-W040",
    "license-undetected": "SORB-W041",
    "license-mismatch": "SORB-W042",
    "unidentified-binaries": "SORB-W050",
}
