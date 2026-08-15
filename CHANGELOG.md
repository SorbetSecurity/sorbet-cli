# Changelog

User-facing changes per release. Release notes are generated from this file.

## 0.2.0

### Added
- `sorb mark` (and UI buttons): mark false positives and add components the scanner
  missed — remembered in `sorb.corrections.json` and applied to every future scan.
- Curated purl → CPE map: well-known packages carry a CPE alongside their purl, so
  SBOMs work with both NVD- and OSV-style vulnerability matching.
- UI: interactive dependency tree — expand level by level, cycle markers, and
  "show in graph" from any component.
- UI: components list with ecosystem multi-select, confidence filter and sortable
  columns; the low-confidence tail is hidden by default.
- UI: certificates & keys (CBOM) separated from packages, hidden behind a toggle
  and excluded from default exports.
- UI: fleet page with per-host rollups and a cross-host version-skew table.
- UI: export options — min confidence, include CBOM, include excluded components.

### Fixed
- Plain-text `.pth` files are no longer misreported as ML models.
- Compiled extension modules inside installed packages are no longer emitted as
  anonymous binary components.
- pypi extras are no longer recorded as dependency edges, removing inflated dep
  counts and phantom dependency cycles.
- Components found only in test-fixture paths stay out of emitted SBOMs.

## 0.1.0

Initial release: evidence-backed SBOM generation for code, containers, binaries
and whole machines, with an offline evidence-explorer UI (`sorb ui`).
