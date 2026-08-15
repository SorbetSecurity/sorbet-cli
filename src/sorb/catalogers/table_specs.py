"""Concrete table-driven lockfile specs for long-tail ecosystems.

Each spec is one entry + one corpus fixture. The Dart spec is the
demonstration cataloger.
"""

from __future__ import annotations

from sorb.catalogers.base import register
from sorb.catalogers.table import JSON, TOML, YAML, LockfileSpec, TableCataloger
from sorb.model import Tier

PUBSPEC_LOCK = LockfileSpec(
    id="dart/pubspec-lock",
    match="pubspec.lock",
    format=YAML,
    packages_at="$.packages.*",
    fields={"name": "@key", "version": "$.version", "digest": "$.description.sha256"},
    purl_type="pub",
    tier=Tier.LOCKED,
)

CARGO_LOCK = LockfileSpec(
    id="rust/cargo-lock",
    match="Cargo.lock",
    format=TOML,
    packages_at="$.package[*]",
    fields={"name": "$.name", "version": "$.version", "digest": "$.checksum"},
    purl_type="cargo",
    tier=Tier.LOCKED,
)

# composer.lock moved to the full parser in `sorb.catalogers.ruby_php`.

# -- Long tail -------------------------------------------------------------------

# stack.yaml.lock, cabal freeze, Package.resolved, Podfile.lock, Cartfile,
# mix.lock, Cargo.toml (workspace inheritance) and build.zig.zon need small
# hand parsers — they live in `sorb.catalogers.longtail`.

RENV_LOCK = LockfileSpec(
    id="r/renv-lock",
    match="renv.lock",
    format=JSON,
    packages_at="$.Packages.*",
    fields={"name": "$.Package", "version": "$.Version", "digest": "$.Hash"},
    purl_type="cran",
    tier=Tier.LOCKED,
)

JULIA_MANIFEST = LockfileSpec(
    id="julia/manifest-toml",
    match="Manifest.toml",
    format=TOML,
    packages_at="$.deps.*[*]",
    fields={"name": "@key", "version": "$.version"},
    purl_type="julia",
    tier=Tier.LOCKED,
)

NIMBLE_LOCK = LockfileSpec(
    id="nim/nimble-lock",
    match="nimble.lock",
    format=JSON,
    packages_at="$.packages.*",
    fields={"name": "@key", "version": "$.version", "digest": "$.checksums.sha1"},
    purl_type="nimble",
    tier=Tier.LOCKED,
)

SHARD_LOCK = LockfileSpec(
    id="crystal/shard-lock",
    match="shard.lock",
    format=YAML,
    packages_at="$.shards.*",
    fields={"name": "@key", "version": "$.version"},
    purl_type="shards",
    tier=Tier.LOCKED,
)

#: One JSON document per installed package, written by conda at install time —
#: the authoritative record of what is actually in an environment, the way
#: `*.dist-info` is for pip. The file name carries name-version-build, but the
#: document states them properly, so the directory is the only hint needed.
CONDA_META = LockfileSpec(
    id="conda/conda-meta",
    match_glob="*conda-meta/*.json",
    format=JSON,
    packages_at="$",  # the document *is* the package
    fields={"name": "$.name", "version": "$.version", "digest": "$.sha256"},
    purl_type="conda",
    tier=Tier.INSTALLED,
    technique="installed-state",
)

#: PDM's lockfile is `[[package]]` array-of-tables, structurally identical to
#: Cargo.lock. Hashes live under `files[].hash`, which the mini-path does not
#: reach into, so they are left to the installed-state cataloger.
PDM_LOCK = LockfileSpec(
    id="python/pdm-lock",
    match="pdm.lock",
    format=TOML,
    packages_at="$.package[*]",
    fields={"name": "$.name", "version": "$.version"},
    purl_type="pypi",
    tier=Tier.LOCKED,
)

#: A flake input is pinned by the git revision in its `locked` block; the
#: `root` node has no `locked` and is skipped for want of a version. narHash is
#: deliberately not mapped to `hashes`: it is a base64 SRI string over a store
#: path, not the hex content digest every other hash field holds.
FLAKE_LOCK = LockfileSpec(
    id="nix/flake-lock",
    match="flake.lock",
    format=JSON,
    packages_at="$.nodes.*",
    fields={"name": "@key", "version": "$.locked.rev"},
    purl_type="nix",
    tier=Tier.LOCKED,
)

#: Unity's package manifest maps package id → version directly. The path glob
#: matters: a bare `manifest.json` is far too common a name to claim.
UNITY_MANIFEST = LockfileSpec(
    id="unity/packages-manifest",
    match_glob="*Packages/manifest.json",
    format=JSON,
    packages_at="$.dependencies.*",
    fields={"name": "@key", "version": "@value"},
    purl_type="unity",
    tier=Tier.DECLARED,
    technique="manifest-parse",
)

#: Every snap carries `meta/snap.yaml` stating its own name and version — the
#: install record for `/snap/<name>/current`, and equally the manifest inside a
#: `.snap` squashfs.
SNAP_YAML = LockfileSpec(
    id="os/snap",
    match_glob="*meta/snap.yaml",
    format=YAML,
    packages_at="$",  # the document *is* the package
    fields={"name": "$.name", "version": "$.version"},
    purl_type="snap",
    tier=Tier.INSTALLED,
    technique="installed-state",
)

for _spec in (
    PUBSPEC_LOCK,
    CARGO_LOCK,
    RENV_LOCK,
    JULIA_MANIFEST,
    NIMBLE_LOCK,
    SHARD_LOCK,
    CONDA_META,
    PDM_LOCK,
    FLAKE_LOCK,
    UNITY_MANIFEST,
    SNAP_YAML,
):
    register(TableCataloger(_spec))
