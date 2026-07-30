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

for _spec in (PUBSPEC_LOCK, CARGO_LOCK, RENV_LOCK, JULIA_MANIFEST, NIMBLE_LOCK, SHARD_LOCK):
    register(TableCataloger(_spec))
