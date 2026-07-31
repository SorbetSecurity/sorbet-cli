# Ecosystem support

What `sorb` can read, and what it cannot yet. For how detection works see
[`architecture.md`](./architecture.md); for what has been checked against real
software see [`validation.md`](./validation.md).

A format is **supported** when a cataloger reads it and the result is covered
by a test. Nothing is listed here on the strength of a purl type existing —
`conda` was a registered purl type, had a version comparator and sat in the
reconciler's single-version set for a whole release while no cataloger read a
single conda file, which is exactly the sort of half-wiring this page exists to
make visible.

## Evidence tiers

The tier a format yields matters as much as whether it is read at all:

| Tier | Means | Typical source |
| --- | --- | --- |
| `declared` | Someone asked for this | manifests (`package.json`, `environment.yml`) |
| `locked` | Resolution pinned it | lockfiles (`poetry.lock`, `Cargo.lock`) |
| `installed` | It is on disk | install databases (`dpkg/status`, `*.dist-info`) |
| `observed` | It was loaded at runtime | `sorb trace`, `/proc` |

## Supported

### Language ecosystems

| Ecosystem | Formats read | Best tier |
| --- | --- | --- |
| JavaScript / TypeScript | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `deno.lock`, `node_modules/*/package.json` | installed |
| Python | `pyproject.toml`, `setup.py`, `requirements*.txt`, `constraints*.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `*.dist-info/METADATA` | installed |
| Go | `go.mod`, `go.sum`, embedded buildinfo in binaries | installed |
| JVM | `pom.xml` (full parent/property/BOM model), `build.gradle(.kts)`, `gradle.lockfile`, `libs.versions.toml`, `verification-metadata.xml`, `*.jar/war/ear` | locked |
| .NET | `*.csproj/fsproj/vbproj`, `packages.lock.json`, `project.assets.json`, `*.deps.json`, `paket.lock`, CLR assembly identity in `*.dll/exe` | locked |
| Rust | `Cargo.toml`, `Cargo.lock`, `cargo-auditable` data in binaries | locked |
| Ruby | `Gemfile.lock`, `*.gemspec` | locked |
| PHP | `composer.json`, `composer.lock`, `vendor/composer/installed.json` | installed |
| Swift / ObjC | `Package.swift`, `Package.resolved`, `Podfile.lock`, `Cartfile.resolved` | locked |
| Dart / Flutter | `pubspec.lock` | locked |
| Elixir | `mix.lock` | locked |
| Haskell | `stack.yaml.lock`, `cabal.project.freeze` | locked |
| R | `renv.lock` | locked |
| Julia | `Manifest.toml` | locked |
| Nim | `nimble.lock` | locked |
| Crystal | `shard.lock` | locked |
| Conda | `environment.yml`, `environment.yaml`, `conda-lock.yml`, `conda-meta/*.json` | installed |
| PDM (Python) | `pdm.lock` | locked |
| Nix | `flake.lock` | locked |
| Erlang | `rebar.lock` | locked |
| Clojure | `deps.edn`, `project.clj` | declared |
| Scala / sbt | `build.sbt`, `project/*.scala` | declared |
| OCaml | `*.opam`, `dune-project` | declared |
| Perl | `cpanfile`, `META.json` | declared |
| Lua | `*.rockspec` | declared |
| Unity | `Packages/manifest.json` | declared |
| Zig | `build.zig.zon` | locked |

### C / C++

| Toolchain | Formats read |
| --- | --- |
| Bazel | `MODULE.bazel` (`bazel_dep`) |
| vcpkg | `vcpkg.json` (incl. `features`, `overrides`, baseline), `vcpkg-configuration.json`, `vcpkg_installed/*/status`, per-port `vcpkg.spdx.json` |
| Conan | `conanfile.txt`, `conanfile.py`, `conan.lock` v2 |
| CMake | `CMakeLists.txt`, `*.cmake` (`find_package`/`FetchContent`/`CPM`), File API codemodel |
| Meson | `subprojects/*.wrap` |
| Long tail | `*.pc` (pkg-config), `Makefile` `-l` flags, `.gitmodules` |

### Operating systems, containers, binaries

| Area | Formats read |
| --- | --- |
| OS packages | dpkg, apk, pacman, rpm (sqlite / ndb / Berkeley DB), portage (Gentoo VDB), snap |
| Containers | registry-direct, OCI layout, docker-save archives, `docker:`, `containerd:`, `container://`; `sorb layers` reports per-layer churn, the instruction that built each layer, and what it introduced |
| Binaries | ELF, PE, Mach-O, WASM link graphs; Go buildinfo, cargo-auditable, .NET CLR |
| Mobile | `*.apk`, `*.aab`, `*.ipa` |
| Windows | registry hives (`SOFTWARE`, `SYSTEM`) |
| IaC | Terraform (+ lock), Kubernetes, Helm, Kustomize, CloudFormation, Bicep, Ansible, Dockerfile |
| Other | certificates/keys (CBOM), ML models (ML-BOM), license files |

## Not yet supported

Every ecosystem previously listed here has been implemented and validated
against a real project. What remains is one format that is *implementable but
not yet checkable*, which is a different thing from a gap in intent:

| Format | Why it is still open |
| --- | --- |
| flatpak | A flatpak deployment is OSTree-based and cannot be produced in a plain container, so there is no real artifact to validate a reader against. A flatpak `metadata` file also names the app and its runtime without stating a version, so the reader would need the OSTree commit metadata to say anything useful |

### Deliberately not supported

| Format | Why |
| --- | --- |
| `WORKSPACE` (Bazel) | The legacy Starlark form runs arbitrary code to declare repositories. `MODULE.bazel` (bzlmod) is the declarative successor and is read instead |
| `bun.lockb` | Bun's legacy *binary* lockfile. Bun 1.2+ writes the text `bun.lock` by default and can regenerate it from the binary form, so the text reader covers current projects |
| `Brewfile.lock.json` | Homebrew removed lockfile generation; `brew bundle` in 6.x has no `lock` subcommand, so current Homebrew never writes one. Supporting it would mean shipping a reader for a format no live tool produces and that cannot be validated against a freshly generated artifact |

A dynamic manifest (`build.sbt`, `Package.swift`, `WORKSPACE`) is what
`--resolve=native` exists for: the honest static answer is often "this file
computes its dependencies", recorded as `SORB-W012`
(`unresolved-dynamic-manifest`) rather than guessed.

## Adding a format

Most lockfiles are declarative. A `LockfileSpec` in
`sorb/catalogers/table_specs.py` yields a working cataloger with evidence
spans, purls and hashes — no parser code:

```python
PDM_LOCK = LockfileSpec(
    id="python/pdm-lock",
    match="pdm.lock",
    format=TOML,
    packages_at="$.package[*]",
    fields={"name": "$.name", "version": "$.version"},
    purl_type="pypi",
    tier=Tier.LOCKED,
)
```

Reach for a hand-written cataloger only when the format is not JSON/YAML/TOML,
or when identity needs real work (parent-pom interpolation, triplet
qualifiers). See [`plugins.md`](./plugins.md) to add one out of tree.
