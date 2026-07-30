# sorb - evidence-backed SBOMs

[![CI](https://github.com/SorbetSecurity/sorbet-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/SorbetSecurity/sorbet-cli/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Sorbet CLI** (`sorb`) is an open-source, cross-platform dependency-analysis
and SBOM-generation engine, delivered as a single self-contained CLI.

Point it at software - a code repository, a container image, a binary,
infrastructure config, or a whole machine - and it produces a trustworthy,
**evidence-backed SBOM** (CycloneDX 1.6, SPDX 2.3/3.0): every component
carries occurrence evidence, a provenance chain, and a confidence score you
can drill into down to the raw bytes that produced it.

```bash
uv tool install sorbet        # or: pipx install sorbet
sorb scan .                   # scan a repo
sorb scan image:alpine:3.20   # scan a container image, layer-accurately
sorb ui                       # explore the evidence graph locally, fully offline
```

## Why sorb

- **Explainable, not just plausible.** `sorb explain <component>` shows *why*
  every component is in your SBOM: which detector found it, in which file, at
  which bytes, and how its confidence was computed. No silent guessing.
- **Offline-first.** No telemetry, no phone-home. Network access is opt-in
  per scan (`--allow-net`); `--offline` is an absolute kill-switch.
- **Contained failure.** A single unparseable file becomes an `analysis-gap`
  annotation, never a dead scan.
- **Reproducible.** `--reproducible` yields byte-identical SBOMs
  (`SOURCE_DATE_EPOCH` honored) - diff-able in CI.
- **A real dependency graph underneath.** Every scan writes an SQLite evidence
  graph that `explain`, `query`, `diff`, `merge`, `fleet`, and the UI all
  share - SBOM files are views over it, and any result exports as a
  CycloneDX/SPDX subgraph.

## What it scans

| Target | Examples |
| --- | --- |
| Source trees | npm/pnpm/yarn, Python, Go, JVM (Maven/Gradle), .NET, Ruby, PHP, Rust, C/C++ (vcpkg/Conan/CMake), and a dozen long-tail lockfile formats |
| Container images | `image:REF` registry-direct, OCI layouts, docker-save archives, daemons/containerd, running containers - with per-layer attribution, base-image splitting, and multi-arch support |
| Compiled binaries | ELF/PE/Mach-O/WASM link graphs, embedded ground truth (Go buildinfo, cargo-auditable, .NET CLR), signature-DB fingerprinting of stripped/static libraries |
| Mobile & installers | APK/AAB/IPA, installers, firmware images |
| IaC | Terraform, Kubernetes/Helm/Kustomize, CloudFormation, Bicep, Ansible, Dockerfiles - with `--follow-images` chaining referenced images into container scans |
| Whole machines | `host://` inventories a running host (marking what's *observed running* and on which ports); `disk://` reads disk images agentlessly - no mount, no root |

Beyond package inventories, `sorb` also emits **CBOM** (certificates with
expiry; private keys flagged, never captured) and **ML-BOM**
(safetensors/GGUF/ONNX/TorchScript with pickle-risk flags).

## Higher-fidelity modes

Static analysis is the default; two opt-in modes go further:

- `sorb scan --resolve=native` runs the ecosystem's own build tool inside a
  deny-by-default sandbox (Linux and macOS) and ingests its exact resolution
  output.
- `sorb trace -- <cmd>` observes what a process *actually loads* at runtime,
  surfacing phantom (undeclared) and unused dependencies; `sorb snapshot` and
  `sorb watch` cover provisioning diffs and long-running observation.

## Working with SBOMs

```bash
sorb convert other.spdx.json -o cyclonedx-json --loss-report
sorb merge a.cdx.json b.spdx.json -o cyclonedx-json
sorb diff v1.cdx.json image:app:2.0 --fail-on-change
sorb validate sbom.json --require ntia
sorb sign / attest / verify        # air-gapped DSSE signing & verification
sorb query 'components where confidence < 0.9 | count by ecosystem'
sorb fleet '.sorb/results/*.sorb.db' -q '…'   # org-scale questions, per host
```

CI gating is built in: `--fail-on drift,stale-lockfile,version-conflict,phantom-deps`
plus stable exit codes, a GitHub Action (`action.yml`), and a container image.

## Scope

`sorb` generates SBOMs; **vulnerability matching is permanently out of
scope** - that's the job of whatever platform consumes the SBOMs downstream.

## Documentation

- [`docs/usage.md`](./docs/usage.md) - installation, every command, targets,
  formats, flags, configuration.
- [`docs/architecture.md`](./docs/architecture.md) - how it's built: the
  evidence model, pipeline, subsystems, storage, plugins, testing.
- [`docs/plugins.md`](./docs/plugins.md) - writing a cataloger or emitter, and
  the WASM plugin ABI.
- [`docs/validation.md`](./docs/validation.md) - what has been checked against
  real repositories, images and binaries, and what has not.

## Extending

Three plugin tiers, all producing findings that are re-validated before they
touch the graph - a plugin cannot inject unchecked claims, impersonate a
first-party detector, or assert more confidence than its technique earns:

- **Entry-point plugins** - trusted Python packages registering catalogers or
  emitters (`examples/sorb-plugin-example/`).
- **WASM plugins** - untrusted, must be signed, run with no filesystem,
  network, or environment access and a CPU-fuel cap (`pip install 'sorbet[wasm]'`).
- **gRPC plugins** - out-of-process services, contacted only when named in
  trusted config (`pip install 'sorbet[grpc]'`).

The last two are declared per project in `sorb.toml`; see
[`docs/plugins.md`](./docs/plugins.md) for the ABI and configuration.

## Development

```bash
uv venv --python 3.13 .venv && uv pip install -e ".[dev]" -p .venv/bin/python
.venv/bin/sorb scan .                    # scan this repo
.venv/bin/pytest -q                      # tests (network-blocked)
.venv/bin/ruff check src tests && .venv/bin/mypy && .venv/bin/lint-imports
```

Requires Python ≥ 3.12. The optional Rust accelerator (`native/sorb-accel`)
is a drop-in speedup adopted only after a byte-identical self-check - the
pure-Python implementation is always the reference.

## License

Apache 2.0. No telemetry, no phone-home - `sorb` is offline-first.
