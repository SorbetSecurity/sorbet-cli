# sorbet-cli : dependency analysis and SBOM generation for code, containers and binaries

[![CI](https://github.com/SorbetSecurity/sorbet-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/SorbetSecurity/sorbet-cli/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

<img src="https://raw.githubusercontent.com/SorbetSecurity/sorbet-cli/main/docs/assets/banner.jpg" alt="sorbet-cli - dependency analysis and SBOM generation for code, containers and binaries" width="100%">

**Sorbet CLI** (`sorb`) is an open-source, cross-platform dependency-analysis
and SBOM-generation tool.

Point it at software - a code repository, a container image, a binary,
infrastructure config, or a whole machine - and it produces an
**evidence-backed SBOM** (CycloneDX 1.6, SPDX 2.3/3.0): every component
carries occurrence evidence, a provenance chain, and a confidence score.

```bash
pip install sorb              # or: uv tool install sorb / pipx install sorb
sorb scan .                   # scan a repo
sorb scan image:alpine:3.20   # scan a container image, per layer
sorb ui                       # browse the results in a local web UI
```

<img src="https://raw.githubusercontent.com/SorbetSecurity/sorbet-cli/main/docs/assets/demo.gif" alt="scanning this repository, then asking why one component is in the SBOM" width="820">

## Features

- **Explainable output.** `sorb explain <component>` reports which detector
  found a component, in which file and at which byte range, and how its
  confidence was derived.
- **Offline by default.** Network access is opt-in per scan (`--allow-net`);
  `--offline` disables it entirely. No telemetry.
- **Contained failures.** An unparseable file becomes an `analysis-gap`
  annotation instead of failing the scan.
- **Reproducible output.** With `--reproducible`, scanning unchanged input
  twice produces the identical file, because timestamps come from
  `SOURCE_DATE_EPOCH` instead of the clock. An SBOM can then be committed and
  regenerated in CI, where any diff means a dependency really changed.
- **A queryable evidence graph.** Each scan writes an SQLite graph shared by
  `explain`, `query`, `diff`, `merge`, `fleet` and the UI. SBOM files are
  views over it, and any result exports as a CycloneDX or SPDX subgraph.

## What it scans

| Target | Examples |
| --- | --- |
| Source trees | npm/pnpm/yarn, Python, Go, JVM (Maven/Gradle), .NET, Ruby, PHP, Rust, C/C++ (vcpkg/Conan/CMake), and a dozen long-tail lockfile formats |
| Container images | `image:REF` registry-direct, OCI layouts, docker-save archives, daemons/containerd, running containers - with per-layer attribution, base-image splitting, and multi-arch support |
| Compiled binaries | ELF/PE/Mach-O/WASM link graphs, embedded ground truth (Go buildinfo, cargo-auditable, .NET CLR), signature-DB fingerprinting of stripped/static libraries |
| Mobile & installers | APK/AAB/IPA, installers, firmware images |
| IaC | Terraform, Kubernetes/Helm/Kustomize, CloudFormation, Bicep, Ansible, Dockerfiles - with `--follow-images` chaining referenced images into container scans |
| Whole machines | `host://` inventories a running host (marking what's *observed running* and on which ports); `disk://` reads disk images agentlessly - no mount, no root |

It also inventories two things that are not packages:

- **Certificates and keys** (a CBOM). Each certificate is recorded with its
  subject, issuer and expiry date. Private keys are noted as present, but
  their contents are never read into the SBOM.
- **Machine-learning models** (an ML-BOM). Safetensors, GGUF, ONNX, PyTorch
  and pickle files, with their format and tensor metadata. Formats that run
  code when loaded, such as pickle and TorchScript, are flagged.

## Beyond static analysis

Static analysis is the default. These optional modes gather more:

- `sorb scan --resolve=native` runs the ecosystem's own build tool inside a
  deny-by-default sandbox (Linux and macOS) and reads what it resolved.
- `sorb trace -- <cmd>` runs a command and records which libraries it actually
  loads, finding dependencies that are used but never declared, and declared
  but never used.
- `sorb snapshot` compares installed state before and after a step such as a
  package install.
- `sorb watch` records the same as `trace`, but across a longer session.

## Working with SBOMs

```bash
sorb convert other.spdx.json -o cyclonedx-json --loss-report
sorb merge a.cdx.json b.spdx.json -o cyclonedx-json
sorb diff v1.cdx.json image:app:2.0 --fail-on-change
sorb validate sbom.json --require ntia
sorb sign / attest / verify        # air-gapped DSSE signing and verification
sorb query 'components where confidence < 0.9 | count by ecosystem'
sorb fleet '.sorb/results/*.sorb.db' -q '…'   # one question across every scanned host
```

For CI: `--fail-on drift,stale-lockfile,version-conflict,phantom-deps`, stable
exit codes, a GitHub Action (`action.yml`), and a container image.

## Scope

`sorb` generates SBOMs. Vulnerability matching is out of scope: that is the
job of whatever platform consumes the SBOMs downstream.

## Documentation

- [`docs/usage.md`](./docs/usage.md) - installation, every command, targets,
  formats, flags, configuration.
- [`docs/architecture.md`](./docs/architecture.md) - how it's built: the
  evidence model, pipeline, subsystems, storage, plugins, testing.
- [`docs/support.md`](./docs/support.md) - every ecosystem and file format
  read, and what is not supported yet.
- [`docs/plugins.md`](./docs/plugins.md) - writing a cataloger or emitter, and
  the WASM plugin ABI.

## Extending

Findings from all three plugin tiers are re-validated before they reach the
graph, so a plugin cannot inject unchecked claims, impersonate a first-party
detector, or claim more confidence than its technique allows.

- **Entry-point plugins** - trusted Python packages registering catalogers or
  emitters (`examples/sorb-plugin-example/`).
- **WASM plugins** - untrusted, must be signed, run with no filesystem,
  network, or environment access and a CPU-fuel cap (`pip install 'sorb[wasm]'`).
- **gRPC plugins** - out-of-process services, contacted only when named in
  trusted config (`pip install 'sorb[grpc]'`).

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
is used only after a load-time check proves its output byte-identical to the
pure-Python implementation, which remains the reference.

## License

Apache 2.0.
