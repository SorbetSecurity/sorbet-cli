# Changelog

## 0.1.0 - initial open-source release

First public release of `sorb`, the Sorbet CLI.

### Scanning
- Source-tree scanning for npm/pnpm/yarn, Python, Go (incl. binary
  buildinfo), JVM (Maven POM model, Gradle locks, JAR/fat-jar analysis),
  .NET (incl. CLR assembly identity), Ruby, PHP, Rust (workspace
  inheritance), C/C++ (vcpkg, Conan, CMake incl. the File API, submodules,
  vendored-tree fingerprinting), dpkg/apk/pacman/rpm, and a dozen long-tail
  lockfile formats.
- Layer-accurate container image scanning: registry-direct, OCI layouts,
  docker-save archives, daemons, containerd, and running containers - with
  per-layer attribution, base-image splitting, package-DB time travel,
  attestation verify-ingest, distroless inventories, and `--all-platforms`.
- Compiled-binary analysis: ELF/PE/Mach-O/WASM link graphs (including ELF
  dynamic symbols with their GNU version requirements), embedded ground
  truth (Go buildinfo, cargo-auditable, .NET CLR), installer/firmware
  unpacking, and signature-DB fingerprinting of stripped/static libraries
  (`sorb db`).
- Mobile apps (APK/AAB/IPA) unpacked and inventoried.
- IaC surface: Terraform, Kubernetes/Helm/Kustomize, CloudFormation, Bicep,
  Ansible, Dockerfiles - including `--follow-images` chaining referenced
  images into container scans.
- Whole machines: `host://` running-host inventory with observed-running
  detection, `disk://` agentless disk-image reading (raw/MBR/GPT/FAT
  in-process; ext4/NTFS/qcow2/… via the optional `dissect` backend),
  offline Windows registry hives, and `sorb fleet` aggregation across many
  host/image stores.

### Accuracy & evidence
- Evidence-backed model throughout: every component carries occurrence
  evidence, a provenance chain, an evidence tier
  (declared/locked/installed/observed), and an explainable confidence score
  (`sorb explain`).
- Reconciliation engine with drift reporting, license detection, and pure
  lockfile-verifying resolvers (npm semver, Go MVS, Maven mediation).
- Opt-in higher-fidelity modes: `--resolve=native` (ecosystem build tool in
  a deny-by-default sandbox on Linux and macOS; refused rather than run
  unconfined where no sandbox exists) and `sorb trace` / `snapshot` / `watch`
  (runtime observation; phantom & unused dependency detection).
- Declared ranges are recorded as requests, never as versions: an unresolved
  dependency is emitted once, with a versionless purl, rather than inventing a
  component at a version that was never built.
- Predicted packages from a Dockerfile `RUN` stop at the shell command
  boundary, so operands of a later command in the same layer are not reported
  as packages, and every install in one `RUN` is found.
- Evidence spans point at the line that declares a component, so
  `sorb explain` sends a reader to the block rather than to the top of the
  file.

### Output & interop
- Emitters: CycloneDX 1.6, SPDX 2.3, SPDX 3.0, a lossless native format,
  and human table/tree/summary renderers; `--reproducible` byte-identical
  output; CBOM and ML-BOM emission.
- Foreign-SBOM tooling: `sorb convert` (any-to-any, with loss report),
  `merge` (union/hierarchical/intersect), `diff`, `validate`
  (structural/NTIA/BSI TR-03183).
- Air-gapped signing: detached signatures, DSSE in-toto attestations with
  subject-digest binding, ordered verification (`sign`/`attest`/`verify`).
  Verifying an artifact you hold always binds the signature to its digest, so
  a validly-signed attestation about a different artifact is refused.

### Exploration
- `sorb ui` / `sorb serve`: a self-contained offline evidence explorer
  (dashboard, dependency-graph canvas, layer stack, visual explain, query
  console) with strict CSP, per-session token auth, and DNS-rebinding
  defense.
- `sorb query`: a graph query DSL (`components where … | count by …`,
  `paths from … to …`) shared by the CLI, fleet, and the UI's API.

### Extensibility & distribution
- Plugins in three tiers: Python entry points (discovered on install), signed
  WASM modules run with no filesystem/network/environment access, and
  explicitly-trusted gRPC services - the latter two opt-in per project via
  `[plugins]` in `sorb.toml`. Findings from every tier are re-validated before
  ingestion, cannot impersonate a first-party detector, and cannot claim more
  confidence than their technique's base rate.
- CI gating (`--fail-on` + stable exit codes), a GitHub Action, a container
  image, Homebrew and winget packaging, PyPI releases, and signed standalone
  bundles with verified self-update (`sorb self update`).
- Optional native accelerator (`sorb-accel`) adopted only after a
  byte-identical self-check; `sorb bench` perf gates and a fuzzing harness
  guard regressions and parser robustness.
