# Usage

`sorb` is a single command-line tool with no services to run. Every command
works offline by default: network access is opt-in per scan (`--allow-net`),
and `--offline` disables it entirely.

## Installation

```bash
uv tool install sorb        # recommended
pipx install sorb           # or pipx
pip install sorb            # plain pip works too
```

Or grab a standalone bundle - no Python needed - from the
[releases page](https://github.com/SorbetSecurity/sorbet-cli/releases), or run
the container image:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/sorbetsecurity/sorb:latest scan /work
```

From a clone, without installing:

```bash
uv venv --python 3.13 .venv && uv pip install -e . -p .venv/bin/python
.venv/bin/sorb scan .
```

Optional extras:

| Extra | Enables | Install |
| --- | --- | --- |
| `ui` | the embedded web explorer (`sorb ui` / `sorb serve`) | `pip install "sorb[ui]"` |
| `disk` | qcow2/VMDK/ext4/XFS/Btrfs/NTFS/LVM disk-image scanning | `pip install "sorb[disk]"` |
| `wasm` | sandboxed WASM cataloger plugins | `pip install "sorb[wasm]"` |
| `grpc` | out-of-process gRPC plugins | `pip install "sorb[grpc]"` |

The base install intentionally stays lean; extras only affect their own
subcommands.

## Quick start

```bash
sorb scan .                                  # scan the current repo, human summary
sorb scan . -o cyclonedx-json -f sbom.json   # write a CycloneDX 1.6 SBOM
sorb scan image:alpine:3.20                  # scan a container image, layer-accurately
sorb explain pkg:npm/left-pad@1.3.0          # why is this component in my SBOM?
sorb query 'components where confidence < 0.9'
sorb ui .                                    # scan, then explore in the browser
```

## Concepts

Five terms appear throughout `sorb`'s output. They are worth two minutes.

**Component** — one piece of software in the result: a library, an OS package,
an application, a certificate. Components are what an SBOM lists.

**Evidence** — the bytes that prove a component is there. Every component
carries at least one evidence record naming a file, a line, the detector that
read it, and what it read. Nothing is asserted without one, which is why
`sorb explain` can always answer "how do you know?".

**Evidence tier** — how close that proof is to the running system. Four rungs,
weakest to strongest:

| Tier | Means | Read from |
| --- | --- | --- |
| `declared` | somebody asked for it | `package.json`, `pyproject.toml` |
| `locked` | a resolver pinned it | `package-lock.json`, `poetry.lock` |
| `installed` | it is on disk | `node_modules/`, dpkg/apk/rpm databases |
| `observed` | it was loaded at runtime | `sorb trace`, `/proc` |

A higher tier wins when sources disagree: if the lockfile says 2.31 and the
installed package is 2.32, the answer is 2.32 and the disagreement is reported
as drift rather than silently dropped.

**Confidence** — a 0–1 score derived from the evidence, never a guess. Multiple
independent sources agreeing raises it; a file in a test fixture lowers it; the
tier caps it. `sorb explain` shows the arithmetic.

**Reconciliation** — the step that turns many raw findings into one component
list. A package named by a manifest, a lockfile and an install record is one
component with three pieces of evidence, not three components.

**purl** — the [package URL](https://github.com/package-url/purl-spec) standard
for naming a package unambiguously, e.g. `pkg:npm/left-pad@1.3.0`. When a
version cannot be resolved, `sorb` emits a *versionless* purl rather than
inventing one.

## `sorb scan` - targets

```
sorb scan [TARGET] [flags]
```

| Target syntax | Scans |
| --- | --- |
| `.` / `path/to/dir` | a source tree (lockfiles, manifests, vendored code, binaries) |
| `path/to/file` | a single file (archive, binary, manifest, …) |
| `image:REF` | a container image, registry-direct (no daemon needed) |
| `oci-dir:PATH` | an OCI layout directory |
| `docker-archive:TAR` | a `docker save` tarball |
| `docker:REF` / `podman:REF` / `containerd:REF` | an image via the local daemon/runtime |
| `container://ID` | a *running* container |
| `host://` | the running machine — package databases and install directories are read directly, rather than crawling the whole disk |
| `disk://IMAGE` | a disk image, read without mounting it or needing root (`[disk]` extra for ext4/NTFS/qcow2/…) |

## `sorb scan` - output

`-o/--output` is repeatable; `-f/--file` pairs positionally with each `-o`
(default: stdout).

| Format | Description |
| --- | --- |
| `cyclonedx-json` | CycloneDX 1.6 (includes CBOM/ML-BOM properties where found) |
| `spdx-json` | SPDX 2.3 |
| `spdx3-json` | SPDX 3.0 |
| `sorb` | native format - lossless round-trip of the evidence graph |
| `table` / `tree` / `summary` | human renderers |

```bash
sorb scan . -o cyclonedx-json -f sbom.cdx.json -o spdx-json -f sbom.spdx.json
```

Third-party emitter plugins add their own format names.

## `sorb scan` - commonly used flags

| Flag | Effect |
| --- | --- |
| `--scope runtime\|dev\|all` | emission filter |
| `--min-confidence F` | drop components below a confidence threshold |
| `--paranoid` | only components backed by locked-tier-or-better evidence |
| `--offline` | disable all network access |
| `--resolve pure\|native\|off` | `native` runs the ecosystem's own build tool inside a deny-by-default sandbox and reads what it resolved (Linux and macOS; see below) |
| `--allow-net HOST` | hosts the sandbox/enrichment may reach (repeatable) |
| `--platform linux/arm64` | image platform (default `linux/amd64`) |
| `--all-platforms` | scan every platform in a multi-arch index |
| `--include-removed` | also emit packages deleted during the image build |
| `--follow-images` | chase image refs found in IaC into container scans |
| `--dockerfile PATH` | cross-link image layer history against a Dockerfile |
| `--reproducible` | honor `SOURCE_DATE_EPOCH`; byte-identical output |
| `--evidence minimal\|standard\|full` | how much evidence detail to embed |
| `--cache` | reuse detector results by content hash |
| `--remote-cache URL` | shared HTTP cache for CI fleets (fail-open) |
| `--no-accel` | force the pure-Python reference implementation |
| `--env k=v` | target environment matrix (repeatable) |
| `--project NAME` | limit to one workspace member |

## Higher-fidelity resolution

Static analysis is the default and needs nothing. `--resolve=native` goes
further, running the ecosystem's own build tool (Maven, Gradle, npm, pnpm,
PEP 517, Swift, sbt, Bazel) so its exact resolution can be ingested as
locked-tier evidence:

```bash
sorb scan . --resolve=native
```

The child runs with no ambient credentials, a throwaway `HOME`, and no
network - user/mount/net namespaces plus a seccomp filter on Linux, a
generated Seatbelt profile on macOS. There is no Windows sandbox, so
`--resolve=native` refuses there rather than running a build tool unconfined;
`--dangerously-no-sandbox` accepts that risk explicitly, and
`--allow-net HOST` opens outbound network for toolchains that need a registry.
Any of this failing degrades to a warning and the static result - never a
guess.

## Policy gates and exit codes

`--fail-on` turns findings into CI failures:

```bash
sorb scan . --fail-on drift,stale-lockfile,version-conflict,phantom-deps,low-confidence
```

Exit codes, everywhere:

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | scan errors present (target unreadable, detector failures recorded) |
| 2 | policy failure (`--fail-on` matched, verification failed, diff changed) |
| 3 | usage / config error |
| 4 | internal error |

A single misbehaving file never kills a scan: detector failures degrade to
`analysis-gap` annotations and exit code 1.

## Explaining results

```bash
sorb explain pkg:pypi/requests@2.32.3    # provenance chain + every piece of evidence
sorb explain requests                    # name[@version], digest, or path also work
sorb explain-warning SORB-W031           # what a warning code means + remediation
```

### Exploring a container image

`sorb layers` breaks an image down the way it was built — one row per layer,
with the instruction that created it, how many files it changed, and how many
components it introduced:

```bash
sorb layers image:node:20-alpine         # the layer stack at a glance
sorb layers image:node:20-alpine --layer 2   # what that layer added, with evidence
```

```
image:node:20-alpine
  4 layers · 361 components attributed to a layer

   #   +files     ~     -   comps  instruction
   0      419     0     0     161  ADD alpine-minirootfs-3.23.4-x86_64.tar.gz /
   1     2389     7     0     199  RUN addgroup -g 1000 node && adduser -u 1000 …
   2       14     6     0       1  RUN apk add --no-cache --virtual .build-deps-yarn …
   3        1     0     0       0  COPY docker-entrypoint.sh /usr/local/bin/
```

This answers "which layer introduced this package, and why is it here?" without
leaving the terminal. The web UI draws the same data as an interactive stack.

## Querying the evidence graph

```bash
sorb query 'components where purl ~ "pkg:npm/*" and confidence < 0.9'
sorb query 'components where scope = runtime | count by ecosystem'
sorb query 'paths from . to pkg:npm/minimist@0.0.8'          # from the root project
sorb query 'paths from project:apps/web to pkg:npm/minimist@0.0.8'
sorb query '...' -o json                 # machine-readable
sorb query '...' --run path/to/run.sorb.db
```

The same DSL powers `sorb fleet -q` and the UI's query console.

## Working with foreign SBOMs

```bash
sorb convert other.spdx.json -o cyclonedx-json --loss-report
sorb merge a.cdx.json b.spdx.json -o cyclonedx-json --strategy union
sorb diff old.cdx.json image:app:2.0 --fail-on-change
sorb validate sbom.json --require ntia,tr03183
```

Inputs to `convert`/`merge`/`diff` may be SBOM files (CycloneDX/SPDX/native),
`.sorb.db` run stores, or container image refs (scanned on the fly). Merge
strategies: `union`, `hierarchical`, `intersect`.

## Signing and attestation

Air-gapped, key-based (DSSE); no network involved:

```bash
sorb sign sbom.json --generate-key --key release.key   # writes release.key/.pub
sorb attest sbom.json --key release.key \
     --subject-digest sha256:… [--attach image:REF]
sorb verify sbom.json.sig --key release.pub --sbom sbom.json
sorb verify sbom.json.att --key release.pub --subject-digest sha256:…
```

`verify` runs its checks in order and reports each discretely; any failure
exits 2. Pass `--sbom` (or `--subject-digest`) whenever you have the artifact:
that is what binds the signature to *these* bytes, so an attestation that is
validly signed but describes something else is rejected. Without either, the
subject check is reported as skipped - the signature is verified, but nothing
ties it to a particular file.

## Runtime observation

```bash
sorb trace -- npm test            # scan, run the command, record what it loads
sorb snapshot -- ./provision.sh   # diff installed state before/after a step
sorb watch --iterations 5 -- ./run-server.sh
```

`trace` upgrades components that were actually loaded to the *observed* tier
and surfaces **phantom** (observed but undeclared) and **unused** (declared but
never loaded) dependencies - `--fail-on phantom-deps` gates on them.

## Fleet aggregation

```bash
sorb fleet '.sorb/results/*.sorb.db' \
  -q 'components where name = openssl and version < "3.0.14" and observed = true'
```

Aggregates many host/image run stores into one graph with per-source
provenance, so org-wide questions answer per host.

## The web UI

```bash
sorb ui .            # scan, then open the explorer (findings stream in live)
sorb ui run.sorb.db  # open an existing result
sorb serve --bind 0.0.0.0 --port 8080   # headless twin for CI/shared hosts
```

Fully offline and self-contained: strict CSP, per-session token auth, and
DNS-rebinding defense. `--allow-scan` opts in to launching scans from the
browser; non-loopback binds require token auth. Behind a reverse proxy, name
each external hostname with `--allowed-host` (repeatable) so the Host-header
check accepts it. Requires the `[ui]` extra.

## Maintenance commands

```bash
sorb config .        # effective config + where each value came from
sorb cache stats|prune|clear     # local content-addressed cache
sorb cache serve     # reference shared-cache server for a CI fleet
sorb db update pack.tar --key pub.pem   # install a signed data pack
sorb db status
sorb accel           # show pure vs accelerated tier
sorb bench --baseline baseline.json     # perf regression + startup gates
sorb self update bundle --signature bundle.sig   # signed standalone-bundle update
```

## Configuration

Precedence, highest first:

1. CLI flags
2. `SORB_*` environment variables (`SORB_SCOPE=runtime`, `SORB_OFFLINE=1`, …)
3. Project `sorb.toml` (or `.sorb/sorb.toml`) - nearest ancestor of the target
4. User config
5. Built-in defaults

`sorb.toml` sections mirror the flags 1:1:

```toml
[scan]
scope = "runtime"
min_confidence = 0.8
output = ["cyclonedx-json"]
```

`sorb config` prints the effective configuration with the origin of every
value. Scan results live in the project's `.sorb/results/` workspace; each run
is a self-contained SQLite store (`<run-id>.sorb.db`) that every other command
(`explain`, `query`, `ui`, `fleet`, `diff`, …) reads.

## Plugins

Third-party catalogers and emitters install as Python entry-point packages and
are picked up automatically. The two out-of-process tiers are opt-in per
project, because running them is a decision the project has to make:

```toml
[plugins]
wasm = [
  { namespace = "acme", module = "plugins/acme.wasm",
    signature = "plugins/acme.wasm.sig", key = "plugins/acme.pub" },
]

[plugins.grpc]
trusted = ["cataloger.internal:50051"]
services = [{ namespace = "cloudsnap", endpoint = "cataloger.internal:50051" }]
```

WASM plugins must be signed and run with no filesystem, network, or
environment access; gRPC endpoints are contacted only when listed in
`trusted`. Findings from every tier are re-validated before ingestion. A
plugin that cannot be loaded is reported (`SORB-W064`/`SORB-W065`) and the
scan continues without it. See [`plugins.md`](./plugins.md) for the ABI and
the full contract.
