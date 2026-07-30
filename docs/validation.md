# Validation

What has been checked against real software, how, and what has not. Every
"validated" row below was run against a real artifact, not a fixture. Numbers
are from a macOS arm64 host; treat them as evidence that a path works, not as
a benchmark.

The fixture suites (`tests/`) are the regression net. This document is about
the wider question those suites cannot answer on their own: does `sorb` tell
the truth about software it has never seen?

## Method

Three independent checks, because each catches what the others miss.

| Check | What it proves | How |
| --- | --- | --- |
| **Evidence audit** | No hallucination: every emitted component is provable from bytes on disk | Re-open the file each component's evidence cites, and re-prove the name, version and line independently of the cataloger that produced them |
| **Differential** | Recall and identity: we do not miss what others find, and we name things the same way | Compare purls against `syft` on the same target; every disagreement is triaged in `tests/differential/ledger.json` |
| **Package-manager ground truth** | Installed state is real: what we report matches what the tool actually installed | Compare against `npm ls --all`, pip's `dist-info` records, and `nm -D` for binary symbols |

The evidence audit is the strongest of the three. A differential comparison
only shows where two tools disagree; it cannot tell you that both are wrong.
Re-deriving each claim from the cited bytes can.

Two things a naive text audit gets wrong, and any re-implementation must
handle: certificate subjects live in DER inside base64, so they are real
evidence that is not plain text; and PyPI names are lowercased per PEP 503, so
`pyjwt` legitimately cites a line reading `PyJWT==2.12.0`.

## Evidence audit results

| Target | Kind | Components | Backed by cited bytes |
| --- | --- | --- | --- |
| `hashicorp/vault` | Go + JS + Terraform monorepo | 3013 | 100% |
| `jitsi/jitsi-meet` | JS + Java + ObjC + Ruby monorepo | 2406 | 100% |
| `grpc/grpc` | 14-ecosystem monorepo | 562 | 99.6% (2 are audit-tool case artifacts) |
| `npm install` tree | real `node_modules` | 139 | 100% |
| `uv pip install` venv | real `site-packages` | 129 | 100% |

The audit is what found the two fabrication sources fixed in this release: a
Dockerfile `RUN` parser that read operands of the *next* shell command as
packages, and Terraform evidence that cited line 1 for every resource.

## Source ecosystems

| Ecosystem | Artifact validated against | Result |
| --- | --- | --- |
| npm (lockfile v3) | `npm/cli` v10.9.2 `package-lock.json`, 1281 packages | 1029 components, 2103 dependency edges, full transitive provenance |
| npm (manifest only) | `expressjs/express` `package.json` | Unresolved deps emitted with versionless purls |
| npm (installed) | real `node_modules` after `npm install` | 137/137 vs `npm ls --all`, zero missed |
| PyPI (lockfile) | `python-poetry/poetry` `poetry.lock` | 69/69 purl parity with syft |
| PyPI (manifest) | `pallets/flask` `pyproject.toml` | 9 identities where syft emits none |
| PyPI (installed) | real venv `site-packages` | Exact match with pip's `dist-info` records |
| Go modules | `kubernetes/kubernetes` v1.31, `prometheus/prometheus` v2.54 | Local-path `replace` no longer emitted as packages |
| Go (binary buildinfo) | the `syft` binary itself, 57 MB | 238 modules vs syft's 239 |
| Cargo | `BurntSushi/ripgrep` 14.1.1 lock + manifest | 61/61 exact purl parity with syft |
| Cargo (workspace) | `tokio-rs/tokio` root manifest | Workspace root with no deps handled |
| Maven | `spring-projects/spring-petclinic` `pom.xml` | 29/29 exact purl parity with syft |
| RubyGems | `rails/rails` v7.2.1 `Gemfile.lock` | Platform variants collapsed to one gem version |
| Composer | `laravel/laravel` v11 `composer.json` | Parsed; lock not available upstream |
| CocoaPods | `jitsi-meet` | 125 components |
| Terraform | `hashicorp/vault` enos modules | 170 components, spans now cite the declaring line |
| Dockerfile | `grpc`, `jitsi-meet` | Predicted installs stop at the shell command boundary |
| dpkg / apk / rpm | container images below | See containers |

## Monorepos

Shallow clones of real repositories, chosen for genuine multi-language content.

| Repository | Files | Ecosystems found | Components | Warm scan |
| --- | --- | --- | --- | --- |
| `grpc/grpc` | 10500 | 14 (npm, pypi, gem, maven, nuget, composer, deb, apk, rpm, cmake, oci, crypto, c, github) | 562 | 4.7s |
| `hashicorp/vault` | 9164 | 9 (golang, npm, terraform, deb, apk, rpm, oci, crypto, c) | 3013 | 7.9s |
| `jitsi/jitsi-meet` | 3139 | 8 (npm, cocoapods, gem, maven, deb, oci, crypto, c) | 2406 | 2.7s |
| `getsentry/sentry` | 20764 | 5 (npm, pypi, deb, oci, c) | 2240 | see note |

Note: sentry's scan completes but was not re-audited after the final fixes;
its number above predates them.

A cold scan of a freshly cloned tree is dominated by disk I/O, not by `sorb`:
grpc took 87s cold and 4.7s warm on the same machine with the same code.

## Container images

Registry-direct pulls, no daemon.

| Image | Base | Components | Parity |
| --- | --- | --- | --- |
| `alpine:3.20` | apk | 14 apk + 145 certificates | 14/14 purl parity with syft |
| `debian:12-slim` | deb | 88 | |
| `ubuntu:24.04` | deb | 92 | |
| `python:3.12-slim` | deb | 281 across 5 ecosystems | |
| `node:20-alpine` | apk | 360 including 192 npm | |
| `nginx:1.27-alpine` | apk | 217 | |
| `gcr.io/distroless/static-debian12` | distroless | 146 from 4 deb records | Distroless yields a real inventory |

Warm-cache scans after the referrers-caching fix: alpine 0.45s, nginx 0.69s,
node 1.04s, python 1.10s.

## Binaries

| Artifact | Format | Checked against | Result |
| --- | --- | --- | --- |
| `libcrypto.so.3` (Debian aarch64) | ELF | `nm -D` | 5859/5859 exported, 0 missed |
| `libssl.so.3` (Debian aarch64) | ELF | `nm -D` | 604/604 exported, 0 missed |
| `python3.12` (Debian aarch64) | ELF | `nm -D` | Symbols, needed, soname, build-id |
| `syft` | Mach-O + Go buildinfo | syft | 238 modules vs 239 |
| `/bin/ls` | Mach-O universal | `file` | Both slices parsed, 3 dylibs each |
| `/usr/bin/python3` | Mach-O universal | syft | Both report no components (no embedded truth) |

Symbol versions (`GLIBC_2.34`, `OPENSSL_3.0.0`) are recovered from
`.gnu.version` with verneed and verdef, and a library's own version labels are
excluded from its interface.

## Commands, formats and policy

Every documented example in `docs/usage.md` was run verbatim.

| Area | Validated |
| --- | --- |
| Commands | `scan`, `explain`, `explain-warning`, `query`, `convert`, `merge`, `diff`, `validate`, `fleet`, `config`, `cache stats/prune/clear`, `db status`, `accel`, `bench`, `sign`, `attest`, `verify`, `trace`, `snapshot`, `ui`, `serve`, `self update` |
| Output formats | `cyclonedx-json`, `spdx-json`, `spdx3-json`, `sorb`, `table`, `tree`, `summary` |
| Query DSL | Comparisons, globs, `and`/`or`, `count by`, `paths from ... to ...`, `-o json`, `--run` |
| Interop | Any-to-any `convert` with `--loss-report`; `merge` union/hierarchical/intersect; `diff` with `--fail-on-change` |
| Round-trip | Ecosystem survives CycloneDX and SPDX export then re-import; merging the two representations of one scan yields one component set |
| Policy | `--fail-on` with all five codes; exit codes 0/1/2/3 observed as documented |
| Reproducibility | `--reproducible` byte-identical across runs; optimized and naive implementations produce identical SBOMs on 11 real projects |
| Web UI | Live server: `/api/health`, `/api/runs`, components, lod, drift, layers, query, and a browser-launched scan |

## Security

| Property | How it was tested |
| --- | --- |
| Signature substitution refused | A valid attestation over one artifact was presented as the signature for an unrelated payload, through `self update`, WASM plugin loading and data-pack install. All three refuse |
| Tampered artifact refused | Byte-modified SBOM against a valid detached signature |
| Wrong key refused | Signature verified against a different public key |
| Subject binding | `verify --sbom` and `--subject-digest` both bind; a mismatch exits 2 |
| Unsigned plugin refused | WASM plugin without a signature bundle |
| Plugin cannot impersonate | A plugin claiming `os/dpkg@1` is forced into `plugin:<ns>/dpkg@1` |
| Plugin confidence ceiling | A plugin claiming high confidence is capped at its technique's base rate |
| Offline kill-switch | `--offline` scans succeed from cache and never open a socket; the test suite blocks `socket.connect` outright |

## Plugins

| Tier | Validated |
| --- | --- |
| Entry-point | Example package discovered by installation; findings namespaced |
| WASM | Real signed guest module executed end to end through the CLI, producing a component in the SBOM. Missing exports, ABI mismatch, oversized returns and traps all handled |
| gRPC | Wire codec round-trip and client shim against a fake channel; trust gate and dead-endpoint containment |

## Pending

Not yet validated, with the reason. Nothing here is known to be broken; it is
unproven.

| Scenario | Why it is pending |
| --- | --- |
| **Windows, end to end** | No Windows host available. Affects path handling, the registry cataloger against a live hive, and PE-specific paths. `--resolve=native` deliberately refuses on Windows |
| **Linux sandbox (`--resolve=native`)** | Only the macOS Seatbelt path was exercised. The namespace and seccomp path needs a Linux host, including the escape tests |
| **Native drivers beyond PEP 517** | Maven, Gradle, npm, pnpm, Swift, sbt and Bazel drivers are unit-tested on their parsers only; none has been run against a real project with its toolchain installed |
| **PE binaries** | No real Windows executable or DLL was parsed. PE and Mach-O still do not extract symbols; only ELF and WASM do |
| **Real WASM modules** | The ABI is proven with generated guests. No module built from Rust or TinyGo has been loaded |
| **Mobile artifacts** | No real APK, AAB or IPA. DEX class-tree extraction is a known depth gap |
| **`disk://` with the `dissect` backend** | Only the in-process FAT path is covered. ext4, XFS, Btrfs, NTFS, qcow2, VMDK and LVM are untested against real images |
| **`host://` on Linux and Windows** | Exercised on macOS only (4394 components across 14 ecosystems). The `/proc` runtime-observation path needs a Linux host |
| **Daemon and runtime sources** | `docker:`, `podman:`, `containerd:` and `container://` were not exercised against live daemons; only registry, OCI layout and archive paths were |
| **`--all-platforms`** | No multi-arch index fanned out |
| **RPM-based images** | The rpm readers were exercised on synthesized fixtures and Dockerfile predictions, not on a real Fedora or Rocky image |
| **Signature data packs** | `sorb db update` is tested with generated packs; no real signature pack has been built and installed, so the fingerprint engines have not run against a real corpus |
| **Remote cache** | The reference server is driven in-process. No multi-machine CI fleet has shared a cache |
| **gRPC plugin against a real server** | Only a fake channel. Needs a service implementing `plugin_v1.proto` |
| **Sigstore keyless verification** | Not implemented. `verify` reports the transparency-log step as skipped |
| **`sorb self update` with a real bundle** | Verified with synthetic bundles. No PyInstaller bundle has been produced and swapped in |
| **`sorb-accel`** | The Rust crate is a scaffold. The self-check that would adopt it is tested with a Python stand-in |
| **External conformance** | NTIA and BSI TR-03183 profiles are self-implemented. Output has not been checked against an external CycloneDX or SPDX validator |
| **Fleet at scale** | Aggregation is unit-tested and run over a handful of stores; not against hundreds of hosts |
| **Coverage-guided fuzzing** | Only the deterministic in-process smoke fuzz runs. OSS-Fuzz integration is committed but has not been run |
| **The evidence auditor itself** | Lives outside the repository. It should land in `tests/` so the no-hallucination property is checked every run rather than by hand |

## Reproducing

The differential comparison is wired up:

```bash
python tests/differential/differential_harness.py --refresh   # re-record competitor output
pytest tests/test_accuracy_gates.py -k differential            # every delta must be in the ledger
```

The evidence audit is not yet committed (see Pending). Its logic: for each
non-excluded component in a run store, read the file each evidence record
cites, and require that the component's name occurs in it, that a concrete
version occurs in it, and that the cited line span exists and lands near the
name. Certificates are corroborated by parsing the cited file as certificate
or key material rather than by text.
