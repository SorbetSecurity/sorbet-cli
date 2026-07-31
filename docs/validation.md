# Validation

What has been checked against real software, how, and what has not. Every
"validated" row below was run against a real artifact, not a fixture. Treat the
numbers as evidence that a path works, not as a benchmark.

Host coverage: source, container and binary rows are from a macOS arm64 host;
the Linux rows from containers on a Linux kernel (Docker Desktop's LinuxKit VM,
native `linux/arm64` and `linux/amd64` under emulation); the Windows rows from a
real Windows image parsed registry-direct, with no Windows machine involved.
No live Windows host has been used at all — see Pending.

The fixture suites (`tests/`) are the regression net. This document is about
the wider question those suites cannot answer on their own: does `sorb` tell
the truth about software it has never seen?

## Status

| | |
| --- | --- |
| Ecosystems, monorepos, container images | Validated against real artifacts, with ground-truth parity where a package manager could be asked |
| No hallucination | **1,742 components across 8 real C/C++ projects, 100% re-derivable from the bytes they cite.** Enforced every test run by a committed auditor |
| C/C++ | Validated across vcpkg, Conan, CMake, Meson, pkg-config, Makefile and submodules — static and dynamic |
| Host inventory | macOS: Homebrew formulae and casks at 23/23 against `brew list --versions`. A partial walk now raises `SORB-W017` instead of reporting a near-empty machine as a complete answer |
| Linux-specific paths | Validated: `host://`, `/proc` observation, and the namespace+seccomp sandbox including a network escape test |
| Windows artifacts | Validated at artifact level: PE VERSIONINFO and registry hives, both differentialed against third-party parsers |
| External conformance | CycloneDX 1.6 validated against the official schema; SPDX not yet |
| Live Windows host, podman/containerd, mobile, `disk://` (dissect), WASM, data packs, Sigstore, fleet at scale | Unproven — see Pending |
| Linux sandbox filesystem confinement | A known limitation, not a coverage gap — see Pending |

Real artifacts have found eleven defects fixture suites could not: rpm
databases unreadable on every Fedora/Rocky image, a platform silently skipped
by `--all-platforms`, two crashes that killed a whole scan, a CycloneDX schema
violation on every certificate, `docker:`/`container://` broken outright
against a current daemon, vcpkg feature dependencies never emitted, a Meson
`wrap-git` reporting a package's own name as its version, Conan manifests and
locks splitting into duplicate components, Dockerfile packages citing the wrong
line, and Maven versions whose cited file did not contain them. Each is covered
by a regression test that fails without its fix.

Scanning large C/C++ trees is 15–26% faster than at the start of that round
(`gstreamer` 2.08s → 1.66s, `grpc` 1.85s → 1.42s, `opencv` 1.36s → 1.11s), with
output verified byte-identical before and after.

## Method

Four independent checks, because each catches what the others miss.

| Check | What it proves | How |
| --- | --- | --- |
| **Evidence audit** | No hallucination: every emitted component is provable from bytes on disk | Re-open the file each component's evidence cites, and re-prove the name, version and line independently of the cataloger that produced them |
| **Differential** | Recall and identity: we do not miss what others find, and we name things the same way | Compare purls against `syft` on the same target; every disagreement is triaged in `tests/differential/ledger.json`. Format-specific parsers are differentialed against their own third parties — `pefile` for PE, `python-registry` for hives |
| **Package-manager ground truth** | Installed state is real: what we report matches what the tool actually installed | Compare against `rpm -qa`, `dpkg-query`, `npm ls --all`, pip's `dist-info` records, and `nm -D` for binary symbols |
| **External conformance** | The output is the format we claim, judged by someone else's rules | Validate emitted SBOMs against the format's official published schema, not our own validator |

The evidence audit is the strongest of the four. A differential comparison only
shows where two tools disagree; it cannot tell you that both are wrong.
Re-deriving each claim from the cited bytes can.

External conformance is the cheapest and was the longest missing: sorb's own
`validate` passed documents that the official CycloneDX schema rejected on every
certificate component.

Two things a naive text audit gets wrong, and any re-implementation must
handle: certificate subjects live in DER inside base64, so they are real
evidence that is not plain text; and PyPI names are lowercased per PEP 503, so
`pyjwt` legitimately cites a line reading `PyJWT==2.12.0`.

## Evidence audit results

| Target | Kind | Components | Backed by cited bytes |
| --- | --- | --- | --- |
| `hashicorp/vault` | Go + JS + Terraform monorepo | 3013 | 100% |
| `jitsi/jitsi-meet` | JS + Java + ObjC + Ruby monorepo | 2406 | 100% |
| `grpc/grpc` | 14-ecosystem monorepo | 562 | 100% |
| `npm install` tree | real `node_modules` | 139 | 100% |
| `uv pip install` venv | real `site-packages` | 129 | 100% |
| `gstreamer/gstreamer` | Meson + Rust + 200 subprojects | 881 | 100% |
| `opencv/opencv` | CMake + Maven + WinRT | 89 | 100% |
| `curl/curl`, `facebook/folly`, `redis/redis`, `nlohmann/json`, `microsoft/terminal` | C/C++ | 210 | 100% |

The auditor is committed (`tests/evidence_audit.py`) and runs as a gate in
`tests/test_accuracy_gates.py`, so the no-hallucination property is checked on
every test run rather than by hand. A companion test plants a component that
the cited file does not support and requires the audit to fail — a gate that
cannot fail is not a gate.

The audit is what found the fabrication sources fixed so far: a Dockerfile
`RUN` parser that read operands of the *next* shell command as packages,
Terraform evidence that cited line 1 for every resource, a Dockerfile package
citing the first line of its `RUN` rather than the continuation line that names
it, a Meson `wrap-git` reporting the package's own name as its version, and a
Maven version interpolated from a parent pom whose only cited file showed
`${property}`.

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
| C/C++ vcpkg | `microsoft/terminal` manifest + overrides | 5/5 dependencies; deps declared under `features` are emitted and scoped optional |
| C/C++ Conan | `conanfile.txt` + `conan.lock` v2 | Manifest and lock reconcile to one component per package, lock's recipe revision retained |
| C/C++ CMake | `opencv`, `folly`, `curl`, `grpc` | `find_package`/`FetchContent` parsed; File API codemodel read without executing CMake |
| C/C++ Meson | `gstreamer` subprojects + wrap fixtures | `wrap-file` versions from the directory, `wrap-git` from `revision`; never the package's own name |
| C/C++ long tail | pkg-config `.pc`, `Makefile` `-l`, `.gitmodules` | Parsed; submodule pinned commits land as locked tier |
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
| `gstreamer/gstreamer` | 12114 | 11 (cargo, npm, meson, crypto, deb, maven, ml, nuget, c, cmake, github) | 881 | 1.7s |
| `opencv/opencv` | 7823 | 6 (cmake, crypto, maven, npm, oci, pypi) | 89 | 1.1s |

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
| `fedora:41` | rpm (sqlite) | 125 rpm + 379 certificates | **125/125 name+version parity with `rpm -qa`**, 0 missing, 0 extra |
| `rockylinux:9` | rpm (sqlite) | 141 rpm + 354 certificates | 141/141 against `rpm -qa` |
| `mcr.microsoft.com/windows/nanoserver:ltsc2022` | Windows | 122 from 3,604 files | See *Windows artifacts* below |

Real rpm images were what exposed the sqlite reader failing on every one of
them: an actual `rpmdb.sqlite` is in WAL mode, and SQLite cannot use WAL
journaling on a deserialized in-memory database. The synthesized fixtures used
`conn.serialize()`, which produces a rollback-journal database, so no fixture
could have caught it. Every Fedora/Rocky image silently reported **zero** rpm
packages behind a single contained `analysis-gap`.

Multi-arch fan-out is exercised against `alpine:3.20`: 8 index entries, 8
distinct images. It previously produced 7 — `linux/arm/v6` and `linux/arm/v7`
both collapsed to `linux/arm`, so one was scanned twice and the other never.

## Windows artifacts

No Windows host was involved. `sorb` pulls registry-direct and parses bytes, so
a real Windows image can be read from any OS — which is what makes these rows
checkable at all.

| Property | Method | Result |
| --- | --- | --- |
| PE VERSIONINFO | 4 real `System32` DLLs compared against `pefile` | **4/4 exact** on ProductName + ProductVersion |
| Registry hives | real `SYSTEM` hive vs `python-registry` | **58/58 exact** (Start ∈ boot/system/auto), 0 false positives |
| Windows path handling | 3,604-file layer, `Files/` and `UtilityVM/Files/` prefixes | 0 analysis gaps; the two trees reconcile into one component set |

The image also surfaced a scan-killing crash: `mcr.microsoft.com` attaches
binary referrer blobs, and `json.loads` on non-UTF-8 bytes raises
`UnicodeDecodeError`, which is *not* a `JSONDecodeError` — so it escaped the
handler and aborted the whole scan.

## Linux-specific paths

Run inside containers on a Linux kernel (Docker Desktop's LinuxKit VM, both
`linux/amd64` under emulation and native `linux/arm64`).

| Property | Method | Result |
| --- | --- | --- |
| `host://` on Linux | `python:3.13-slim`, compared against `dpkg-query` | **87/87 name+version**, 0 missing, 0 extra |
| `/proc` runtime observation | same scan | 6 observed-tier components (kernel + modules) |
| `--resolve=native` sandbox | PEP 517 build inside namespaces + seccomp, native arm64 | Resolved 2 dependencies at locked tier — unshare, uid/gid map, tmpfs and the seccomp filter all applied |
| Network escape | build backend attempting an outbound socket | **Denied** in the sandbox; reached with `--dangerously-no-sandbox` (control) |
| Sandbox unavailable | default Docker seccomp, which blocks `unshare(2)` | Refused and degraded to `SORB-W015`; the build tool never runs unconfined |

Two caveats worth stating plainly:

- **Filesystem writes outside the scratch home are not denied.** The Linux
  sandbox unshares user/mount/net namespaces, mounts a private tmpfs over the
  scratch home, applies rlimits and a seccomp *blocklist* of ten syscalls. It
  does not remount the root filesystem read-only, so a build backend can still
  write to `/tmp`, `$HOME`, or the project tree — verified by a build script
  that did exactly that. "Deny-by-default" in the README describes the network
  and the scratch home, not the whole filesystem.
- On `linux/amd64` under Rosetta emulation the seccomp filter is rejected with
  `EINVAL` (BPF filters are architecture-specific). This is an emulation
  artifact, not a sandbox defect: the same code applies the filter successfully
  on native `linux/arm64`. Either way the failure is refusal, not exposure.

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
| External conformance | CycloneDX **1.6 official JSON schema**: 4 real SBOMs (repo, `alpine:3.20`, `fedora:41`, nanoserver — 1,000 components total) validate with **0 errors**. Before this, every certificate component was invalid: `certificateProperties` is closed to 8 fields and `certificateFingerprint` is not one of them (645 violations). The fingerprint now rides in `hashes` |
| Daemon & runtime sources | `docker:` and `container://` against Docker 29.2 — both produce a byte-identical component set to the registry-direct scan of the same image. Required negotiating the engine API version: the hardcoded `v1.43` is below Docker 29's `MinAPIVersion` of 1.44, so every request returned 400 |
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

Not yet validated, with the reason. These are unproven rather than broken, with
one exception stated as such: the Linux sandbox does not confine filesystem
writes outside the scratch home. That one is a measured limitation, not a gap in
coverage.

| Scenario | Why it is pending |
| --- | --- |
| **Windows, live host** | Artifact parsing is now validated against a real Windows image (PE VERSIONINFO, registry hives, layer path handling). What remains unproven needs an actual Windows machine: path handling on a live NTFS filesystem, the registry cataloger against a mounted live hive, and that `--resolve=native` refuses there as designed |
| **Linux sandbox, filesystem confinement** | Namespaces, seccomp and network denial are validated. The root filesystem is *not* remounted read-only, so a build tool can write outside the scratch home — verified, and left as-is deliberately: making it read-only would break build tools that legitimately write to caches and `/tmp`, so it is a policy decision rather than a bug fix |
| **Linux sandbox on x86-64** | The namespace+seccomp path is proven on native `linux/arm64`. On `linux/amd64` it could only be run under Rosetta emulation, where the kernel rejects the (architecture-specific) BPF filter. Needs a native x86-64 Linux host |
| **C/C++ native build execution** | The static path is validated broadly. `--resolve=native` has no C/C++ driver: CMake/Meson configure steps are not run, so a dependency that only exists after configure (a generated `CMakeCache`, a resolved `FetchContent`) is out of static scope |
| **Native drivers beyond PEP 517** | Maven, Gradle, npm, pnpm, Swift, sbt and Bazel drivers are unit-tested on their parsers only; none has been run against a real project with its toolchain installed. PEP 517 is now exercised end to end inside the Linux sandbox |
| **PE symbols** | Real PE files are now parsed and their VERSIONINFO checked against `pefile`. PE and Mach-O still do not extract *symbols*; only ELF and WASM do |
| **`podman:` and `containerd:` sources** | `docker:` and `container://` are validated against a live Docker 29.2 daemon. The podman and containerd paths share the client but were not exercised against those runtimes |
| **SPDX external conformance** | CycloneDX 1.6 output is validated against the official schema. The SPDX 2.3 and 3.0 emitters have not been checked against an external SPDX validator, and the NTIA/BSI profiles remain self-implemented |
| **Real WASM modules** | The ABI is proven with generated guests. No module built from Rust or TinyGo has been loaded |
| **Mobile artifacts** | No real APK, AAB or IPA. DEX class-tree extraction is a known depth gap |
| **`disk://` with the `dissect` backend** | Only the in-process FAT path is covered. ext4, XFS, Btrfs, NTFS, qcow2, VMDK and LVM are untested against real images |
| **`host://` on Windows** | Exercised on macOS (Homebrew 23/23 parity with `brew list --versions`) and Linux (87/87 dpkg parity, `/proc` observation). A Windows host remains untested |
| **Signature data packs** | `sorb db update` is tested with generated packs; no real signature pack has been built and installed, so the fingerprint engines have not run against a real corpus |
| **Remote cache** | The reference server is driven in-process. No multi-machine CI fleet has shared a cache |
| **gRPC plugin against a real server** | Only a fake channel. Needs a service implementing `plugin_v1.proto` |
| **Sigstore keyless verification** | Not implemented. `verify` reports the transparency-log step as skipped |
| **`sorb self update` with a real bundle** | Verified with synthetic bundles. No PyInstaller bundle has been produced and swapped in |
| **`sorb-accel`** | The Rust crate is a scaffold. The self-check that would adopt it is tested with a Python stand-in |
| **Fleet at scale** | Aggregation is unit-tested and run over a handful of stores; not against hundreds of hosts |
| **Coverage-guided fuzzing** | Only the deterministic in-process smoke fuzz runs. OSS-Fuzz integration is committed but has not been run |

## Reproducing

The differential comparison is wired up:

```bash
python tests/differential/differential_harness.py --refresh   # re-record competitor output
pytest tests/test_accuracy_gates.py -k differential            # every delta must be in the ledger
```

Real-artifact checks from the rounds above, each needing only Docker and
network:

```bash
# rpm ground truth (expects exact parity)
docker run --rm --platform linux/amd64 fedora:41 rpm -qa | wc -l
sorb scan image:fedora:41 -o summary

# multi-arch: 8 index entries must yield 8 distinct images
sorb scan image:alpine:3.20 --all-platforms -o summary

# Windows artifacts, no Windows host required
sorb scan image:mcr.microsoft.com/windows/nanoserver:ltsc2022 \
  --platform windows/amd64 -o summary

# Linux host inventory vs dpkg, inside a container
docker run --rm -v "$PWD:/w" -w /w python:3.13-slim bash -c \
  'pip install -qe . && sorb scan host:// -o summary && dpkg-query -W | wc -l'

# external CycloneDX conformance
pip install jsonschema
curl -sO https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json
sorb scan . -o cyclonedx-json -f out.json   # then validate out.json against it
```

The evidence audit is not yet committed (see Pending). Its logic: for each
non-excluded component in a run store, read the file each evidence record
cites, and require that the component's name occurs in it, that a concrete
version occurs in it, and that the cited line span exists and lands near the
name. Certificates are corroborated by parsing the cited file as certificate
or key material rather than by text.
