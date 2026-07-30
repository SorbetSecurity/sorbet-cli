# Plugins

Three tiers, in increasing order of isolation and decreasing order of trust.
All three produce findings as JSON that `sorb` re-validates before ingestion
(`sorb/plugin/validation.py`): the schema is re-checked, resource caps are
enforced, detector ids are forced into `plugin:<namespace>/…` so a plugin
cannot impersonate a first-party detector, and confidence is capped at the base
rate its technique earns.

## Entry-point plugins

A trusted Python package that registers a cataloger or emitter. Installing it
is all the wiring there is:

```toml
[project.entry-points."sorb.catalogers"]
acme = "sorb_plugin_example:AcmeLockCataloger"

[project.entry-points."sorb.emitters"]
acme = "sorb_plugin_example:AcmeCsvEmitter"
```

A working package is in `examples/sorb-plugin-example/`. A plugin that fails to
import is skipped with a warning, never fatal.

## WASM plugins

Untrusted code, strongly isolated: `pip install 'sorbet[wasm]'`. A plugin is a
signed `.wasm` module, and an unsigned or tampered one is refused before it is
instantiated. Once loaded it gets no filesystem, no network, no environment and
no stdio - only the bytes of files it matched - plus a CPU-fuel budget and a
memory cap.

Declare it in the project's `sorb.toml`:

```toml
[plugins]
wasm = [
  { namespace = "acme", module = "plugins/acme.wasm",
    signature = "plugins/acme.wasm.sig", key = "plugins/acme.pub" },
]
```

Sign one with the same machinery as an SBOM:

```bash
sorb sign plugins/acme.wasm --generate-key --key plugins/acme.key
```

### ABI version 1

A guest exports linear `memory` plus four functions. Returning a packed
`i64` keeps this to plain wasm32 core exports, so a guest needs no multi-value
or component-model support.

| Export | Signature | Contract |
| --- | --- | --- |
| `sorb_abi_version` | `() -> i32` | Must return `1`. |
| `sorb_alloc` | `(i32 size) -> i32` | Return an offset with `size` writable bytes. |
| `sorb_matcher_globs` | `() -> i64` | `ptr << 32 \| len` of a newline-separated glob list. |
| `sorb_analyze` | `(i32 meta_ptr, i32 meta_len, i32 blob_ptr, i32 blob_len) -> i64` | `ptr << 32 \| len` of findings JSON. |

`meta` is a JSON object (`path`, `size`, `role`). The findings document is:

```json
{"findings": [
  {"claim": {"ctype": "library", "name": "acme-widget", "version": "2.1.0",
             "ecosystem": "acme"},
   "evidence": [{"technique": "plugin-analysis", "tier": "declared",
                 "detector": "acme-lock@1",
                 "location": {"source_id": "s1", "path": "thing.acme"}}]}
]}
```

A trap, a fuel exhaustion, an oversized return, or a missing export becomes an
`analysis-gap` annotation on the run - never a failed scan.
`tests/unit/wasm_guest.py` builds conforming guests used by the test suite.

## gRPC plugins

For integrations where WASM is too restrictive - cloud snapshot providers,
proprietary registries: `pip install 'sorbet[grpc]'`. A gRPC plugin runs as a
user-launched process with the host's privileges, so it is contacted **only**
when the endpoint is named in trusted config. Channels are TLS by default;
plaintext is opt-in per endpoint.

```toml
[plugins.grpc]
trusted = ["cataloger.internal:50051"]
insecure = []                        # per-endpoint opt-out of TLS
services = [
  { namespace = "cloudsnap", endpoint = "cataloger.internal:50051" },
]
```

Omit `globs` and the host asks the service via `MatcherGlobs`; supply them to
avoid a startup round-trip. The protocol is
`sorb/plugin/proto/plugin_v1.proto`; messages are encoded by
`sorb/plugin/wire.py`, so the extra installs a transport and no code
generation step. A dead or misbehaving service degrades to an analysis gap.

Trusting the process is not trusting its output: findings still go through the
same re-validation as every other tier.
