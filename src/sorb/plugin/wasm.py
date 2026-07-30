"""WASM plugin host for *untrusted* third-party catalogers.

The strong-isolation tier: a plugin is a signed WASM module that receives only
matched-file streams and returns findings JSON — no ambient filesystem or network
capability, a CPU-fuel limit, and re-validation of everything it returns
(`sorb.plugin.validation`). Distribution is signed OCI artifacts verified with the
same DSSE machinery as data packs — an **unsigned or tampered plugin is
refused before it is ever instantiated**.

The wasmtime runtime is an optional dependency (`sorbet[wasm]`); the security
seams that don't need it — signature verification, findings re-validation, the
capability-free execution *policy* — are exercised directly. `WasmCataloger` takes
its `analyze` bridge as a callable, so the whole cataloger path is testable with a
Python stand-in while `load_wasm_plugin` supplies the real wasm-backed bridge.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher
from sorb.errors import DetectorFailure, UsageError
from sorb.model import Finding
from sorb.plugin.validation import validate_findings_json
from sorb.source.base import Entry

#: fuel bounds CPU work; memory + table sizes are capped at instantiation.
DEFAULT_FUEL = 2_000_000_000
MAX_MEMORY_BYTES = 256 * 1024 * 1024
#: a guest cannot force the host to materialize an unbounded findings buffer.
MAX_RETURN_BYTES = 32 * 1024 * 1024

AnalyzeFn = Callable[[dict[str, object], bytes], bytes]


class PluginSignatureError(UsageError):
    """A WASM plugin was unsigned or its signature did not verify."""


class PluginRuntimeError(UsageError):
    """The WASM runtime is unavailable or failed to instantiate the module."""


class WasmCataloger(Cataloger):
    """A cataloger whose `analyze` runs in a sandbox; output is re-validated."""

    def __init__(
        self, namespace: str, globs: list[str], analyze: AnalyzeFn, version: int = 1
    ) -> None:
        self.id = f"wasm/{namespace}"
        self.version = version
        self.matchers = [Matcher(glob=g) for g in globs]
        self._analyze = analyze
        self._namespace = namespace

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        meta: dict[str, object] = {"path": entry.path, "size": entry.size, "role": entry.role}
        try:
            raw = self._analyze(meta, blob)
        except Exception as e:  # sandbox trap / fuel exhaustion / crash → contained
            raise DetectorFailure(f"wasm plugin {self._namespace} trapped: {type(e).__name__}") from e
        # NOTHING the plugin returned is trusted until it passes schema + limits.
        yield from validate_findings_json(raw, namespace=self._namespace)


def verify_plugin_signature(
    artifact: bytes, *, signature_bundle: bytes, public_key_pem: bytes
) -> bool:
    """True iff the signature verifies over the exact plugin bytes."""
    from sorb.emit.signing import verify_artifact

    return verify_artifact(
        artifact, signature=signature_bundle, public_key_pem=public_key_pem
    )


def load_wasm_plugin(
    artifact: bytes,
    *,
    namespace: str,
    signature_bundle: bytes | None = None,
    public_key_pem: bytes | None = None,
    fuel: int = DEFAULT_FUEL,
) -> WasmCataloger:
    """Verify + instantiate a WASM plugin. Refuses unsigned; sandboxes execution."""
    if signature_bundle is None or public_key_pem is None:
        raise PluginSignatureError(
            f"wasm plugin {namespace!r} is unsigned — refused (WASM plugins must be signed OCI artifacts)"
        )
    if not verify_plugin_signature(
        artifact, signature_bundle=signature_bundle, public_key_pem=public_key_pem
    ):
        raise PluginSignatureError(f"wasm plugin {namespace!r} signature did not verify — refused")

    try:
        import wasmtime
    except ImportError as e:  # pragma: no cover - optional dependency
        raise PluginRuntimeError(
            "wasm plugin support needs the runtime — `pip install 'sorbet[wasm]'`"
        ) from e

    return _instantiate(wasmtime, artifact, namespace, fuel)


def _instantiate(wasmtime: object, artifact: bytes, namespace: str, fuel: int) -> WasmCataloger:
    """Capability-scoped instantiation: WASI with no preopens/env/stdio, a memory
    cap, and a CPU-fuel budget — no ambient FS or network is ever granted."""
    config = wasmtime.Config()  # type: ignore[attr-defined]
    config.consume_fuel = True
    engine = wasmtime.Engine(config)  # type: ignore[attr-defined]
    store = wasmtime.Store(engine)  # type: ignore[attr-defined]
    store.set_fuel(fuel)
    store.set_limits(memory_size=MAX_MEMORY_BYTES)
    wasi = wasmtime.WasiConfig()  # type: ignore[attr-defined]
    # deliberately grant NOTHING: no preopen_dir(), no inherit_env/stdout/stdin.
    store.set_wasi(wasi)
    try:
        module = wasmtime.Module(engine, artifact)  # type: ignore[attr-defined]
        linker = wasmtime.Linker(engine)  # type: ignore[attr-defined]
        linker.define_wasi()
        instance = linker.instantiate(store, module)
    except Exception as e:
        raise PluginRuntimeError(f"wasm plugin {namespace!r} failed to instantiate: {e}") from e

    abi = _Abi(store, instance, namespace)
    abi.check_version()
    return WasmCataloger(namespace, abi.matcher_globs(), abi.analyze)


class _Abi:
    """Host side of the plugin ABI (`docs/plugins.md`).

    A guest exports linear `memory` plus:

    - ``sorb_abi_version() -> i32``
    - ``sorb_alloc(i32 size) -> i32``
    - ``sorb_matcher_globs() -> i64``  packed ``ptr << 32 | len``
    - ``sorb_analyze(i32 meta_ptr, i32 meta_len, i32 blob_ptr, i32 blob_len) -> i64``

    Returning a packed i64 keeps the ABI to plain wasm32 core exports, so a
    guest needs no multi-value or component-model support.
    """

    ABI_VERSION = 1

    def __init__(self, store: object, instance: object, namespace: str) -> None:
        self._store = store
        self._namespace = namespace
        exports = instance.exports(store)  # type: ignore[attr-defined]
        self._memory = self._require(exports, "memory")
        self._version = self._require(exports, "sorb_abi_version")
        self._alloc = self._require(exports, "sorb_alloc")
        self._globs = self._require(exports, "sorb_matcher_globs")
        self._analyze = self._require(exports, "sorb_analyze")

    def _require(self, exports: object, name: str) -> object:
        try:
            export = exports[name]  # type: ignore[index]
        except KeyError as e:
            raise PluginRuntimeError(
                f"wasm plugin {self._namespace!r} does not export {name!r} — "
                f"it must implement ABI version {self.ABI_VERSION}"
            ) from e
        return export

    def check_version(self) -> None:
        got = int(self._version(self._store))  # type: ignore[operator]
        if got != self.ABI_VERSION:
            raise PluginRuntimeError(
                f"wasm plugin {self._namespace!r} speaks ABI version {got}, "
                f"this build supports {self.ABI_VERSION}"
            )

    def _read(self, packed: int) -> bytes:
        ptr, length = packed >> 32, packed & 0xFFFFFFFF
        if length > MAX_RETURN_BYTES:
            raise PluginRuntimeError(
                f"wasm plugin {self._namespace!r} returned {length} bytes "
                f"(limit {MAX_RETURN_BYTES})"
            )
        data = self._memory.read(self._store, ptr, ptr + length)  # type: ignore[attr-defined]
        return bytes(data)

    def _write(self, payload: bytes) -> tuple[int, int]:
        ptr = int(self._alloc(self._store, len(payload)))  # type: ignore[operator]
        if ptr <= 0:
            raise PluginRuntimeError(
                f"wasm plugin {self._namespace!r} could not allocate {len(payload)} bytes"
            )
        self._memory.write(self._store, payload, ptr)  # type: ignore[attr-defined]
        return ptr, len(payload)

    def matcher_globs(self) -> list[str]:
        raw = self._read(int(self._globs(self._store)))  # type: ignore[operator]
        return [line for line in raw.decode("utf-8", "replace").splitlines() if line.strip()]

    def analyze(self, meta: dict[str, object], blob: bytes) -> bytes:
        import json

        meta_ptr, meta_len = self._write(json.dumps(meta, sort_keys=True).encode())
        blob_ptr, blob_len = self._write(blob)
        packed = int(
            self._analyze(self._store, meta_ptr, meta_len, blob_ptr, blob_len)  # type: ignore[operator]
        )
        return self._read(packed)
