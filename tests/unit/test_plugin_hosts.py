"""WASM + gRPC plugin hosts: the parts that hold without the
optional runtimes — findings re-validation, unsigned-plugin refusal, the
capability-scoped cataloger path, and the gRPC trust gate. wasmtime/grpcio
execution is skipped when the runtime is absent."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from sorb.catalogers.base import CatalogerContext
from sorb.errors import DetectorFailure, UsageError
from sorb.plugin.grpc import GrpcCataloger, TrustConfig
from sorb.plugin.validation import PluginValidationError, validate_findings_json
from sorb.plugin.wasm import (
    PluginRuntimeError,
    WasmCataloger,
    load_wasm_plugin,
    verify_plugin_signature,
)
from sorb.source.base import Entry

sys.path.insert(0, str(Path(__file__).parent))

_GOOD = json.dumps({"findings": [{
    "claim": {"ctype": "library", "name": "acme-lib", "version": "1.2.3"},
    "evidence": [{"technique": "manifest-parse", "tier": "declared", "detector": "acme@1",
                  "location": {"source_id": "s1", "path": "acme.json"}}],
}]}).encode()


# -- findings re-validation (the untrusted-tier gate) ------------------------------------


def test_valid_findings_pass_and_are_namespaced() -> None:
    findings = validate_findings_json(_GOOD, namespace="acme")
    assert len(findings) == 1
    assert findings[0].claim.name == "acme-lib"
    assert findings[0].evidence[0].detector == "plugin:acme/acme@1"


def test_malformed_json_rejected() -> None:
    with pytest.raises(PluginValidationError):
        validate_findings_json(b"not json{", namespace="x")


def test_missing_claim_rejected() -> None:
    bad = json.dumps({"findings": [{"evidence": []}]}).encode()
    with pytest.raises(PluginValidationError):
        validate_findings_json(bad, namespace="x")


def test_detector_impersonation_is_stripped() -> None:
    # a plugin claiming a first-party detector id is forced back into plugin: space
    sneaky = json.dumps({"findings": [{
        "claim": {"ctype": "library", "name": "x"},
        "evidence": [{"technique": "manifest-parse", "tier": "declared", "detector": "os/dpkg@1",
                      "location": {"source_id": "s1", "path": "p"}}],
    }]}).encode()
    findings = validate_findings_json(sneaky, namespace="acme")
    assert findings[0].evidence[0].detector == "plugin:acme/dpkg@1"


def test_flood_rejected() -> None:
    from sorb.plugin.validation import MAX_FINDINGS

    flood = json.dumps({"findings": [{"claim": {"ctype": "library", "name": "x"}}]
                        * (MAX_FINDINGS + 1)}).encode()
    with pytest.raises(PluginValidationError):
        validate_findings_json(flood, namespace="x")


def test_oversized_captured_is_truncated() -> None:
    big = json.dumps({"findings": [{
        "claim": {"ctype": "library", "name": "x"},
        "evidence": [{"technique": "manifest-parse", "tier": "declared", "detector": "a@1",
                      "location": {"source_id": "s1", "path": "p"}, "captured": "A" * 10000}],
    }]}).encode()
    findings = validate_findings_json(big, namespace="x")
    assert len(findings[0].evidence[0].captured or "") <= 4096


# -- WASM host: signature refusal + sandboxed cataloger path -----------------------------


def test_unsigned_wasm_plugin_refused() -> None:
    with pytest.raises(UsageError, match="unsigned"):
        load_wasm_plugin(b"\x00asm", namespace="acme")


def test_signature_verification_roundtrip(tmp_path: Path) -> None:
    from sorb.emit.signing import generate_keypair, sign_detached

    priv, pub = generate_keypair(tmp_path)
    artifact = b"\x00asm\x01\x00\x00\x00fake-wasm-module"
    bundle = sign_detached(artifact, private_key_pem=priv.read_bytes())
    assert verify_plugin_signature(artifact, signature_bundle=bundle,
                                   public_key_pem=pub.read_bytes())
    # a tampered artifact fails
    assert not verify_plugin_signature(artifact + b"x", signature_bundle=bundle,
                                       public_key_pem=pub.read_bytes())


def test_wasm_cataloger_validates_output(tmp_path: Path) -> None:
    """The cataloger path is testable with a Python analyze stand-in."""
    def analyze(meta: dict, blob: bytes) -> bytes:
        return _GOOD

    cat = WasmCataloger("acme", ["*.acme"], analyze)
    ctx = CatalogerContext(source=None, detector=cat.detector)  # type: ignore[arg-type]
    findings = list(cat.parse(ctx, Entry(path="x.acme", size=1), b"data"))
    assert findings[0].evidence[0].detector == "plugin:acme/acme@1"


def test_wasm_plugin_trap_is_contained() -> None:
    from sorb.errors import DetectorFailure

    def hostile(meta: dict, blob: bytes) -> bytes:
        raise MemoryError("simulated fuel exhaustion / trap")

    cat = WasmCataloger("evil", ["*"], hostile)
    ctx = CatalogerContext(source=None, detector=cat.detector)  # type: ignore[arg-type]
    with pytest.raises(DetectorFailure):
        list(cat.parse(ctx, Entry(path="x", size=1), b""))


# -- gRPC host: explicit-trust gate ------------------------------------------------------


def test_grpc_untrusted_endpoint_refused() -> None:
    cat = GrpcCataloger("acme", "localhost:50051", ["*.acme"], TrustConfig())
    ctx = CatalogerContext(source=None, detector=cat.detector)  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="trusted config"):
        list(cat.parse(ctx, Entry(path="x.acme", size=1), b""))


# -- optional runtimes (skipped when absent) ---------------------------------------------


def test_wasmtime_rejects_non_wasm_bytes(tmp_path: Path) -> None:
    pytest.importorskip("wasmtime")
    from sorb.emit.signing import generate_keypair, sign_detached

    priv, pub = generate_keypair(tmp_path)
    artifact = b"not a real wasm module"
    bundle = sign_detached(artifact, private_key_pem=priv.read_bytes())
    with pytest.raises(PluginRuntimeError, match="failed to instantiate"):
        load_wasm_plugin(artifact, namespace="acme", signature_bundle=bundle,
                         public_key_pem=pub.read_bytes())


# -- WASM ABI bridge (real guest modules) ------------------------------------------------

_PLUGIN_FINDINGS = json.dumps({"findings": [{
    "claim": {"ctype": "library", "name": "acme-widget", "version": "2.1.0",
              "ecosystem": "acme"},
    "evidence": [{"technique": "plugin-analysis", "tier": "declared", "detector": "guest@1",
                  "location": {"source_id": "s1", "path": "x.acme"}}],
}]}).encode()


def _load_guest(tmp_path: Path, wat: str, namespace: str = "acme"):  # type: ignore[no-untyped-def]
    from wasm_guest import wat_to_wasm

    from sorb.emit.signing import generate_keypair, sign_detached

    wasm = wat_to_wasm(wat)
    priv, pub = generate_keypair(tmp_path)
    bundle = sign_detached(wasm, private_key_pem=priv.read_bytes())
    return load_wasm_plugin(wasm, namespace=namespace, signature_bundle=bundle,
                            public_key_pem=pub.read_bytes())


def test_wasm_guest_globs_and_findings_cross_the_boundary(tmp_path: Path) -> None:
    """The host reads the guest's globs and findings out of linear memory."""
    pytest.importorskip("wasmtime")
    from wasm_guest import guest_wat

    cat = _load_guest(tmp_path, guest_wat(globs="*.acme\n*.widget\n", payload=_PLUGIN_FINDINGS))
    assert [m.glob for m in cat.matchers] == ["*.acme", "*.widget"]
    ctx = CatalogerContext(source=None, detector=cat.detector)  # type: ignore[arg-type]
    findings = list(cat.parse(ctx, Entry(path="x.acme", size=4), b"data"))
    assert findings[0].claim.name == "acme-widget"
    assert findings[0].claim.version == "2.1.0"
    # a guest cannot claim first-party attribution
    assert findings[0].evidence[0].detector == "plugin:acme/guest@1"


def test_wasm_guest_missing_export_is_reported(tmp_path: Path) -> None:
    pytest.importorskip("wasmtime")
    from wasm_guest import guest_wat

    wat = guest_wat(
        payload=_PLUGIN_FINDINGS,
        exports=("memory", "sorb_abi_version", "sorb_alloc", "sorb_matcher_globs"),
    )
    with pytest.raises(PluginRuntimeError, match="sorb_analyze"):
        _load_guest(tmp_path, wat)


def test_wasm_guest_abi_version_mismatch_is_refused(tmp_path: Path) -> None:
    pytest.importorskip("wasmtime")
    from wasm_guest import guest_wat

    with pytest.raises(PluginRuntimeError, match="ABI version 99"):
        _load_guest(tmp_path, guest_wat(payload=_PLUGIN_FINDINGS, abi_version=99))


def test_wasm_guest_oversized_return_is_refused(tmp_path: Path) -> None:
    """A guest must not be able to make the host materialize an unbounded buffer."""
    pytest.importorskip("wasmtime")
    from wasm_guest import guest_wat

    from sorb.plugin.wasm import MAX_RETURN_BYTES

    cat = _load_guest(
        tmp_path,
        guest_wat(payload=_PLUGIN_FINDINGS, claim_len=MAX_RETURN_BYTES + 1),
    )
    ctx = CatalogerContext(source=None, detector=cat.detector)  # type: ignore[arg-type]
    with pytest.raises(DetectorFailure):
        list(cat.parse(ctx, Entry(path="x.acme", size=1), b""))


def test_wasm_guest_trap_degrades_to_a_gap(tmp_path: Path) -> None:
    pytest.importorskip("wasmtime")
    from wasm_guest import trapping_guest_wat

    cat = _load_guest(tmp_path, trapping_guest_wat(), namespace="hostile")
    ctx = CatalogerContext(source=None, detector=cat.detector)  # type: ignore[arg-type]
    with pytest.raises(DetectorFailure):
        list(cat.parse(ctx, Entry(path="anything", size=1), b""))


# -- gRPC wire codec + client shim --------------------------------------------------------


def test_analyze_request_roundtrips_through_the_wire_codec() -> None:
    from sorb.plugin.wire import decode_findings_json, encode_analyze_request, fields

    encoded = encode_analyze_request("a/b.acme", 12, b"\x00\x01binary")
    decoded = dict(fields(encoded))  # type: ignore[arg-type]
    assert decoded[1] == b"a/b.acme"
    assert decoded[2] == 12
    assert decoded[3] == b"\x00\x01binary"
    from sorb.plugin.wire import encode_bytes_field

    assert decode_findings_json(encode_bytes_field(1, _PLUGIN_FINDINGS)) == _PLUGIN_FINDINGS


def test_malformed_wire_message_is_rejected() -> None:
    from sorb.plugin.wire import WireError, fields

    with pytest.raises(WireError):
        fields(b"\x0a\xff")  # length-delimited field longer than the message


def test_grpc_cataloger_calls_the_service_and_validates_output() -> None:
    """A trusted endpoint is contacted; its findings are still re-validated."""
    from sorb.plugin.wire import encode_bytes_field

    calls: list[tuple[str, bytes]] = []

    class FakeChannel:
        def unary_unary(self, method: str):  # type: ignore[no-untyped-def]
            def call(payload: bytes, timeout: float | None = None) -> bytes:
                calls.append((method, payload))
                return encode_bytes_field(1, _PLUGIN_FINDINGS)

            return call

    trust = TrustConfig(trusted_endpoints={"localhost:50051"})
    cat = GrpcCataloger("acme", "localhost:50051", ["*.acme"], trust, channel=FakeChannel())
    ctx = CatalogerContext(source=None, detector=cat.detector)  # type: ignore[arg-type]
    findings = list(cat.parse(ctx, Entry(path="x.acme", size=4), b"data"))
    assert findings[0].claim.name == "acme-widget"
    assert findings[0].evidence[0].detector == "plugin:acme/guest@1"
    assert calls[0][0] == "/sorb.plugin.v1.Cataloger/Analyze"


def test_grpc_matcher_globs_is_trust_gated() -> None:
    from sorb.plugin.grpc import matcher_globs

    with pytest.raises(UsageError, match="trusted config"):
        matcher_globs("localhost:50051", TrustConfig(), channel=object())


def test_grpc_dead_plugin_degrades_to_a_gap() -> None:
    class DeadChannel:
        def unary_unary(self, method: str):  # type: ignore[no-untyped-def]
            def call(payload: bytes, timeout: float | None = None) -> bytes:
                raise OSError("connection refused")

            return call

    trust = TrustConfig(trusted_endpoints={"localhost:50051"})
    cat = GrpcCataloger("acme", "localhost:50051", ["*.acme"], trust, channel=DeadChannel())
    ctx = CatalogerContext(source=None, detector=cat.detector)  # type: ignore[arg-type]
    with pytest.raises(DetectorFailure):
        list(cat.parse(ctx, Entry(path="x.acme", size=1), b""))
