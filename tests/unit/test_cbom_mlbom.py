"""CBOM + ML-BOM catalogers.

Real certificates/keys are minted with `cryptography`; model files are
synthesized byte-for-byte. Everything runs offline; the scrubber test asserts no
private-key bytes reach the store.
"""

from __future__ import annotations

import datetime
import json
import struct
from pathlib import Path

import pytest

from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.emit.cyclonedx import emit_cyclonedx
from sorb.graph.store import GraphStore
from sorb.query import run_query

# -- fixtures: certs + keys --------------------------------------------------------------


def _make_cert(days: int, key_bits: int = 2048):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svc.example.com")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


@pytest.fixture()
def crypto_host(tmp_path: Path):
    root = tmp_path / "host"
    (root / "etc/ssl").mkdir(parents=True)
    cert_pem, key_pem = _make_cert(days=20)  # expires 2026-01-21
    (root / "etc/ssl/server.crt").write_bytes(cert_pem)
    (root / "etc/ssl/server.key").write_bytes(key_pem)
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(root), cfg, store_path=tmp_path / "c.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    yield store, key_pem
    store.close()


def test_certificate_becomes_crypto_asset(crypto_host) -> None:
    store, _ = crypto_host
    certs = [c for c in store.components() if c.ctype == "cryptographic-asset"
             and c.attrs.get("asset_type") == "certificate"]
    assert certs
    cert = certs[0]
    assert cert.attrs["subject"].startswith("CN=svc.example.com")
    assert cert.attrs["not_after"].startswith("2026-01-21")
    assert cert.attrs["key_type"] == "RSA" and cert.attrs["key_size"] == 2048


def test_expiring_cert_query(crypto_host) -> None:
    """'which hosts hold expiring certs' answered as a query."""
    store, _ = crypto_host
    result = run_query(store, 'components where asset_type = certificate and not_after < "2026-02-01"')
    assert result.rows, "the cert expiring 2026-01-21 should match"
    later = run_query(store, 'components where asset_type = certificate and not_after < "2026-01-10"')
    assert not later.rows  # not expiring before the 10th


def test_private_key_flagged_never_captured(crypto_host, tmp_path: Path) -> None:
    store, key_pem = crypto_host
    # a private-key component exists, flagged
    keys = [c for c in store.components() if c.attrs.get("asset_type") == "private-key"]
    assert keys
    anns = {a["code"] for a in store.all_annotations()}
    assert "private-key-present" in anns
    # SCRUBBER: no private-key bytes anywhere in the store DB
    db_bytes = Path(store._conn.execute("PRAGMA database_list").fetchall()[0][2]).read_bytes()
    body = key_pem.split(b"-----")[2]  # the base64 body between PEM markers
    secret = body.strip().splitlines()[1]  # a full base64 line of key material
    assert len(secret) > 20
    assert secret not in db_bytes, "private key material leaked into the store"


def test_weak_key_flagged(tmp_path: Path) -> None:
    root = tmp_path / "weak"
    root.mkdir()
    cert_pem, _ = _make_cert(days=400, key_bits=1024)  # RSA-1024 is weak
    (root / "weak.pem").write_bytes(cert_pem)
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(root), cfg, store_path=tmp_path / "w.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        cert = next(c for c in store.components() if c.attrs.get("asset_type") == "certificate")
        assert cert.attrs.get("weak_crypto") == "true"
    finally:
        store.close()


def test_cert_emitted_as_cyclonedx_crypto_properties(crypto_host) -> None:
    store, _ = crypto_host
    doc = json.loads(emit_cyclonedx(store, reproducible=True))
    certs = [c for c in doc["components"]
             if c.get("cryptoProperties", {}).get("assetType") == "certificate"]
    assert certs
    props = certs[0]["cryptoProperties"]
    assert "notValidAfter" in props["certificateProperties"]
    # the private key is emitted too, as related-crypto-material (no key bytes)
    keys = [c for c in doc["components"]
            if c.get("cryptoProperties", {}).get("assetType") == "related-crypto-material"]
    assert keys


# -- ML-BOM ------------------------------------------------------------------------------


def _safetensors(arch: str) -> bytes:
    header = {"weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
              "__metadata__": {"architecture": arch}}
    hb = json.dumps(header).encode()
    return struct.pack("<Q", len(hb)) + hb + b"\x00" * 16


def _gguf(arch: str) -> bytes:
    out = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 1)
    # one KV: general.architecture (string) = arch
    key = b"general.architecture"
    out += struct.pack("<Q", len(key)) + key + struct.pack("<I", 8)
    out += struct.pack("<Q", len(arch)) + arch.encode()
    return out


@pytest.fixture()
def model_zoo(tmp_path: Path) -> GraphStore:
    zoo = tmp_path / "zoo"
    zoo.mkdir()
    (zoo / "model.safetensors").write_bytes(_safetensors("llama"))
    (zoo / "model.gguf").write_bytes(_gguf("qwen2"))
    (zoo / "model.onnx").write_bytes(b"\x08\x07\x12\x08pytorch\x1a\x032.1")
    (zoo / "model.pt").write_bytes(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.")  # pickle
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(zoo), cfg, store_path=tmp_path / "z.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    yield store
    store.close()


def test_model_zoo_inventories_all_four_formats(model_zoo: GraphStore) -> None:
    models = [c for c in model_zoo.components() if c.ctype == "machine-learning-model"]
    formats = {c.attrs.get("model_format") for c in models}
    assert {"safetensors", "gguf", "onnx", "pickle"} <= formats


def test_safetensors_and_gguf_architecture(model_zoo: GraphStore) -> None:
    by_fmt = {c.attrs["model_format"]: c for c in model_zoo.components()
              if c.ctype == "machine-learning-model"}
    assert by_fmt["safetensors"].attrs.get("architecture") == "llama"
    assert by_fmt["gguf"].attrs.get("architecture") == "qwen2"


def test_pickle_model_gets_risk_annotation(model_zoo: GraphStore) -> None:
    pt = next(c for c in model_zoo.components()
              if c.attrs.get("model_format") == "pickle")
    assert pt.attrs.get("pickle_risk") == "true"
    anns = {a["code"] for a in model_zoo.all_annotations()}
    assert "ml-pickle-risk" in anns


def test_hf_cache_identity(tmp_path: Path) -> None:
    root = tmp_path / "hf"
    d = root / ".cache/huggingface/hub/models--meta-llama--Llama-3/snapshots/abc123"
    d.mkdir(parents=True)
    (d / "model.safetensors").write_bytes(_safetensors("llama"))
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(root), cfg, store_path=tmp_path / "hf.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        m = next(c for c in store.components() if c.ctype == "machine-learning-model")
        assert m.attrs.get("hf_repo") == "meta-llama/Llama-3"
        assert m.attrs.get("hf_revision") == "abc123"
        assert m.name == "meta-llama/Llama-3"
    finally:
        store.close()
