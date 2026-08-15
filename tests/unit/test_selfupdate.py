"""`sorb self update` signed-bundle verification: valid installs,
tampered is refused, unsigned is refused."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sorb.selfupdate import UpdateRefused, apply_update, verify_bundle


def _signed_bundle(tmp_path: Path) -> tuple[Path, Path, bytes]:
    from sorb.emit.signing import generate_keypair, sign_detached

    priv, pub = generate_keypair(tmp_path)
    bundle = tmp_path / "sorb-bundle"
    bundle.write_bytes(b"#!/fake/standalone/sorb binary\x00\x01\x02" * 100)
    sig = tmp_path / "sorb-bundle.sig"
    sig.write_bytes(sign_detached(bundle.read_bytes(), private_key_pem=priv.read_bytes()))
    return bundle, sig, pub.read_bytes()


def test_valid_bundle_verifies(tmp_path: Path) -> None:
    bundle, sig, pub = _signed_bundle(tmp_path)
    assert verify_bundle(bundle.read_bytes(), signature_bundle=sig.read_bytes(),
                         public_key_pem=pub)


def test_apply_update_installs_verified_bundle(tmp_path: Path) -> None:
    bundle, sig, pub = _signed_bundle(tmp_path)
    dest = tmp_path / "installed" / "sorb"
    dest.parent.mkdir()
    dest.write_bytes(b"old binary")
    result = apply_update(bundle, signature_path=sig, public_key_pem=pub, install_to=dest)
    assert result.verified
    assert dest.read_bytes() == bundle.read_bytes()  # atomically swapped in


def test_tampered_bundle_refused(tmp_path: Path) -> None:
    bundle, sig, pub = _signed_bundle(tmp_path)
    dest = tmp_path / "sorb"
    dest.write_bytes(b"old")
    bundle.write_bytes(bundle.read_bytes() + b"MALICIOUS")  # tamper after signing
    with pytest.raises(UpdateRefused):
        apply_update(bundle, signature_path=sig, public_key_pem=pub, install_to=dest)
    assert dest.read_bytes() == b"old"  # nothing was written


def test_wrong_key_refused(tmp_path: Path) -> None:
    from sorb.emit.signing import generate_keypair

    bundle, sig, _ = _signed_bundle(tmp_path)
    _, other_pub = generate_keypair(tmp_path / "other")
    assert not verify_bundle(bundle.read_bytes(), signature_bundle=sig.read_bytes(),
                             public_key_pem=other_pub.read_bytes())


def test_self_update_cli(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from sorb.cli.main import app

    bundle, sig, pub = _signed_bundle(tmp_path)
    keyfile = tmp_path / "key.pem"
    keyfile.write_bytes(pub)
    runner = CliRunner()
    ok = runner.invoke(app, ["self", "update", str(bundle), "--signature", str(sig),
                             "--key", str(keyfile)])
    assert ok.exit_code == 0 and "verified" in ok.output

    bundle.write_bytes(bundle.read_bytes() + b"x")  # tamper
    bad = runner.invoke(app, ["self", "update", str(bundle), "--signature", str(sig),
                              "--key", str(keyfile)])
    assert bad.exit_code == 2  # policy failure — refused


def test_attestation_for_another_artifact_is_refused(tmp_path: Path) -> None:
    """A validly signed DSSE envelope must not authenticate a different artifact.

    The release key signs public attestations; if the envelope's signature were
    checked without binding it to the bytes in hand, any published attestation
    would serve as a signature for an attacker-supplied update.
    """
    import json

    from sorb.emit.signing import attest, generate_keypair

    priv, pub = generate_keypair(tmp_path)
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}).encode()
    envelope = attest(
        sbom,
        subject_name="the-real-sbom",
        subject_digest="sha256:" + hashlib.sha256(sbom).hexdigest(),
        private_key_pem=priv.read_bytes(),
    )
    assert verify_bundle(sbom, signature_bundle=envelope, public_key_pem=pub.read_bytes())
    assert not verify_bundle(
        b"#!/bin/sh\nmalicious payload\n",
        signature_bundle=envelope,
        public_key_pem=pub.read_bytes(),
    )


def test_wasm_plugin_rejects_substituted_attestation(tmp_path: Path) -> None:
    import json

    from sorb.emit.signing import attest, generate_keypair
    from sorb.plugin.wasm import verify_plugin_signature

    priv, pub = generate_keypair(tmp_path)
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}).encode()
    envelope = attest(
        sbom,
        subject_name="sbom",
        subject_digest="sha256:" + hashlib.sha256(sbom).hexdigest(),
        private_key_pem=priv.read_bytes(),
    )
    assert not verify_plugin_signature(
        b"\x00asm\x01\x00\x00\x00", signature_bundle=envelope, public_key_pem=pub.read_bytes()
    )
