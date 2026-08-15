"""Signing & verification.

- ``sorb attest``: DSSE-enveloped in-toto attestation with the SBOM as
  predicate, **bound to the subject's digest** — the recommended form.
- ``sorb sign``: detached signature bundle over the raw SBOM bytes.
- Keys: ECDSA P-256 (cosign's default scheme, DSSE PAE encoding — verifiable
  by cosign-compatible tooling) with optional passphrase; fully air-gapped.
  Sigstore keyless (Fulcio/Rekor) is not yet supported: it requires the network
  and an OIDC identity by construction.
- ``sorb verify``: **ordered checks as discrete, individually
  reported steps** — envelope validity → signer identity policy → subject
  digest binding → transparency log (recorded gap without Sigstore bundles)
  → document-lineage consistency (a superseded version presented as current
  is flagged).
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

PAYLOAD_TYPE_INTOTO = "application/vnd.in-toto+json"
PREDICATE_CYCLONEDX = "https://cyclonedx.org/bom"
STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
BUNDLE_MEDIA_TYPE = "application/vnd.sorb.signature.bundle+json;version=1"


# -- keys ---------------------------------------------------------------------------


def generate_keypair(
    directory: Path, password: bytes | None = None, stem: str = "sorb"
) -> tuple[Path, Path]:
    """ECDSA P-256 keypair as PEM files. Returns (private_path, public_path)."""
    directory.mkdir(parents=True, exist_ok=True)
    private = ec.generate_private_key(ec.SECP256R1())
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    private_path = directory / f"{stem}.key"
    public_path = directory / f"{stem}.pub"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def _load_private(pem: bytes, password: bytes | None) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("expected an ECDSA private key (P-256)")
    return key


def _load_public(pem: bytes) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("expected an ECDSA public key (P-256)")
    return key


def _key_id(public_pem: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_pem).hexdigest()


# -- DSSE ---------------------------------------------------------------------------


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def make_statement(
    sbom: dict[str, Any],
    *,
    subject_name: str,
    subject_digest: str,
    predicate_type: str = PREDICATE_CYCLONEDX,
) -> dict[str, Any]:
    algo, _, hexval = subject_digest.partition(":")
    return {
        "_type": STATEMENT_TYPE,
        "predicateType": predicate_type,
        "subject": [{"name": subject_name, "digest": {algo or "sha256": hexval or subject_digest}}],
        "predicate": sbom,
    }


def attest(
    sbom_bytes: bytes,
    *,
    subject_name: str,
    subject_digest: str,
    private_key_pem: bytes,
    password: bytes | None = None,
) -> bytes:
    """DSSE envelope over an in-toto statement with the SBOM as predicate."""
    sbom = json.loads(sbom_bytes)
    predicate_type = (
        PREDICATE_CYCLONEDX if sbom.get("bomFormat") == "CycloneDX" else "https://spdx.dev/Document"
    )
    statement = make_statement(
        sbom, subject_name=subject_name, subject_digest=subject_digest,
        predicate_type=predicate_type,
    )
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    key = _load_private(private_key_pem, password)
    signature = key.sign(pae(PAYLOAD_TYPE_INTOTO, payload), ec.ECDSA(hashes.SHA256()))
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    envelope = {
        "payloadType": PAYLOAD_TYPE_INTOTO,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {"keyid": _key_id(public_pem), "sig": base64.b64encode(signature).decode()}
        ],
    }
    return (json.dumps(envelope, sort_keys=True, indent=2) + "\n").encode()


def sign_detached(
    sbom_bytes: bytes, *, private_key_pem: bytes, password: bytes | None = None
) -> bytes:
    """Detached signature bundle over the exact SBOM bytes."""
    key = _load_private(private_key_pem, password)
    digest = hashlib.sha256(sbom_bytes).digest()
    signature = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    bundle = {
        "mediaType": BUNDLE_MEDIA_TYPE,
        "payloadSha256": hashlib.sha256(sbom_bytes).hexdigest(),
        "signature": base64.b64encode(signature).decode(),
        "keyid": _key_id(public_pem),
    }
    return (json.dumps(bundle, sort_keys=True, indent=2) + "\n").encode()


# -- verification (ordered, discrete steps) ------------------------------------------


@dataclass(frozen=True, slots=True)
class VerifyStep:
    name: str
    ok: bool
    detail: str
    skipped: bool = False


def verify(
    artifact: bytes,
    *,
    public_key_pem: bytes,
    expected_subject_digest: str | None = None,
    sbom_bytes: bytes | None = None,  # for detached bundles
    lineage_index: dict[str, Any] | None = None,
) -> list[VerifyStep]:
    """Run the ordered checks; stops adding checks after a hard failure
    so the *first* broken property is what gets reported."""
    steps: list[VerifyStep] = []
    try:
        doc = json.loads(artifact)
    except json.JSONDecodeError as e:
        return [VerifyStep("envelope-validity", False, f"not JSON: {e}")]

    key = _load_public(public_key_pem)
    key_id = _key_id(public_key_pem)
    payload: bytes | None = None
    bundle_digest: str | None = None

    # 1. envelope / signature validity
    if doc.get("payloadType"):  # DSSE envelope
        try:
            payload = base64.b64decode(doc["payload"])
            sig = base64.b64decode(doc["signatures"][0]["sig"])
            key.verify(sig, pae(str(doc["payloadType"]), payload), ec.ECDSA(hashes.SHA256()))
            steps.append(VerifyStep("envelope-validity", True, "DSSE signature verifies"))
        except (KeyError, IndexError, ValueError, InvalidSignature) as e:
            steps.append(
                VerifyStep("envelope-validity", False, f"DSSE signature invalid: {type(e).__name__}")
            )
            return steps
        signer_keyid = str(doc["signatures"][0].get("keyid", ""))
    elif doc.get("mediaType") == BUNDLE_MEDIA_TYPE:  # detached bundle
        if sbom_bytes is None:
            steps.append(
                VerifyStep("envelope-validity", False, "detached bundle needs the SBOM file too")
            )
            return steps
        try:
            sig = base64.b64decode(doc["signature"])
            digest = hashlib.sha256(sbom_bytes).digest()
            if doc.get("payloadSha256") != hashlib.sha256(sbom_bytes).hexdigest():
                raise InvalidSignature("payload digest mismatch")
            key.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
            bundle_digest = str(doc["payloadSha256"])
            steps.append(VerifyStep("envelope-validity", True, "detached signature verifies"))
        except (KeyError, ValueError, InvalidSignature) as e:
            steps.append(
                VerifyStep("envelope-validity", False, f"signature invalid: {type(e).__name__}: {e}")
            )
            return steps
        signer_keyid = str(doc.get("keyid", ""))
    else:
        steps.append(
            VerifyStep("envelope-validity", False, "neither a DSSE envelope nor a sorb bundle")
        )
        return steps

    # 2. signer identity policy (pinned key; keyless identity is the sigstore gap)
    if signer_keyid and signer_keyid != key_id:
        steps.append(
            VerifyStep(
                "identity-policy",
                False,
                f"artifact was signed by {signer_keyid[:23]}…, not the pinned key {key_id[:23]}…",
            )
        )
        return steps
    steps.append(VerifyStep("identity-policy", True, f"pinned key matches ({key_id[:23]}…)"))

    # 3. subject digest binding
    statement: dict[str, Any] | None = None
    if payload is not None:
        try:
            statement = json.loads(payload)
        except json.JSONDecodeError:
            statement = None
    want: str | None = None
    if expected_subject_digest is not None:
        want = expected_subject_digest.partition(":")[2] or expected_subject_digest
        # Both were supplied and they name different artifacts. Silently
        # preferring one would report "verification passed" for a subject the
        # caller never asked about, so the contradiction is the answer.
        if sbom_bytes is not None and hashlib.sha256(sbom_bytes).hexdigest() != want:
            steps.append(
                VerifyStep(
                    "subject-binding",
                    False,
                    f"--subject-digest {want[:16]}… and --sbom "
                    f"({hashlib.sha256(sbom_bytes).hexdigest()[:16]}…) name different "
                    "artifacts — pass only the one you mean to bind against",
                )
            )
            return steps
    elif sbom_bytes is not None:
        # Holding the artifact makes it the subject to bind against: a validly
        # signed envelope that describes something else is not evidence about
        # this artifact, and accepting it would allow signature substitution.
        want = hashlib.sha256(sbom_bytes).hexdigest()

    if bundle_digest is not None:
        # A detached bundle was already bound to the artifact bytes in step 1;
        # all that remains is whether it is the artifact the caller expected.
        if want is None or want == bundle_digest:
            steps.append(
                VerifyStep("subject-binding", True, f"signed over {bundle_digest[:16]}…")
            )
        else:
            steps.append(
                VerifyStep(
                    "subject-binding",
                    False,
                    f"bundle is over {bundle_digest[:16]}…, not the expected {want[:16]}…",
                )
            )
            return steps
    elif want is None:
        steps.append(
            VerifyStep("subject-binding", True, "no expected subject supplied", skipped=True)
        )
    elif statement is None:
        steps.append(
            VerifyStep(
                "subject-binding", False, "envelope carries no in-toto statement to bind a subject"
            )
        )
        return steps
    else:
        digests = {
            d
            for s in statement.get("subject", [])
            for d in (s.get("digest") or {}).values()
        }
        if want in digests:
            steps.append(VerifyStep("subject-binding", True, f"subject digest {want[:16]}… bound"))
        else:
            steps.append(
                VerifyStep(
                    "subject-binding",
                    False,
                    f"attestation is about {sorted(digests)}, not the expected {want[:16]}… — "
                    "validly signed but for a different artifact",
                )
            )
            return steps

    # 4. transparency-log inclusion (Sigstore bundles — not yet supported)
    steps.append(
        VerifyStep(
            "transparency-log",
            True,
            "no transparency material attached (keyless/Sigstore signing lands with its integration)",
            skipped=True,
        )
    )

    # 5. document-lineage consistency
    if lineage_index is None:
        steps.append(VerifyStep("lineage-consistency", True, "no lineage supplied", skipped=True))
        return steps
    serial = None
    if statement is not None:
        predicate = statement.get("predicate") or {}
        serial = str(predicate.get("serialNumber", "")).removeprefix("urn:uuid:")
    if not serial:
        steps.append(
            VerifyStep("lineage-consistency", True, "document carries no serial", skipped=True)
        )
        return steps
    latest: str | None = None
    for lineage in (lineage_index.get("subjects") or {}).values():
        for entry in lineage:
            if entry.get("serial") == serial:
                latest = str(lineage[-1]["serial"])
    if latest is None:
        steps.append(
            VerifyStep("lineage-consistency", True, "serial not in local lineage", skipped=True)
        )
    elif latest == serial:
        steps.append(VerifyStep("lineage-consistency", True, "document is the current version"))
    else:
        steps.append(
            VerifyStep(
                "lineage-consistency",
                False,
                f"document {serial[:13]}… has been superseded by {latest[:13]}… — "
                "a superseded SBOM is being presented as current",
            )
        )
    return steps


def verify_artifact(artifact: bytes, *, signature: bytes, public_key_pem: bytes) -> bool:
    """True iff `signature` authenticates these exact bytes under this key.

    The gate for executable trust decisions — self-update bundles, WASM
    plugins, data packs. Unlike :func:`verify`, a skipped subject binding is
    never good enough: the signature has to be about *this* artifact.
    """
    steps = verify(signature, public_key_pem=public_key_pem, sbom_bytes=artifact)
    if not steps or not all(s.ok for s in steps):
        return False
    binding = next((s for s in steps if s.name == "subject-binding"), None)
    return binding is not None and not binding.skipped
