"""CBOM — cryptographic-asset catalogers.

Certificates (PEM/DER/PKCS#12/JKS) become `cryptographic-asset` components with
their subject, issuer, signature algorithm, key type/size, and — the operationally
useful part — **expiry**, so "which hosts hold expiring certs or weak keys?" is a
`sorb query`. Private-key material is **flagged but never captured**: the evidence
for a key records only that one is present, never a byte of it (the honesty +
credential-scrubbing rules). Certificates are emitted as CycloneDX 1.6
`cryptoProperties` (see `sorb.emit.cyclonedx`).
"""

from __future__ import annotations

import contextlib
import warnings
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.model import Annotation, ComponentClaim, Finding, Tier
from sorb.source.base import Entry

if TYPE_CHECKING:
    from cryptography.x509 import Certificate


@contextlib.contextmanager
def _quiet_parse() -> Iterator[None]:
    """Silence the crypto library's per-certificate warnings.

    Real-world CA bundles contain certificates that violate RFC 5280 in ways
    `cryptography` warns about. That is a property of the scanned input, not of
    this scan, and it must not print over the scan's own output; a certificate
    that fails to parse is already dropped.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        yield


_PEM_CERT = b"-----BEGIN CERTIFICATE-----"
_PEM_KEY_MARKERS = (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----",
                    b"-----BEGIN EC PRIVATE KEY-----", b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
                    b"-----BEGIN OPENSSH PRIVATE KEY-----", b"-----BEGIN DSA PRIVATE KEY-----")
_JKS_MAGIC = b"\xfe\xed\xfe\xed"


class CertificateCataloger(Cataloger):
    id = "crypto/certificate"
    version = 1
    matchers = [
        Matcher(glob="*.pem"), Matcher(glob="*.crt"), Matcher(glob="*.cer"),
        Matcher(glob="*.der"), Matcher(glob="*.p12"), Matcher(glob="*.pfx"),
        Matcher(glob="*.jks"), Matcher(glob="*.keystore"), Matcher(glob="*.key"),
        Matcher(magic=_PEM_CERT), Matcher(magic=_JKS_MAGIC),
    ]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        certs, has_private_key = _extract(entry.path, blob)
        for cert in certs:
            finding = _cert_finding(ctx, entry, cert)
            if finding is not None:
                yield finding
        if has_private_key:
            # a key is present — recorded, with NOTHING of the key itself captured.
            yield Finding(
                claim=ComponentClaim(
                    ctype="cryptographic-asset",
                    name=f"private-key:{entry.path.rsplit('/', 1)[-1]}",
                    ecosystem="crypto",
                    attrs=(("asset_type", "private-key"), ("kind", "private-key")),
                ),
                evidence=(
                    ctx.evidence("installed-state", Tier.INSTALLED, entry,
                                 captured="private key material present (not captured)"),
                ),
                annotations=(
                    Annotation(code="private-key-present", subject=f"file:{entry.path}",
                               detail="private key material detected — never stored in evidence"),
                ),
            )


def _extract(path: str, blob: bytes) -> tuple[list[Certificate], bool]:
    """Return (certificates, has_private_key). Never raises."""
    from cryptography import x509

    certs: list[Certificate] = []
    has_key = any(m in blob for m in _PEM_KEY_MARKERS)
    lower = path.lower()

    try:
        if _PEM_CERT in blob:
            certs.extend(_pem_certs(blob))
        elif lower.endswith((".p12", ".pfx")):
            c, k = _pkcs12(blob)
            certs.extend(c)
            has_key = has_key or k
        elif blob[:4] == _JKS_MAGIC:
            c, k = _jks(blob)
            certs.extend(c)
            has_key = has_key or k
        elif blob[:1] == b"\x30":  # DER SEQUENCE
            try:
                with _quiet_parse():
                    certs.append(x509.load_der_x509_certificate(blob))
            except Exception:
                pass
    except Exception:
        pass
    return certs, has_key


def _pem_certs(blob: bytes) -> list[Certificate]:
    from cryptography import x509

    out: list[Certificate] = []
    marker = _PEM_CERT
    end = b"-----END CERTIFICATE-----"
    start = 0
    while True:
        i = blob.find(marker, start)
        if i < 0:
            break
        j = blob.find(end, i)
        if j < 0:
            break
        block = blob[i:j + len(end)]
        try:
            with _quiet_parse():
                out.append(x509.load_pem_x509_certificate(block))
        except Exception:
            pass
        start = j + len(end)
    return out


def _pkcs12(blob: bytes) -> tuple[list[Certificate], bool]:
    from cryptography.hazmat.primitives.serialization import pkcs12

    for password in (None, b"", b"changeit"):
        try:
            with _quiet_parse():
                key, cert, extra = pkcs12.load_key_and_certificates(blob, password)
            certs = ([cert] if cert else []) + list(extra or [])
            return certs, key is not None
        except Exception:
            continue
    return [], True  # couldn't open (likely password) — assume a key is inside


def _jks(blob: bytes) -> tuple[list[Certificate], bool]:
    """Minimal JKS reader: pull DER certs out of trusted-cert/key-chain entries."""
    from cryptography import x509

    def u16(o: int) -> int:
        return int.from_bytes(blob[o:o + 2], "big")

    def u32(o: int) -> int:
        return int.from_bytes(blob[o:o + 4], "big")

    certs: list[Certificate] = []
    has_key = False
    try:
        if blob[:4] != _JKS_MAGIC:
            return [], False
        count = u32(8)
        pos = 12
        for _ in range(min(count, 10000)):
            tag = u32(pos)
            pos += 4
            alias_len = u16(pos)
            pos += 2 + alias_len + 8  # alias + timestamp
            if tag == 1:  # private key entry: [protected key][chain]
                has_key = True
                key_len = u32(pos)
                pos += 4 + key_len
                n_chain = u32(pos)
                pos += 4
                for _c in range(n_chain):
                    ctype_len = u16(pos)
                    pos += 2 + ctype_len
                    clen = u32(pos)
                    pos += 4
                    _try_der(x509, blob[pos:pos + clen], certs)
                    pos += clen
            elif tag == 2:  # trusted cert
                ctype_len = u16(pos)
                pos += 2 + ctype_len
                clen = u32(pos)
                pos += 4
                _try_der(x509, blob[pos:pos + clen], certs)
                pos += clen
            else:
                break
    except Exception:
        pass
    return certs, has_key


def _try_der(x509_mod: Any, der: bytes, out: list[Certificate]) -> None:
    try:
        with _quiet_parse():
            out.append(x509_mod.load_der_x509_certificate(der))
    except Exception:
        pass


def _cert_finding(ctx: CatalogerContext, entry: Entry, cert: Certificate) -> Finding | None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    try:
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_after = cert.not_valid_after_utc.isoformat()
        not_before = cert.not_valid_before_utc.isoformat()
        sig_algo = (cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown")
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            key_type, key_size = "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_type, key_size = f"EC-{pub.curve.name}", pub.curve.key_size
        else:
            key_type, key_size = type(pub).__name__, 0
    except Exception:
        return None

    cn = _common_name(subject) or subject or "certificate"
    weak = key_size and (
        (key_type == "RSA" and key_size < 2048) or sig_algo in ("md5", "sha1")
    )
    attrs: list[tuple[str, Any]] = [
        ("asset_type", "certificate"), ("kind", "certificate"),
        ("subject", subject), ("issuer", issuer),
        ("signature_algorithm", sig_algo), ("key_type", key_type),
        ("not_before", not_before), ("not_after", not_after),
        ("fingerprint_sha256", fingerprint),
        ("self_signed", "true" if subject == issuer else "false"),
    ]
    if key_size:
        attrs.append(("key_size", key_size))
    if weak:
        attrs.append(("weak_crypto", "true"))
    annotations: tuple[Annotation, ...] = ()
    if weak:
        annotations = (Annotation(code="weak-crypto", subject=f"file:{entry.path}",
                                  detail=f"{key_type} {key_size} / {sig_algo}"),)
    return Finding(
        claim=ComponentClaim(
            ctype="cryptographic-asset", name=cn, version=fingerprint[:16],
            ecosystem="crypto", attrs=tuple(attrs),
        ),
        evidence=(
            ctx.evidence("installed-state", Tier.INSTALLED, entry,
                         captured=f"CN={cn} expires {not_after} {key_type}/{sig_algo}"),
        ),
        annotations=annotations,
    )


def _common_name(dn: str) -> str | None:
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return None


register(CertificateCataloger())
