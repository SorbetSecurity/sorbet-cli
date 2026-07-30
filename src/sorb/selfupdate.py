"""`sorb self update` — signed standalone-bundle updates.

Only the **bundle channel** self-updates (a pip install updates via pip). An
update is a standalone binary bundle plus a detached signature; it is applied
**only after** the signature verifies against a release public key with the same
DSSE machinery the SBOM signer uses — a tampered or unsigned update is
refused before a byte is written. The download itself honours `--offline` and the
CLI's network rules; the verify-then-swap core is what this module owns.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class UpdateResult:
    verified: bool
    version: str | None
    sha256: str
    detail: str


class UpdateRefused(Exception):
    """The update failed signature verification and was refused."""


def verify_bundle(artifact: bytes, *, signature_bundle: bytes, public_key_pem: bytes) -> bool:
    """True iff the signature verifies over the exact bundle bytes."""
    from sorb.emit.signing import verify_artifact

    return verify_artifact(
        artifact, signature=signature_bundle, public_key_pem=public_key_pem
    )


def apply_update(
    bundle_path: Path,
    *,
    signature_path: Path,
    public_key_pem: bytes,
    install_to: Path | None = None,
    version: str | None = None,
) -> UpdateResult:
    """Verify a bundle and (if `install_to` is given) atomically replace the
    running binary. Refuses on verification failure — never writes on a bad sig."""
    artifact = bundle_path.read_bytes()
    signature = signature_path.read_bytes()
    digest = hashlib.sha256(artifact).hexdigest()

    if not verify_bundle(artifact, signature_bundle=signature, public_key_pem=public_key_pem):
        raise UpdateRefused(
            f"update signature did not verify (sha256 {digest[:12]}…) — refusing to install"
        )

    if install_to is not None:
        tmp = install_to.with_suffix(install_to.suffix + ".new")
        tmp.write_bytes(artifact)
        tmp.chmod(0o755)
        tmp.replace(install_to)  # atomic swap
    return UpdateResult(verified=True, version=version, sha256=digest,
                        detail=f"verified and installed to {install_to}" if install_to
                        else "verified (dry run)")


def release_public_key() -> bytes | None:
    """The embedded release signing key, shipped with the bundle. Absent in the
    dev tree (the key is injected at release time)."""
    from importlib import resources

    try:
        key = resources.files("sorb") / "data" / "release-key.pem"
        if key.is_file():
            return key.read_bytes()
    except (FileNotFoundError, ModuleNotFoundError):
        pass
    return None
