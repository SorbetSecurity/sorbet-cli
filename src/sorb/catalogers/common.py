"""Shared parser helpers for catalogers (`sorb.catalogers.common`)."""

from __future__ import annotations

import base64
import posixpath

from sorb.model import ComponentClaim

# Reference-string grammar shared with reconcile:
#   purl:<purl> | claim:<eco>/<name>@<ver> | family:<eco>/<name> |
#   project:<path> | source:<id> | file:<path>


def ref_purl(purl: str) -> str:
    return f"purl:{purl}"


def ref_family(eco: str, name: str) -> str:
    return f"family:{eco}/{name}"


def ref_project(path: str) -> str:
    return f"project:{path}"


def ref_file(path: str) -> str:
    return f"file:{path}"


def ref_for_claim(claim: ComponentClaim) -> str:
    return claim.ref()


def decode_sri(integrity: str) -> tuple[str, str] | None:
    """Decode a Subresource Integrity string ('sha512-<b64>') to (algo, hex)."""
    algo, _, b64 = integrity.partition("-")
    if not b64 or algo not in ("sha1", "sha256", "sha384", "sha512"):
        return None
    try:
        return (algo, base64.b64decode(b64).hex())
    except (ValueError, TypeError):
        return None


def dirname_of(path: str) -> str:
    d = posixpath.dirname(path)
    return d if d else "."
