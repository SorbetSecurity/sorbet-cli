"""Data-pack install + verification.

``sorb db update`` installs a signed data pack into the cache; **unsigned or
identity-mismatched packs are refused** (supply-chain protection). A
pack is a tar of ``pack.json`` (metadata) + payload files; it ships with a
detached signature bundle verified against a pinned public key (the same DSSE
detached-bundle scheme as ``sorb sign``). Keyless Sigstore verification is a
planned follow-up.
"""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path

from sorb.errors import SubsystemDegraded, UsageError


@dataclass(frozen=True, slots=True)
class InstalledPack:
    name: str
    version: str
    path: Path
    verified: bool


def _read_pack_meta(pack_bytes: bytes) -> dict[str, str]:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(pack_bytes), mode="r:*")
    except tarfile.TarError as e:
        raise UsageError(f"not a valid data pack (tar): {e}") from e
    for name in ("pack.json", "./pack.json"):
        member = tf.extractfile(name) if name in tf.getnames() else None
        if member is not None:
            with member:
                doc: dict[str, str] = json.loads(member.read())
            return doc
    raise UsageError("data pack missing pack.json metadata")


def install_pack(
    pack_bytes: bytes,
    *,
    packs_dir: Path,
    signature: bytes | None = None,
    public_key_pem: bytes | None = None,
    allow_unsigned: bool = False,
) -> InstalledPack:
    """Verify and unpack a data pack into ``packs_dir/<name>/<version>/``."""
    meta = _read_pack_meta(pack_bytes)
    name = str(meta.get("name", ""))
    version = str(meta.get("version", ""))
    if not name or not version:
        raise UsageError("data pack metadata missing name/version")

    verified = False
    if signature is not None and public_key_pem is not None:
        from sorb.emit.signing import verify, verify_artifact

        if not verify_artifact(pack_bytes, signature=signature, public_key_pem=public_key_pem):
            steps = verify(signature, public_key_pem=public_key_pem, sbom_bytes=pack_bytes)
            bad = next((s for s in steps if not s.ok), None)
            detail = f"{bad.name}: {bad.detail}" if bad else "signature is not bound to this pack"
            raise SubsystemDegraded(
                f"data pack {name} signature verification failed at {detail} — refusing to install"
            )
        verified = True
    elif not allow_unsigned:
        raise SubsystemDegraded(
            f"data pack {name} is unsigned (no signature/key supplied); "
            "pass --allow-unsigned to install anyway (not recommended)"
        )

    dest = packs_dir / name / version
    dest.mkdir(parents=True, exist_ok=True)
    tf = tarfile.open(fileobj=io.BytesIO(pack_bytes), mode="r:*")
    for member in tf.getmembers():
        # containment: no absolute paths, no traversal
        clean = member.name.lstrip("./").lstrip("/")
        if clean.startswith("..") or "/../" in clean:
            continue
        if member.isfile():
            data = tf.extractfile(member)
            if data is not None:
                with data:
                    (dest / clean).parent.mkdir(parents=True, exist_ok=True)
                    (dest / clean).write_bytes(data.read())
    return InstalledPack(name=name, version=version, path=dest, verified=verified)


def list_installed_packs(packs_dir: Path) -> list[InstalledPack]:
    out: list[InstalledPack] = []
    if not packs_dir.is_dir():
        return out
    for pack_root in sorted(p for p in packs_dir.iterdir() if p.is_dir()):
        for version_dir in sorted((v for v in pack_root.iterdir() if v.is_dir()), reverse=True):
            verified = (version_dir / ".verified").exists()
            out.append(
                InstalledPack(
                    name=pack_root.name, version=version_dir.name,
                    path=version_dir, verified=verified,
                )
            )
    return out


def build_pack(name: str, version: str, files: dict[str, bytes]) -> bytes:
    """Build a data-pack tar (used by the build pipeline and tests)."""
    meta = json.dumps(
        {"name": name, "version": version, "schema": 1, "min_sorb_version": "0.1.0"},
        sort_keys=True,
    ).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        def add(path: str, data: bytes) -> None:
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            info.mtime = 0
            tf.addfile(info, io.BytesIO(data))

        add("pack.json", meta)
        for path, data in sorted(files.items()):
            add(path, data)
    return buf.getvalue()
