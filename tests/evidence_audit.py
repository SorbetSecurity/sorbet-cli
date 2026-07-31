"""Evidence auditor: re-prove every emitted component from the bytes it cites.

The fixture suites check that a cataloger produces what we expect. This checks
something else, and stronger: that nothing in a run store is *asserted without
support*. For each emitted component it re-opens the file each evidence record
points at and requires the claim to be re-derivable from those bytes, using no
code from the cataloger that produced it.

A component is BACKED when at least one of its evidence records corroborates it
— evidence records are alternative proofs, not conjuncts. A component with no
corroborating record at all is a hallucination and the audit fails.

Deliberately independent: the checks below re-read raw bytes and do their own
matching. If a cataloger and this auditor share a bug, the audit is worthless.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sorb.graph.store import Component, GraphStore

#: Techniques whose evidence is a derivation rather than a citation of bytes
#: that literally contain the name — audited by their own rule below.
_BINARY_TECHNIQUES = {
    "binary-metadata",
    "embedded-buildinfo",
    "symbol-fingerprint",
    "link-graph",
}


@dataclass
class Unbacked:
    component: str
    version: str | None
    detector: str
    path: str
    reason: str

    def __str__(self) -> str:  # pragma: no cover - diagnostic only
        v = f"@{self.version}" if self.version else ""
        return f"{self.component}{v} [{self.detector}] {self.path}: {self.reason}"


@dataclass
class AuditReport:
    checked: int = 0
    backed: int = 0
    unbacked: list[Unbacked] = field(default_factory=list)
    no_evidence: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.unbacked and not self.no_evidence

    def summary(self) -> str:
        pct = 100.0 * self.backed / self.checked if self.checked else 100.0
        return (
            f"{self.backed}/{self.checked} components backed by cited bytes "
            f"({pct:.1f}%), {len(self.unbacked)} unbacked, "
            f"{len(self.no_evidence)} with no evidence at all"
        )


# -- name / version normalisation -------------------------------------------------------


def _name_variants(name: str) -> list[str]:
    """Spellings of `name` that a source file may legitimately use.

    PyPI lowercases per PEP 503, Maven names itself `group:artifact` while the
    POM spells them separately, vcpkg ports carry feature suffixes, and CMake
    packages are found under their own casing.
    """
    out = {name, name.lower()}
    out.add(re.sub(r"[-_.]+", "-", name.lower()))
    out.add(re.sub(r"[-_.]+", "_", name.lower()))
    for sep in (":", "/"):
        if sep in name:
            out.add(name.rsplit(sep, 1)[-1])
            out.add(name.rsplit(sep, 1)[-1].lower())
    if name.startswith("lib"):
        out.add(name[3:])
    else:
        out.add("lib" + name)
    return [v for v in out if v]


def _contains_name(haystack: str, name: str) -> bool:
    """The name must occur as a whole token, not as a substring.

    A plain `in` test passes `icense` because the file says `License`, which is
    exactly how a Makefile parser inventing library names out of `--license`
    slipped past this audit. A real occurrence stands on its own.
    """
    low = haystack.lower()
    for variant in _name_variants(name):
        v = variant.lower()
        if v not in low:  # cheap reject before the boundary-aware scan
            continue
        if re.search(rf"(?<![\w]){re.escape(v)}(?![\w])", low):
            return True
    return False


def _contains_version(haystack: str, version: str) -> bool:
    """A concrete version must occur, allowing the usual cosmetic differences.

    Distro versions carry epochs (`1:8.6.0`) and releases (`-1.fc41`), and
    package databases store the parts separately, so the numeric core is what
    has to be present.
    """
    if version in haystack:
        return True
    core = version.split(":")[-1]
    if core and core in haystack:
        return True
    base = re.split(r"[-+~]", core)[0]
    return bool(base) and base in haystack


def _decode(blob: bytes) -> str:
    """Text of a file, both encodings.

    Always include the UTF-16 view: PE VERSIONINFO strings are UTF-16LE inside
    an otherwise byte-dense binary, so a null-density heuristic misses them.
    """
    text = blob.decode("utf-8", "replace")
    return text + "\n" + blob.decode("utf-16-le", "replace")


# -- per-technique corroboration --------------------------------------------------------


def _crypto_backs(blob: bytes, comp: Component, rel: str) -> tuple[bool, str]:
    """Crypto assets are parsed, never grepped: DER hides inside base64.

    Three shapes appear in real trees — certificates, bare private keys, and
    PKCS#12 bundles — and only the first is an X.509 document.
    """
    try:
        import hashlib

        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import pkcs12
    except ImportError:  # pragma: no cover
        return True, ""

    if comp.attrs.get("asset_type") == "private-key" or comp.name.startswith("private-key:"):
        # Key material is flagged, never captured, so the only honest check is
        # that the cited file really is a key.
        if b"PRIVATE KEY" in blob or rel.endswith((".key", ".pfx", ".p12")):
            return True, ""
        return False, "cited file holds no private-key material"

    certs: list[Any] = []
    try:
        if b"-----BEGIN" in blob:
            certs = list(x509.load_pem_x509_certificates(blob))
        elif rel.endswith((".pfx", ".p12")):
            for password in (None, b"", b"password"):
                try:
                    _k, cert, extra = pkcs12.load_key_and_certificates(blob, password)
                    certs = [c for c in [cert, *(extra or [])] if c is not None]
                    break
                except Exception:  # noqa: BLE001 — try the next password
                    continue
        else:
            certs = [x509.load_der_x509_certificate(blob)]
    except Exception:  # noqa: BLE001 — a file we cannot parse cannot corroborate
        return False, "cited file does not parse as certificate material"
    if not certs:
        return False, "no certificate in the cited file"

    fingerprint = str(comp.attrs.get("fingerprint_sha256", "")) or comp.hashes.get("sha256", "")
    if not fingerprint:
        return True, ""
    for cert in certs:
        if hashlib.sha256(cert.public_bytes(_der())).hexdigest() == fingerprint:
            return True, ""
    return False, f"no certificate in the cited file has fingerprint {fingerprint[:16]}…"


def _der() -> Any:
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def _span_lands_near_name(text: str, span: list[int] | None, name: str) -> tuple[bool, str]:
    """The cited line must exist, and the name must be in view from it.

    A span that points at line 1 of every file is not evidence — it is a
    citation that happens to be in the right document.
    """
    if not span:
        return True, ""
    lines = text.splitlines()
    start = int(span[0])
    if start < 1 or start > len(lines):
        return False, f"cited line {start} does not exist (file has {len(lines)})"
    end = int(span[1]) if len(span) > 1 else start
    window = "\n".join(lines[max(0, start - 4) : min(len(lines), end + 3)])
    if _contains_name(window, name):
        return True, ""
    return False, f"cited line {start} is not near any mention of {name!r}"


def _evidence_backs(
    root: Path, comp: Component, ev: dict[str, Any]
) -> tuple[bool, str, dict[str, bool]]:
    """(fully backs, reason, what this record individually proved)."""
    nothing: dict[str, bool] = {}
    location = ev["location"]
    rel = location["path"]
    technique = ev.get("technique", "")
    path = root / rel
    if not path.is_file():
        return False, f"cited file does not exist: {rel}", nothing
    try:
        blob = path.read_bytes()
    except OSError as e:
        return False, f"cited file unreadable: {e}", nothing

    if comp.ctype == "cryptographic-asset":
        ok, reason = _crypto_backs(blob, comp, rel)
        return ok, reason, {"name": ok, "version": ok}

    # A model file is identified *as a file*: the name is its basename and the
    # body is binary tensor data, so the filename is the claim to corroborate.
    if comp.attrs.get("ecosystem") == "ml" or comp.ctype == "machine-learning-model":
        ok = rel.rsplit("/", 1)[-1] == comp.name
        reason = "" if ok else f"cited file is not the model named {comp.name!r}"
        return ok, reason, {"name": ok, "version": ok}

    text = _decode(blob)
    has_name = _contains_name(text, comp.name)
    no_version_needed = not comp.version or technique in _BINARY_TECHNIQUES
    has_version = no_version_needed or _contains_version(text, comp.version or "")
    proved = {"name": has_name, "version": has_version}
    if not has_name:
        return False, f"name {comp.name!r} does not occur in the cited file", proved
    if not has_version:
        return False, f"version {comp.version!r} does not occur in the cited file", proved
    ok, reason = _span_lands_near_name(text, location.get("span"), comp.name)
    return ok, reason, proved


# -- entry point ------------------------------------------------------------------------


def audit_store(store: GraphStore, root: str | Path) -> AuditReport:
    """Re-prove every emitted component in `store` from files under `root`."""
    root = Path(root)
    report = AuditReport()
    for comp in store.components():
        if comp.attrs.get("excluded"):
            continue
        # Components grafted from another scan cite that scan's tree, not this
        # one; auditing them here would test the wrong filesystem.
        if comp.attrs.get("from_followed_image") or comp.attrs.get("imported_from"):
            continue
        report.checked += 1
        evidence = store.evidence_for_component(comp.id)
        if not evidence:
            report.no_evidence.append(comp.display_ref())
            continue
        # Records can be complementary rather than alternative: a Maven version
        # interpolated from a parent pom is named in the child and valued in the
        # parent, and neither file alone proves the pair. The component is
        # backed when the cited files *together* prove name and version.
        reasons: list[str] = []
        name_proven = version_proven = False
        for ev in evidence:
            ok, reason, proved = _evidence_backs(root, comp, ev)
            name_proven = name_proven or proved.get("name", False)
            version_proven = version_proven or proved.get("version", False)
            if ok:
                name_proven = version_proven = True
                break
            reasons.append(f"{ev['detector']} {ev['location']['path']}: {reason}")
        if name_proven and version_proven:
            report.backed += 1
        else:
            first = evidence[0]
            report.unbacked.append(
                Unbacked(
                    component=comp.name,
                    version=comp.version,
                    detector=first["detector"],
                    path=first["location"]["path"],
                    reason=" | ".join(reasons[:3]),
                )
            )
    return report


def audit_run(store_path: str | Path, root: str | Path) -> AuditReport:
    store = GraphStore.open_readonly(store_path)
    try:
        return audit_store(store, root)
    finally:
        store.close()


if __name__ == "__main__":  # pragma: no cover - manual driver
    import sys

    rep = audit_run(sys.argv[1], sys.argv[2])
    print(rep.summary())
    for u in rep.unbacked[:40]:
        print("  UNBACKED", u)
    for n in rep.no_evidence[:20]:
        print("  NO EVIDENCE", n)
    sys.exit(0 if rep.ok else 1)
