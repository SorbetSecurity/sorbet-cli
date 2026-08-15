"""Component identity & version schemes.

- purl is primary identity; canonicalization enforces qualifier ordering.
- Identity keys in precedence order: digest → canonical purl → name-tuple.
- Per-ecosystem version ordering behind one ``compare(eco, a, b)`` API.
- CPE is emitted **only** on an exact curated-map hit.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from typing import Any

from packageurl import PackageURL

from sorb.model import ComponentClaim

# --------------------------------------------------------------------------
# purl canonicalization
# --------------------------------------------------------------------------


def canonical_purl(purl: str) -> str:
    """Parse and re-serialize a purl so equal purls compare byte-equal.

    packageurl-python sorts qualifiers and lowercases type on to_string().
    Raises ValueError on malformed input.
    """
    return PackageURL.from_string(purl).to_string()


def make_purl(
    ptype: str,
    name: str,
    version: str | None = None,
    namespace: str | None = None,
    qualifiers: dict[str, str] | None = None,
    subpath: str | None = None,
) -> str:
    return PackageURL(
        type=ptype,
        namespace=namespace or None,
        name=name,
        version=version or None,
        qualifiers={k: v for k, v in (qualifiers or {}).items() if v} or None,
        subpath=subpath or None,
    ).to_string()


# --------------------------------------------------------------------------
# Identity keys: digest → purl → name-tuple (flagged)
# --------------------------------------------------------------------------


def identity_keys(claim: ComponentClaim) -> list[str]:
    """All identity keys for a claim, strongest first.

    Any shared key merges two claims at reconcile time (union-find).
    """
    keys: list[str] = []
    for algo, hexval in claim.hashes:
        keys.append(f"digest:{algo}:{hexval.lower()}")
    if claim.purl:
        keys.append(f"purl:{claim.purl}")
    elif claim.version:  # name-tuple last resort, only meaningful with a version
        eco = claim.ecosystem or claim.ctype
        ns = claim.namespace or ""
        keys.append(f"name:{claim.ctype}:{eco}:{ns}:{claim.name.lower()}:{claim.version}")
    return keys


#: purl types the catalogers emit. A versionless purl is only synthesized for
#: these — `ecosystem` also carries non-purl labels ("c", "binary", "crypto")
#: for things that have no package coordinate at all.
PURL_TYPES = frozenset({
    "alpm", "android", "apk", "bicep", "cargo", "cocoapods", "composer", "conan",
    "conda", "cran", "deb", "gem", "generic", "github", "golang", "hackage",
    "helm", "hex", "ios", "maven", "npm", "nuget", "oci", "pub", "pypi", "rpm",
    "swift", "terraform", "vcpkg",
})


def versionless_purl(claim: ComponentClaim) -> str | None:
    """A purl for a component whose version could not be resolved.

    A purl without a version is still an identity downstream tools can match
    on, and is far more useful than a bare name. Returns None when the claim
    has no ecosystem that maps to a purl type.
    """
    eco = (claim.ecosystem or "").lower()
    if eco not in PURL_TYPES:
        return None
    ns, name = claim.namespace or "", claim.name
    if eco == "maven" and ":" in name:
        # maven claims name themselves "group:artifact"; the purl carries the
        # group as the namespace and only the artifact as the name
        group, _, name = name.rpartition(":")
        ns = ns or group
    elif not ns and "/" in name:
        ns, _, name = name.rpartition("/")
    try:
        return make_purl(eco, name, None, namespace=ns or None)
    except ValueError:
        return None


def family_key(claim: ComponentClaim) -> str:
    """Version-insensitive grouping key: 'the same package, any version'."""
    if claim.purl:
        try:
            p = PackageURL.from_string(claim.purl)
            return f"{p.type}:{p.namespace or ''}:{p.name}".lower()
        except ValueError:
            pass
    eco = claim.ecosystem or claim.ctype
    ns = claim.namespace or ""
    name = claim.name
    if not ns and "/" in name:
        # split scoped/pathed names the same way purl construction does, so
        # "@types/node" (manifest claim) and pkg:npm/@types/node agree
        ns, _, name = name.rpartition("/")
    return f"{eco}:{ns}:{name}".lower()


# --------------------------------------------------------------------------
# Version schemes (a growing subset of ecosystems)
# --------------------------------------------------------------------------

_NUM_RE = re.compile(r"(\d+|[a-zA-Z]+)")


def _generic_parts(v: str) -> list[Any]:
    parts: list[Any] = []
    for tok in _NUM_RE.findall(v):
        parts.append((0, int(tok)) if tok.isdigit() else (1, tok.lower()))
    return parts


def _cmp(a: Any, b: Any) -> int:
    return int(a > b) - int(a < b)


def _semverish_compare(a: str, b: str) -> int:
    """Semver-style compare tolerant of leading 'v' and missing parts."""

    def split(v: str) -> tuple[list[int], str]:
        v = v.lstrip("vV").strip()
        core, _, pre = v.partition("-")
        core = core.split("+", 1)[0]
        nums: list[int] = []
        for p in core.split("."):
            digits = re.match(r"\d+", p)
            nums.append(int(digits.group()) if digits else 0)
        while len(nums) < 3:
            nums.append(0)
        return nums, pre

    an, apre = split(a)
    bn, bpre = split(b)
    if an != bn:
        return _cmp(an, bn)
    # a pre-release sorts before the release
    if apre and not bpre:
        return -1
    if bpre and not apre:
        return 1
    return _cmp(_generic_parts(apre), _generic_parts(bpre))


def _pep440_compare(a: str, b: str) -> int:
    from packaging.version import InvalidVersion, Version

    try:
        return _cmp(Version(a), Version(b))
    except InvalidVersion:
        return _cmp(_generic_parts(a), _generic_parts(b))


def _deb_order_char(c: str) -> int:
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256  # non-alphanumerics sort after letters


def _deb_verrevcmp(a: str, b: str) -> int:
    """dpkg version comparison for one segment (upstream or revision)."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _deb_order_char(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _deb_order_char(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return _cmp(ac, bc)
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            if first_diff == 0:
                first_diff = _cmp(a[i], b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _deb_compare(a: str, b: str) -> int:
    def split(v: str) -> tuple[int, str, str]:
        epoch = 0
        if ":" in v:
            e, _, v = v.partition(":")
            if e.isdigit():
                epoch = int(e)
        upstream, _, revision = v.rpartition("-") if "-" in v else (v, "", "")
        if not upstream:
            upstream, revision = v, ""
        return epoch, upstream, revision

    ae, au, ar = split(a)
    be, bu, br = split(b)
    if ae != be:
        return _cmp(ae, be)
    r = _deb_verrevcmp(au, bu)
    if r != 0:
        return r
    return _deb_verrevcmp(ar, br)


_SCHEMES = {
    "npm": _semverish_compare,
    "golang": _semverish_compare,
    "cargo": _semverish_compare,
    "pub": _semverish_compare,
    "gem": _semverish_compare,
    "composer": _semverish_compare,
    "pypi": _pep440_compare,
    "conda": _pep440_compare,
    "deb": _deb_compare,
    "apk": _deb_compare,  # apk ordering is deb-like for practical purposes
}


def compare(eco: str | None, a: str, b: str) -> int:
    """Compare two versions under the ecosystem's scheme. Returns -1/0/1."""
    fn = _SCHEMES.get((eco or "").lower())
    if fn is not None:
        return fn(a, b)
    return _cmp(_generic_parts(a), _generic_parts(b))


# --------------------------------------------------------------------------
# Curated purl → CPE map (no fuzzy guessing, exact hits only)
# --------------------------------------------------------------------------

_CPE_MAP: dict[str, str] | None = None


def cpe_for(purl: str | None) -> str | None:
    """Return a CPE only for an exact curated-map hit; otherwise None."""
    global _CPE_MAP
    if purl is None:
        return None
    if _CPE_MAP is None:
        try:
            raw = (resources.files("sorb") / "data" / "cpe-map.json").read_bytes()
            _CPE_MAP = json.loads(raw)
        except (FileNotFoundError, json.JSONDecodeError):
            _CPE_MAP = {}
    try:
        p = PackageURL.from_string(purl)
        key = PackageURL(type=p.type, namespace=p.namespace, name=p.name).to_string()
    except ValueError:
        return None
    template = _CPE_MAP.get(key)
    if template is None:
        return None
    return template.replace("{version}", p.version or "*")
