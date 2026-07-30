"""Purl canonicalization, version ordering, CPE discipline."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from sorb.ident import (
    canonical_purl,
    compare,
    cpe_for,
    family_key,
    identity_keys,
    make_purl,
    versionless_purl,
)
from sorb.model import ComponentClaim


def test_shuffled_qualifiers_canonicalize_identically() -> None:
    a = canonical_purl("pkg:deb/debian/openssl@3.0.13?arch=amd64&distro=debian")
    b = canonical_purl("pkg:deb/debian/openssl@3.0.13?distro=debian&arch=amd64")
    assert a == b


def test_make_purl_scoped_npm() -> None:
    assert make_purl("npm", "core", "1.0.0", namespace="@babel") == "pkg:npm/%40babel/core@1.0.0"


def test_no_cpe_for_unmapped_purls() -> None:
    assert cpe_for("pkg:npm/ms@2.1.3") is None  # the classic 'ms' example
    assert cpe_for(None) is None


def test_identity_keys_precedence() -> None:
    claim = ComponentClaim(
        ctype="library",
        name="lodash",
        version="4.17.21",
        purl="pkg:npm/lodash@4.17.21",
        ecosystem="npm",
        hashes=(("sha512", "aa" * 8),),
    )
    keys = identity_keys(claim)
    assert keys[0].startswith("digest:sha512:")
    assert keys[1] == "purl:pkg:npm/lodash@4.17.21"


def test_family_key_version_insensitive() -> None:
    a = ComponentClaim(ctype="library", name="requests", version="1.0", purl="pkg:pypi/requests@1.0", ecosystem="pypi")
    b = ComponentClaim(ctype="library", name="requests", version="2.0", purl="pkg:pypi/requests@2.0", ecosystem="pypi")
    assert family_key(a) == family_key(b)


def test_semver_ordering() -> None:
    assert compare("npm", "1.10.0", "1.9.0") > 0  # not lexicographic
    assert compare("npm", "1.0.0-alpha", "1.0.0") < 0
    assert compare("golang", "v1.8.2", "v1.8.1") > 0


def test_pep440_ordering() -> None:
    assert compare("pypi", "2.32.0", "2.31.0") > 0
    assert compare("pypi", "1.0rc1", "1.0") < 0


def test_deb_evr_ordering() -> None:
    assert compare("deb", "3.0.13-1~deb12u1", "3.0.13-1") < 0  # tilde sorts first
    assert compare("deb", "1:1.0", "9.9") > 0  # epoch wins
    assert compare("deb", "2.36-9+deb12u7", "2.36-9") > 0


@given(st.from_regex(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", fullmatch=True))
def test_compare_reflexive(v: str) -> None:
    for eco in ("npm", "pypi", "deb", "unknown"):
        assert compare(eco, v, v) == 0


@given(
    st.from_regex(r"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}", fullmatch=True),
    st.from_regex(r"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}", fullmatch=True),
)
def test_compare_antisymmetric(a: str, b: str) -> None:
    assert compare("npm", a, b) == -compare("npm", b, a)


# -- versionless purls -------------------------------------------------------------------


def test_versionless_purl_gives_unresolved_components_an_identity() -> None:
    """A declared-but-unresolved dependency still deserves a purl.

    Downstream tooling matches on purls; a bare name is far weaker, and the
    purl spec makes the version optional.
    """
    assert versionless_purl(ComponentClaim(ctype="library", name="click", ecosystem="pypi")) == (
        "pkg:pypi/click"
    )
    scoped = ComponentClaim(ctype="library", name="@types/node", ecosystem="npm")
    assert versionless_purl(scoped) == "pkg:npm/%40types/node"


def test_versionless_purl_splits_the_maven_group_out_of_the_name() -> None:
    claim = ComponentClaim(ctype="library", name="com.h2database:h2", ecosystem="maven")
    assert versionless_purl(claim) == "pkg:maven/com.h2database/h2"
    with_ns = ComponentClaim(
        ctype="library", name="org.slf4j:slf4j-api", ecosystem="maven", namespace="org.slf4j"
    )
    assert versionless_purl(with_ns) == "pkg:maven/org.slf4j/slf4j-api"


def test_no_versionless_purl_without_a_purl_ecosystem() -> None:
    """"c" or "crypto" name a kind of artifact, not a package namespace."""
    for eco in (None, "c", "binary", "crypto"):
        claim = ComponentClaim(ctype="library", name="libssl", ecosystem=eco)
        assert versionless_purl(claim) is None
