"""Serde identity, Tier ordering, Coordinates chaining."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from sorb.model import (
    Annotation,
    ComponentClaim,
    Coordinates,
    EdgeClaim,
    EdgeType,
    EvidenceRecord,
    Finding,
    Scope,
    Tier,
    finding_from_json,
    finding_to_json,
)

_names = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_./@"),
    min_size=1,
    max_size=30,
)


@st.composite
def findings(draw: st.DrawFn) -> Finding:
    claim = ComponentClaim(
        ctype=draw(st.sampled_from(["library", "application", "os-package"])),
        name=draw(_names),
        version=draw(st.none() | st.from_regex(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", fullmatch=True)),
        ecosystem=draw(st.sampled_from(["npm", "pypi", "golang", None])),
        qualifiers=tuple(sorted(draw(st.dictionaries(_names, _names, max_size=2)).items())),
        hashes=tuple(sorted(draw(st.dictionaries(st.sampled_from(["sha256", "sha512"]), st.from_regex(r"[0-9a-f]{8}", fullmatch=True), max_size=2)).items())),
    )
    coords = Coordinates(
        source_id="s1",
        path=draw(_names),
        span=draw(st.none() | st.tuples(st.integers(1, 100), st.integers(1, 100))),
        parent=draw(st.none() | st.builds(Coordinates, source_id=st.just("s1"), path=_names)),
    )
    ev = EvidenceRecord(
        technique="lockfile-parse",
        tier=draw(st.sampled_from(list(Tier))),
        detector="test/x@1",
        location=coords,
        captured=draw(st.none() | st.text(max_size=50)),
        confidence=draw(st.floats(0, 1, allow_nan=False)),
        modifiers=tuple(draw(st.lists(_names, max_size=2))),
    )
    edge = EdgeClaim(
        kind=draw(st.sampled_from(list(EdgeType))),
        src=draw(_names),
        dst=draw(_names),
        scope=draw(st.none() | st.sampled_from(list(Scope))),
        direct=draw(st.none() | st.booleans()),
    )
    ann = Annotation(code="test-code", subject=draw(_names), detail=draw(st.text(max_size=30)))
    return Finding(claim=claim, evidence=(ev,), edges=(edge,), annotations=(ann,))


@given(findings())
def test_serde_roundtrip_is_identity(f: Finding) -> None:
    assert finding_from_json(finding_to_json(f)) == f


def test_tier_ordering_matches_design() -> None:
    # observed > installed > locked > declared > inferred
    assert Tier.OBSERVED > Tier.INSTALLED > Tier.LOCKED > Tier.DECLARED > Tier.INFERRED
    assert Tier.from_label("locked") is Tier.LOCKED
    assert Tier.INSTALLED.label == "installed"


def test_coordinates_chain_flattens_to_physical_path() -> None:
    outer = Coordinates(source_id="s1", path="layer.tar")
    mid = Coordinates(source_id="s1", path="app.jar", parent=outer)
    inner = Coordinates(source_id="s1", path="lib/inner.jar", parent=mid)
    assert inner.physical_path() == "layer.tar!app.jar!lib/inner.jar"
