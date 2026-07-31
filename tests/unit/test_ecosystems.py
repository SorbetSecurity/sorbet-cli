"""Ecosystems added on top of the original set.

Every case here is reduced from a real file: rebar3_hex's rebar.lock, Paket's
own paket.lock, Unity's EntityComponentSystemSamples, apple/swift-nio,
bazelbuild/bazel, babashka, ring, opam-client, plack/Plack, Penlight, a Gentoo
stage3 VDB and snaps from the Snap Store.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from catalog_harness import by_name, catalog  # noqa: E402
from sorb.model import Scope, Tier  # noqa: E402

# -- Erlang ------------------------------------------------------------------------------


def test_rebar_lock_reads_hex_packages_and_digests() -> None:
    lock = """{"1.2.0",
[{<<"hex_core">>,{pkg,<<"hex_core">>,<<"0.17.0">>},0},
 {<<"verl">>,{pkg,<<"verl">>,<<"1.1.1">>},0}]}.
[
{pkg_hash,[
 {<<"hex_core">>, <<"B942B9BC1B6959EA289E77C4915330935B83FB569232E6D6BF21DE5D1EC581E7">>},
 {<<"verl">>, <<"98F3EC48B943AA4AE8E29742DE86A7CD752513687911FE07D2E00ECDF3107E45">>}]}
].
"""
    found = by_name(catalog({"rebar.lock": lock}, "rebar.lock"))
    assert set(found) == {"hex_core", "verl"}
    assert found["hex_core"].claim.version == "0.17.0"
    assert found["hex_core"].claim.purl == "pkg:hex/hex_core@0.17.0"
    # the pkg_hash section is a second mention of the same names; not a second package
    assert dict(found["verl"].claim.hashes)["sha256"].startswith("98f3ec48")
    assert found["verl"].evidence[0].tier is Tier.LOCKED


# -- Paket -------------------------------------------------------------------------------


def test_paket_lock_takes_resolutions_not_constraints() -> None:
    """Four-space entries are resolved; deeper ones are the ranges they need."""
    lock = """STORAGE: NONE
NUGET
  remote: https://api.nuget.org/v3/index.json
    Argu (6.1.1)
      FSharp.Core (>= 4.3.2) - restriction: >= netstandard2.0
    Castle.Core (4.4.1) - restriction: || (>= net45) (>= netstandard2.0)
GITHUB
  remote: some/repo
    src/File.fs (abc123)
"""
    found = by_name(catalog({"paket.lock": lock}, "paket.lock"))
    assert set(found) == {"Argu", "Castle.Core"}
    assert found["Argu"].claim.version == "6.1.1"
    # a version with a restriction suffix on the same line is still resolved
    assert found["Castle.Core"].claim.version == "4.4.1"
    assert found["Castle.Core"].claim.purl == "pkg:nuget/Castle.Core@4.4.1"


# -- Unity -------------------------------------------------------------------------------


def test_unity_manifest_needs_the_packages_directory() -> None:
    manifest = json.dumps({"dependencies": {"com.unity.ugui": "2.0.0"}})
    found = catalog({"Packages/manifest.json": manifest}, "Packages/manifest.json")
    assert [(f.claim.name, f.claim.version) for f in found] == [("com.unity.ugui", "2.0.0")]
    # `manifest.json` is far too common a name to claim outside Packages/
    assert catalog({"build/manifest.json": manifest}, "build/manifest.json") == []


# -- Swift -------------------------------------------------------------------------------


def test_package_swift_ranges_are_requests_and_paths_are_ignored() -> None:
    """`from:` means "up to the next major", so it is not a pinned version."""
    pkg = """// swift-tools-version:5.9
import PackageDescription
let package = Package(name: "app", dependencies: [
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.62.0"),
    .package(url: "https://github.com/apple/swift-atomics.git", exact: "1.2.0"),
    .package(path: "../local-thing"),
])
"""
    found = by_name(catalog({"Package.swift": pkg}, "Package.swift"))
    assert "local-thing" not in found  # a local checkout is not a released package
    assert found["swift-nio"].claim.version is None
    assert found["swift-nio"].claim.requested == "2.62.0"
    assert found["swift-atomics"].claim.version == "1.2.0"  # exact: pins
    assert found["swift-nio"].claim.namespace == "apple"


# -- Bazel -------------------------------------------------------------------------------


def test_module_bazel_reads_bazel_dep() -> None:
    module = """module(name = "app", version = "1.0")
bazel_dep(name = "abseil-cpp", version = "20250814.1")
bazel_dep(name = "bazel_skylib", version = "1.9.0")
"""
    found = by_name(catalog({"MODULE.bazel": module}, "MODULE.bazel"))
    assert set(found) == {"abseil-cpp", "bazel_skylib"}
    assert found["abseil-cpp"].claim.purl == "pkg:bazel/abseil-cpp@20250814.1"


# -- Clojure -----------------------------------------------------------------------------


def test_clojure_deps_are_maven_coordinates() -> None:
    """`:local/root` deps are source checkouts, and are reported as such."""
    edn = """{:paths ["src"]
 :deps {org.clojure/clojure {:mvn/version "1.12.5"}
        org.babashka/sci {:local/root "sci"}
        cheshire/cheshire {:mvn/version "5.13.0"}}}
"""
    found = catalog({"deps.edn": edn}, "deps.edn")
    named = by_name(found)
    assert "org.clojure/clojure" in named and "cheshire/cheshire" in named
    assert named["org.clojure/clojure"].claim.version == "1.12.5"
    assert named["org.clojure/clojure"].claim.namespace == "org.clojure"
    codes = {a.code for f in found for a in f.annotations}
    assert "local-path-dependency" in codes


def test_leiningen_project_clj() -> None:
    proj = """(defproject ring "1.15.5"
  :dependencies [[ring/ring-core "1.15.5"]
                 [org.ring-clojure/ring-jakarta-servlet "1.15.5"]])
"""
    found = by_name(catalog({"project.clj": proj}, "project.clj"))
    assert "ring/ring-core" in found
    assert found["ring/ring-core"].claim.purl == "pkg:maven/ring/ring-core@1.15.5"


# -- OCaml -------------------------------------------------------------------------------


def test_opam_constraints_are_requests() -> None:
    opam = """opam-version: "2.0"
version: "2.6.0"
depends: [
  "ocaml" {>= "4.11.0"}
  "dune" {>= "2.8.0"}
  "opam-state" {= version}
]
conflicts: [ "merlin" {< "3.4.0"} ]
"""
    found = by_name(catalog({"x.opam": opam}, "x.opam"))
    assert {"ocaml", "dune", "opam-state"} <= set(found)
    assert found["ocaml"].claim.version is None
    assert found["ocaml"].claim.requested == ">=4.11.0"
    # `{= version}` refers to this package's own version, not a literal
    assert found["opam-state"].claim.version is None
    assert "merlin" not in found  # conflicts are not dependencies


# -- Perl --------------------------------------------------------------------------------


def test_cpanfile_versions_are_minimums() -> None:
    cpanfile = """requires 'perl', '5.012000';
requires 'Plack', '1.0047';
requires 'Try::Tiny';
on 'test' => sub {
    requires 'Test::More', '0.88';
};
"""
    found = by_name(catalog({"cpanfile": cpanfile}, "cpanfile"))
    assert "perl" not in found  # the interpreter, not a distribution
    assert found["Plack"].claim.version is None
    assert found["Plack"].claim.requested == ">=1.0047"
    assert found["Try::Tiny"].claim.requested is None
    assert found["Test::More"].edges[0].scope is Scope.TEST


def test_perl_meta_json_only_claims_cpan_meta() -> None:
    meta = json.dumps(
        {"prereqs": {"runtime": {"requires": {"Plack": "1.0047", "perl": "5.012"}}}}
    )
    found = by_name(catalog({"META.json": meta}, "META.json"))
    assert set(found) == {"Plack"}
    assert found["Plack"].claim.requested == ">=1.0047"
    # an unrelated META.json must not be mistaken for a CPAN distribution
    assert catalog({"META.json": json.dumps({"name": "x"})}, "META.json") == []


# -- Lua ---------------------------------------------------------------------------------


def test_rockspec_believes_literals_only() -> None:
    """`package = package_name` names a Lua variable, not a package."""
    computed = """local package_name = "penlight"
package = package_name
version = package_version .. "-1"
dependencies = {
  "lua >= 5.1",
  "luafilesystem"
}
"""
    found = catalog({"p.rockspec": computed}, "p.rockspec")
    named = by_name(found)
    assert "package_name" not in named and "penlight" not in named
    assert "lua" not in named  # the interpreter
    assert named["luafilesystem"].claim.version is None
    assert "unresolved-dynamic-manifest" in {a.code for f in found for a in f.annotations}


# -- OS package databases ----------------------------------------------------------------


def test_portage_vdb_uses_category_and_splits_at_the_version() -> None:
    """A Gentoo package name may contain hyphens; the version starts at a digit."""
    files = {
        "var/db/pkg/app-text/docbook-xml-dtd-4.1.2-r7/PF": "docbook-xml-dtd-4.1.2-r7",
        "var/db/pkg/app-text/docbook-xml-dtd-4.1.2-r7/CATEGORY": "app-text",
        "var/db/pkg/app-text/docbook-xml-dtd-4.1.2-r7/SLOT": "4.1.2",
        "var/db/pkg/app-text/docbook-xml-dtd-4.1.2-r7/repository": "gentoo",
    }
    found = catalog(files, "var/db/pkg/app-text/docbook-xml-dtd-4.1.2-r7/PF")
    assert len(found) == 1
    claim = found[0].claim
    assert claim.name == "docbook-xml-dtd" and claim.version == "4.1.2-r7"
    assert claim.namespace == "app-text"
    assert "slot=4.1.2" in (claim.purl or "")
    assert found[0].evidence[0].tier is Tier.INSTALLED


def test_snap_yaml_is_installed_state() -> None:
    snap = "name: hello-world\nversion: '6.4'\nsummary: demo\narchitectures: [ all ]\n"
    found = catalog({"snap/meta/snap.yaml": snap}, "snap/meta/snap.yaml")
    assert [(f.claim.name, f.claim.version) for f in found] == [("hello-world", "6.4")]
    assert found[0].evidence[0].tier is Tier.INSTALLED


def test_homebrew_formula_and_cask_identity_comes_from_the_path() -> None:
    """brew's receipt states no version; the path it is filed under does.

    Homebrew was absent from the host store list entirely, which made a scan of
    a Mac report almost nothing — most software on a developer Mac is a keg.
    """
    receipt = json.dumps({"poured_from_bottle": True, "source": {"tap": "homebrew/core"}})
    keg = "opt/homebrew/Cellar/jq/1.7.1/INSTALL_RECEIPT.json"
    found = catalog({keg: receipt}, keg)
    assert len(found) == 1
    claim = found[0].claim
    assert (claim.name, claim.version) == ("jq", "1.7.1")
    assert claim.purl == "pkg:brew/jq@1.7.1"
    assert dict(claim.attrs)["poured-from-bottle"] == "true"
    assert dict(claim.attrs)["tap"] == "homebrew/core"
    assert found[0].evidence[0].tier is Tier.INSTALLED

    # a cask files its receipt under .metadata/<version>/<stamp>/Casks/<name>.json
    cask = (
        "opt/homebrew/Caskroom/gcloud-cli/.metadata/503.0.0/"
        "20241216124731.495/Casks/gcloud-cli.json"
    )
    cfound = catalog({cask: json.dumps({"token": "gcloud-cli"})}, cask)
    assert [(f.claim.name, f.claim.version) for f in cfound] == [("gcloud-cli", "503.0.0")]


def test_homebrew_is_a_discovered_host_store() -> None:
    """Both Apple Silicon and Intel prefixes, formulae and casks."""
    from sorb.source.host import _FIXED_STORES

    for expected in (
        "opt/homebrew/Cellar", "usr/local/Cellar",
        "opt/homebrew/Caskroom", "usr/local/Caskroom",
    ):
        assert expected in _FIXED_STORES, expected
