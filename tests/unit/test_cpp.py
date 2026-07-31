"""vcpkg, Conan, CMake, and the C/C++ long-tail catalogers."""

from __future__ import annotations

import json

from sorb.catalogers.base import CatalogerContext, dispatch
from sorb.model import Coordinates, Finding, Scope, Tier
from sorb.source.base import Entry


class MapSource:
    def __init__(self, files: dict[str, bytes]):
        self.files = files

    def exists(self, path: str) -> bool:
        return path in self.files

    def open(self, path: str) -> bytes:
        return self.files[path]

    def coords(self, path: str, span=None):  # noqa: ANN001
        return Coordinates(source_id="s1", path=path, span=span)


def catalog(files: dict[str, bytes | str], path: str) -> list[Finding]:
    raw = {k: (v.encode() if isinstance(v, str) else v) for k, v in files.items()}
    blob = raw[path]
    entry = Entry(path=path, size=len(blob), sniff=blob[:64])
    out: list[Finding] = []
    for c in dispatch(entry):
        ctx = CatalogerContext(source=MapSource(raw), detector=c.detector)  # type: ignore[arg-type]
        out.extend(c.parse(ctx, entry, blob))
    return out


def by_name(fs: list[Finding]) -> dict[str, Finding]:
    return {f.claim.name: f for f in fs}


# -- vcpkg ------------------------------------------------------------------------------


def test_vcpkg_manifest_resolves_without_vcpkg() -> None:
    """Manifest fixture resolves exact port versions (via
    overrides/version>=) without vcpkg installed."""
    manifest = json.dumps({
        "name": "myapp",
        "builtin-baseline": "a1b2c3d4e5f6",
        "dependencies": [
            "zlib",
            {"name": "openssl", "version>=": "3.0.13", "features": ["tools"]},
            {"name": "fmt"},
        ],
        "overrides": [{"name": "fmt", "version": "10.2.1"}],
    })
    config = json.dumps({
        "registries": [{"kind": "git", "repository": "https://priv.example/registry",
                        "packages": ["fmt"]}]
    })
    fs = by_name(catalog({"vcpkg.json": manifest, "vcpkg-configuration.json": config}, "vcpkg.json"))
    assert fs["openssl"].claim.version == "3.0.13"
    assert fs["openssl"].evidence[0].tier is Tier.LOCKED
    assert ("feature", "tools") in fs["openssl"].claim.attrs
    assert fs["fmt"].claim.version == "10.2.1"  # override resolved
    assert "priv.example" in (fs["fmt"].claim.purl or "")  # registry provenance
    # zlib has no override/constraint → declared + resolution-incomplete
    assert fs["zlib"].claim.version is None
    assert any(a.code == "resolution-incomplete" for a in fs["zlib"].annotations)


def test_vcpkg_status_triplet_linkage() -> None:
    """Static-linkage triplet lands in qualifiers."""
    status = (
        "Package: zlib\nVersion: 1.3.1\nPort-Version: 0\n"
        "Architecture: x64-linux-static\nStatus: install ok installed\n"
        "Depends: \nAbi: deadbeef\n\n"
        "Package: openssl\nVersion: 3.0.13\nArchitecture: x64-linux-static\n"
        "Status: install ok installed\nDepends: zlib\n"
    )
    fs = by_name(catalog({"installed/vcpkg/status": status}, "installed/vcpkg/status"))
    zlib = fs["zlib"]
    quals = dict(zlib.claim.qualifiers)
    assert quals["linkage"] == "static"  # security-relevant
    assert quals["arch"] == "x64" and quals["os"] == "linux"
    assert zlib.evidence[0].tier is Tier.INSTALLED
    assert any("zlib" in e.dst for e in fs["openssl"].edges)


def test_vcpkg_spdx_verify_ingest() -> None:
    spdx = json.dumps({
        "packages": [{"name": "curl", "versionInfo": "8.6.0", "licenseConcluded": "curl"}]
    })
    fs = catalog({"share/curl/vcpkg.spdx.json": spdx}, "share/curl/vcpkg.spdx.json")
    curl = fs[0]
    assert curl.claim.name == "curl" and curl.claim.version == "8.6.0"
    assert any(a.code == "vcpkg-spdx-ingested" for a in curl.annotations)


# -- Conan ------------------------------------------------------------------------------


def test_conan_lock_v2_revisions() -> None:
    """v2 lock graph matches expected with recipe revisions."""
    lock = json.dumps({
        "version": "0.5",
        "requires": ["zlib/1.3.1#abc123revision%1700000000", "openssl/3.2.0#def456"],
        "build_requires": ["cmake/3.28.1#rev"],
    })
    fs = by_name(catalog({"conan.lock": lock}, "conan.lock"))
    assert fs["zlib"].claim.version == "1.3.1"
    assert dict(fs["zlib"].claim.qualifiers)["rrev"] == "abc123revision"
    assert fs["zlib"].evidence[0].tier is Tier.LOCKED
    assert "cmake" in fs


def test_conanfile_txt_and_dynamic_py() -> None:
    txt = "[requires]\nzlib/1.3.1\nfmt/10.2.1\n[tool_requires]\ncmake/3.28.1\n"
    fs = by_name(catalog({"conanfile.txt": txt}, "conanfile.txt"))
    assert fs["zlib"].claim.version == "1.3.1"
    assert fs["cmake"].edges[0].scope.value == "build"

    dyn = "from conan import ConanFile\nclass R(ConanFile):\n    def requirements(self):\n        self.requires('boost/1.84.0')\n"
    dfs = catalog({"conanfile.py": dyn}, "conanfile.py")
    # the explicit self.requires is captured; no dynamic annotation needed
    assert any(f.claim.name == "boost" for f in dfs)


# -- CMake ------------------------------------------------------------------------------


def test_cmake_fetchcontent_pinned_vs_tag() -> None:
    """FetchContent pinned-hash → locked, tag-only → declared."""
    cml = (
        "cmake_minimum_required(VERSION 3.20)\n"
        "find_package(OpenSSL 3.0 REQUIRED)\n"
        "include(FetchContent)\n"
        "FetchContent_Declare(json GIT_REPOSITORY https://github.com/nlohmann/json GIT_TAG a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0)\n"
        'CPMAddPackage("fmtlib/fmt@10.2.1")\n'
    )
    fs = by_name(catalog({"CMakeLists.txt": cml}, "CMakeLists.txt"))
    assert fs["OpenSSL"].claim.requested == "3.0"
    json_dep = fs["json"]
    assert json_dep.evidence[0].tier is Tier.LOCKED  # pinned commit
    assert fs["fmt"].claim.version == "10.2.1" and fs["fmt"].evidence[0].tier is Tier.LOCKED


def test_cmake_file_api_target_links() -> None:
    """Configured-build-tree File API yields per-target links,
    no cmake execution."""
    target = json.dumps({
        "name": "myapp",
        "link": {"commandFragments": [
            {"role": "libraries", "fragment": "-lssl -lcrypto /usr/lib/libz.so"},
            {"role": "flags", "fragment": "-O2"},
        ]},
    })
    fs = by_name(catalog(
        {"build/.cmake/api/v1/reply/target-myapp.json": target},
        "build/.cmake/api/v1/reply/target-myapp.json",
    ))
    assert "ssl" in fs and "crypto" in fs and "z" in fs
    assert dict(fs["ssl"].claim.attrs)["linked-by-target"] == "myapp"


# -- long tail --------------------------------------------------------------------------


def test_meson_wrap_and_pkgconfig() -> None:
    wrap = "[wrap-file]\ndirectory = zlib-1.3.1\nsource_url = https://zlib.net/zlib-1.3.1.tar.gz\nsource_hash = deadbeef\nwrap_version = 1.3.1\n"
    fs = catalog({"subprojects/zlib.wrap": wrap}, "subprojects/zlib.wrap")
    assert fs[0].claim.name == "zlib" and fs[0].claim.version == "1.3.1"
    assert dict(fs[0].claim.hashes)["sha256"] == "deadbeef"

    pc = "prefix=/usr\nName: libssl\nDescription: SSL\nVersion: 3.0.13\nLibs: -lssl\n"
    pfs = catalog({"usr/lib/pkgconfig/libssl.pc": pc}, "usr/lib/pkgconfig/libssl.pc")
    assert pfs[0].claim.name == "libssl" and pfs[0].claim.version == "3.0.13"
    assert pfs[0].evidence[0].tier is Tier.INSTALLED


def test_gitmodules_pinned_commit_locked() -> None:
    """Submodule pinned commit lands as locked tier."""
    gm = '[submodule "third_party/zlib"]\n\tpath = third_party/zlib\n\turl = https://github.com/madler/zlib.git\n'
    commit = "a" * 40
    fs = catalog(
        {".gitmodules": gm, ".git/modules/third_party/zlib/HEAD": commit},
        ".gitmodules",
    )
    zlib = fs[0]
    assert zlib.claim.name == "zlib"
    assert zlib.claim.namespace == "github.com/madler"
    assert zlib.evidence[0].tier is Tier.LOCKED  # pinned commit → locked
    assert zlib.claim.version == commit[:12]

    # without the commit → declared + resolution-incomplete
    fs2 = catalog({".gitmodules": gm}, ".gitmodules")
    assert fs2[0].evidence[0].tier is Tier.DECLARED
    assert any(a.code == "resolution-incomplete" for a in fs2[0].annotations)


def test_makefile_ldflags_inferred() -> None:
    mk = "CFLAGS=-O2\nLDLIBS=-lssl -lcrypto -lz -lpthread -lm\napp: main.o\n"
    fs = by_name(catalog({"Makefile": mk}, "Makefile"))
    assert "ssl" in fs and "crypto" in fs and "z" in fs
    assert "pthread" not in fs and "m" not in fs  # system noise filtered
    assert fs["ssl"].evidence[0].tier is Tier.INFERRED


def test_vcpkg_feature_dependencies_are_emitted_and_gated() -> None:
    """Deps under `features` are real declarations, not decoration.

    microsoft/terminal declares 5 dependencies; 3 of them live under a feature,
    and ignoring that block reported the project as having only 2.
    """
    manifest = json.dumps(
        {
            "dependencies": ["fmt", "ms-gsl"],
            "features": {
                "terminal": {
                    "description": "Windows Terminal components",
                    "dependencies": ["jsoncpp", "cli11", "cmark"],
                }
            },
            "overrides": [
                {"name": "fmt", "version": "12.1.0"},
                {"name": "jsoncpp", "version": "1.9.6"},
                {"name": "cli11", "version": "2.6.1"},
                {"name": "cmark", "version": "0.31.1"},
                {"name": "ms-gsl", "version": "4.2.2"},
            ],
        }
    )
    found = by_name(catalog({"vcpkg.json": manifest}, "vcpkg.json"))
    assert set(found) == {"fmt", "ms-gsl", "jsoncpp", "cli11", "cmark"}
    assert found["jsoncpp"].claim.version == "1.9.6"  # override still applies
    assert dict(found["cli11"].claim.attrs)["gated-by-feature"] == "terminal"
    # a feature is opt-in, so its edge is conditional, exactly like an extra
    assert found["cmark"].edges[0].marker == "feature:terminal"
    assert found["cmark"].edges[0].scope is Scope.OPTIONAL
    assert found["fmt"].edges[0].marker is None
    assert "gated-by-feature" not in dict(found["fmt"].claim.attrs)


def test_meson_wrap_git_uses_revision_not_directory() -> None:
    """`directory` is not a version: a wrap-git names a bare directory.

    Splitting it on "-" reported `libpng` as the version *of libpng*, and hid
    the real pin sitting in `revision`.
    """
    wrap = (
        "[wrap-git]\ndirectory = libpng\n"
        "url = https://github.com/glennrp/libpng.git\nrevision = v1.6.40\n"
    )
    fs = catalog({"subprojects/libpng.wrap": wrap}, "subprojects/libpng.wrap")
    assert fs[0].claim.name == "libpng"
    assert fs[0].claim.version == "v1.6.40"
    assert fs[0].claim.version != "libpng"

    # a directory with no version at all yields no version, never a guess
    bare = "[wrap-git]\ndirectory = mylib\nurl = https://example.com/mylib.git\n"
    bfs = catalog({"subprojects/mylib.wrap": bare}, "subprojects/mylib.wrap")
    assert bfs[0].claim.version is None
    # and the wrap-file form still reads its version out of the directory
    wf = "[wrap-file]\ndirectory = zlib-1.3.1\nsource_url = https://zlib.net/z.tar.gz\n"
    zfs = catalog({"subprojects/zlib.wrap": wf}, "subprojects/zlib.wrap")
    assert zfs[0].claim.version == "1.3.1"


def test_maven_property_from_parent_pom_is_evidenced() -> None:
    """A version interpolated from a parent must cite where it is defined.

    Otherwise the SBOM says 4.8.0 while the only file it names says
    `${pax.exam.version}` — true, but not checkable from the cited bytes.
    """
    child = """<project>
      <parent><groupId>g</groupId><artifactId>p</artifactId><version>1</version></parent>
      <artifactId>child</artifactId>
      <dependencies>
        <dependency>
          <groupId>org.ops4j.pax.exam</groupId>
          <artifactId>pax-exam-junit4</artifactId>
          <version>${pax.exam.version}</version>
        </dependency>
      </dependencies>
    </project>"""
    parent = """<project>
      <groupId>g</groupId><artifactId>p</artifactId><version>1</version>
      <properties>
        <pax.exam.version>4.8.0</pax.exam.version>
      </properties>
    </project>"""
    fs = catalog({"mod/pom.xml": child, "pom.xml": parent}, "mod/pom.xml")
    dep = by_name(fs)["org.ops4j.pax.exam:pax-exam-junit4"]
    assert dep.claim.version == "4.8.0"
    cited = {e.location.path for e in dep.evidence}
    assert "pom.xml" in cited, f"parent pom not cited: {cited}"
    prop_ev = next(e for e in dep.evidence if e.location.path == "pom.xml")
    assert "4.8.0" in (prop_ev.captured or "")
    assert prop_ev.location.span is not None


def test_makefile_long_options_are_not_libraries() -> None:
    """`-l` has to start an option, or ordinary prose becomes dependencies.

    Without a left boundary the `-l` inside `--license` matched, and a real
    build tree produced libraries named `icense`, `ist`, `ine` and `evel`.
    """
    makefile = (
        "LDLIBS = -lssl -lcrypto -lz\n"
        "docs:\n"
        "\t$(TOOL) --license --list --line-numbers --level=3\n"
        "\t$(CC) -Wl,--gc-sections $(LDLIBS) -lstdc++\n"
    )
    names = {f.claim.name for f in catalog({"Makefile": makefile}, "Makefile")}
    assert {"ssl", "crypto", "z", "stdc++"} <= names
    assert not ({"icense", "ist", "ine", "evel", "ine-numbers"} & names), names
