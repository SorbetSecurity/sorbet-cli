"""Ecosystem catalogers: Maven, Gradle/JAR, .NET,
Ruby+PHP, the long tail, and license detection."""

from __future__ import annotations

import io
import json
import struct
import zipfile

from sorb.catalogers.base import CatalogerContext, dispatch
from sorb.model import Coordinates, EdgeType, Finding, Tier
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
    """Run every matching registered cataloger over `path` within `files`."""
    raw = {k: (v.encode() if isinstance(v, str) else v) for k, v in files.items()}
    blob = raw[path]
    entry = Entry(path=path, size=len(blob), sniff=blob[:64])
    out: list[Finding] = []
    for cataloger in dispatch(entry):
        ctx = CatalogerContext(source=MapSource(raw), detector=cataloger.detector)  # type: ignore[arg-type]
        out.extend(cataloger.parse(ctx, entry, blob))
    return out


def by_name(findings: list[Finding]) -> dict[str, Finding]:
    return {f.claim.name: f for f in findings}


# -- Maven POM model --------------------------------------------------------------------

PARENT_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.acme</groupId><artifactId>acme-parent</artifactId><version>2.0.0</version>
  <packaging>pom</packaging>
  <properties><guava.version>33.0.0-jre</guava.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId>
      <version>${guava.version}</version></dependency>
    <dependency><groupId>com.acme</groupId><artifactId>acme-bom</artifactId>
      <version>1.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
</project>"""

BOM_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.acme</groupId><artifactId>acme-bom</artifactId><version>1.0</version>
  <packaging>pom</packaging>
  <dependencyManagement><dependencies>
    <dependency><groupId>io.netty</groupId><artifactId>netty-all</artifactId>
      <version>4.1.100.Final</version></dependency>
  </dependencies></dependencyManagement>
</project>"""

CHILD_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>com.acme</groupId><artifactId>acme-parent</artifactId>
    <version>2.0.0</version></parent>
  <artifactId>api</artifactId>
  <dependencies>
    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId></dependency>
    <dependency><groupId>io.netty</groupId><artifactId>netty-all</artifactId></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId>
      <version>4.13.2</version><scope>test</scope></dependency>
    <dependency><groupId>jakarta.servlet</groupId><artifactId>jakarta.servlet-api</artifactId>
      <version>6.0.0</version><scope>provided</scope></dependency>
  </dependencies>
  <profiles><profile><id>legacy</id>
    <dependencies><dependency><groupId>log4j</groupId><artifactId>log4j</artifactId>
      <version>1.2.17</version></dependency></dependencies>
  </profile></profiles>
</project>"""

MAVEN_TREE = {  # committed `mvn dependency:tree` ground truth for the fixture
    "com.google.guava:guava": "33.0.0-jre",
    "io.netty:netty-all": "4.1.100.Final",
    "junit:junit": "4.13.2",
    "jakarta.servlet:jakarta.servlet-api": "6.0.0",
}


def _maven_files() -> dict[str, str]:
    return {
        "pom.xml": PARENT_POM,
        "acme-bom/pom.xml": BOM_POM,
        "api/pom.xml": CHILD_POM,
    }


def test_maven_versions_match_recorded_tree() -> None:
    findings = catalog(_maven_files(), "api/pom.xml")
    got = {f.claim.name: f.claim.version for f in findings if f.claim.name in MAVEN_TREE}
    assert got == MAVEN_TREE  # every recorded version matches


def test_maven_scopes_profiles_and_provided() -> None:
    findings = by_name(catalog(_maven_files(), "api/pom.xml"))
    junit_edge = findings["junit:junit"].edges[0]
    assert junit_edge.scope is not None and junit_edge.scope.value == "test"
    servlet = findings["jakarta.servlet:jakarta.servlet-api"]
    assert any(a.code == "provided-scope" for a in servlet.annotations)
    log4j_edge = findings["log4j:log4j"].edges[0]
    assert log4j_edge.marker == "profile:legacy"  # non-default profile = conditional


def test_maven_unresolved_parent_is_annotated() -> None:
    findings = catalog({"api/pom.xml": CHILD_POM}, "api/pom.xml")
    codes = {a.code for f in findings for a in f.annotations}
    assert "unresolved-parent" in codes
    guava = by_name(findings)["com.google.guava:guava"]
    assert guava.claim.version is None  # no guess without the parent's depMgmt
    assert any(a.code == "resolution-incomplete" for a in guava.annotations)


# -- Gradle + JAR ----------------------------------------------------------------------


def test_gradle_lockfile_and_verification_metadata() -> None:
    lock = "org.slf4j:slf4j-api:2.0.9=runtimeClasspath\ncom.foo:bar:1.0=testCompileClasspath\nempty=annotationProcessor\n"
    findings = by_name(catalog({"gradle.lockfile": lock}, "gradle.lockfile"))
    assert findings["org.slf4j:slf4j-api"].claim.version == "2.0.9"
    assert findings["org.slf4j:slf4j-api"].evidence[0].tier is Tier.LOCKED
    assert findings["com.foo:bar"].edges[0].scope.value == "test"

    vm = """<verification-metadata><components>
      <component group="org.slf4j" name="slf4j-api" version="2.0.9">
        <artifact name="slf4j-api-2.0.9.jar"><sha256 value="abc123"/></artifact>
      </component></components></verification-metadata>"""
    vfindings = by_name(catalog({"gradle/verification-metadata.xml": vm}, "gradle/verification-metadata.xml"))
    assert dict(vfindings["org.slf4j:slf4j-api"].claim.hashes)["sha256"] == "abc123"


def test_gradle_version_catalog_and_incomplete_build() -> None:
    toml = '[versions]\nkotlinx = "1.8.0"\n[libraries]\ncoroutines = { module = "org.jetbrains.kotlinx:kotlinx-coroutines-core", version.ref = "kotlinx" }\nokio = "com.squareup.okio:okio:3.7.0"\n'
    findings = by_name(catalog({"gradle/libs.versions.toml": toml}, "gradle/libs.versions.toml"))
    assert findings["org.jetbrains.kotlinx:kotlinx-coroutines-core"].claim.version == "1.8.0"
    assert findings["com.squareup.okio:okio"].claim.version == "3.7.0"

    build = 'dependencies {\n  implementation("com.google.guava:guava:33.0.0-jre")\n}\n'
    bfindings = catalog({"build.gradle.kts": build}, "build.gradle.kts")
    guava = by_name(bfindings)["com.google.guava:guava"]
    assert any(a.code == "resolution-incomplete" for a in guava.annotations)  # no lock

    with_lock = catalog(
        {"build.gradle.kts": build, "gradle.lockfile": "com.google.guava:guava:33.0.0-jre=rc\n"},
        "build.gradle.kts",
    )
    guava2 = by_name(with_lock)["com.google.guava:guava"]
    assert not any(a.code == "resolution-incomplete" for a in guava2.annotations)


def _jar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_fat_jar_inner_libs_become_contains_children() -> None:
    inner = _jar(
        {
            "META-INF/maven/org.slf4j/slf4j-api/pom.properties": b"groupId=org.slf4j\nartifactId=slf4j-api\nversion=2.0.9\n",
            "org/slf4j/Logger.class": b"\xca\xfe\xba\xbe",
        }
    )
    mystery = _jar({"com/x/Y.class": b"\xca\xfe\xba\xbe"})
    fat = _jar(
        {
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nImplementation-Title: acme-app\nImplementation-Version: 1.0.0\n",
            "META-INF/maven/com.acme/acme-app/pom.properties": b"groupId=com.acme\nartifactId=acme-app\nversion=1.0.0\n",
            "BOOT-INF/lib/slf4j-api-2.0.9.jar": inner,
            "BOOT-INF/lib/mystery-1.0.jar": mystery,
        }
    )
    findings = catalog({"app/acme-app-1.0.0.jar": fat}, "app/acme-app-1.0.0.jar")
    names = by_name(findings)
    assert names["com.acme:acme-app"].claim.version == "1.0.0"
    slf4j = names["org.slf4j:slf4j-api"]
    assert slf4j.claim.version == "2.0.9"
    assert slf4j.evidence[0].tier is Tier.INSTALLED
    contains = [e for f in findings for e in f.edges if e.kind is EdgeType.CONTAINS]
    assert any("slf4j-api" in e.dst for e in contains)
    codes = {a.code for f in findings for a in f.annotations}
    assert "contains-unidentified-classes" in codes  # the mystery jar


# -- .NET -------------------------------------------------------------------------------


def test_csproj_with_central_package_management() -> None:
    csproj = '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" /><PackageReference Include="Serilog" Version="3.1.1" /></ItemGroup></Project>'
    props = '<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>'
    findings = by_name(
        catalog({"src/Api/Api.csproj": csproj, "Directory.Packages.props": props}, "src/Api/Api.csproj")
    )
    newtonsoft = findings["Newtonsoft.Json"]
    assert newtonsoft.claim.version == "13.0.3"
    assert dict(newtonsoft.claim.attrs)["version-source"] == "Directory.Packages.props"
    assert findings["Serilog"].claim.version == "3.1.1"


def test_packages_lock_and_project_assets() -> None:
    lock = json.dumps(
        {
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": {
                        "type": "Direct",
                        "requested": "[13.0.3, )",
                        "resolved": "13.0.3",
                        "contentHash": "QUJDRA==",
                    },
                    "MyProject.Core": {"type": "Project"},
                }
            },
        }
    )
    findings = by_name(catalog({"packages.lock.json": lock}, "packages.lock.json"))
    assert set(findings) == {"Newtonsoft.Json"}
    assert findings["Newtonsoft.Json"].edges[0].direct is True

    assets = json.dumps(
        {
            "targets": {".NETCoreApp,Version=v8.0/linux-x64": {"Serilog/3.1.1": {}}},
            "libraries": {"Serilog/3.1.1": {"type": "package", "sha512": "QUJDRA=="}},
        }
    )
    afindings = by_name(catalog({"obj/project.assets.json": assets}, "obj/project.assets.json"))
    serilog = afindings["Serilog"]
    assert serilog.evidence[0].tier is Tier.INSTALLED
    assert dict(serilog.claim.qualifiers).get("rid") == "linux-x64"  # RID assets qualified


def make_dotnet_assembly(name: str, version: tuple[int, int, int, int],
                         refs: list[tuple[str, tuple[int, int, int, int]]]) -> bytes:
    """Format-exact minimal .NET PE: CLR header + BSJB metadata with
    Module(0x00), Assembly(0x20) and AssemblyRef(0x23) tables."""
    strings = bytearray(b"\x00")
    def s(value: str) -> int:
        off = len(strings)
        strings.extend(value.encode() + b"\x00")
        return off

    name_idx = s(name)
    ref_idxs = [s(r) for r, _ in refs]
    while len(strings) % 4:
        strings.append(0)

    rows_module = struct.pack("<H", 0) + struct.pack("<HHHH", 1, 0, 0, 0)  # gen + S + 3×G (2b each)
    rows_assembly = struct.pack(
        "<IHHHHI", 0x8004, *version, 0
    ) + struct.pack("<HHH", 0, name_idx, 0)  # blob(publickey) + S(name) + S(culture)
    rows_refs = b"".join(
        struct.pack("<HHHH", *ver) + struct.pack("<IHHHH", 0, 0, idx, 0, 0)
        for (_, ver), idx in zip(refs, ref_idxs, strict=True)
    )  # ver(4×2) + flags(4) + blob + S + S + blob(hash)
    valid = (1 << 0x00) | (1 << 0x20) | ((1 << 0x23) if refs else 0)
    rowcounts = struct.pack("<I", 1) + struct.pack("<I", 1) + (
        struct.pack("<I", len(refs)) if refs else b""
    )
    tables = (
        struct.pack("<IBBBB", 0, 2, 0, 0x00, 1)
        + struct.pack("<QQ", valid, 0)
        + rowcounts
        + rows_module
        + rows_assembly
        + rows_refs
    )
    while len(tables) % 4:
        tables += b"\x00"

    version_str = b"v4.0.30319\x00\x00"
    stream_headers_size = (8 + 4) + (8 + 12)  # "#~\0\0" pad4 | "#Strings\0" pad4→12
    root_header_size = 16 + len(version_str) + 4
    tables_off = root_header_size + stream_headers_size
    strings_off = tables_off + len(tables)
    metadata = (
        struct.pack("<IHHI", 0x424A5342, 1, 1, 0)
        + struct.pack("<I", len(version_str))
        + version_str
        + struct.pack("<HH", 0, 2)
        + struct.pack("<II", tables_off, len(tables)) + b"#~\x00\x00"
        + struct.pack("<II", strings_off, len(strings)) + b"#Strings\x00\x00\x00\x00"
        + tables
        + bytes(strings)
    )

    # one section: metadata preceded by the 72-byte CLR header
    clr_rva = 0x2000
    md_rva = clr_rva + 72
    clr_header = struct.pack("<IHHIIIIQQQQQQ", 72, 2, 5, md_rva, len(metadata), 1, 0, 0, 0, 0, 0, 0, 0)
    section_data = clr_header + metadata

    e_lfanew = 0x80
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew)
    dos += b"\x00" * (e_lfanew - len(dos))
    opt_size = 96 + 16 * 8  # PE32, 16 data directories
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, opt_size, 0x2102)
    raw_ptr = e_lfanew + 4 + 20 + opt_size + 40
    raw_ptr = (raw_ptr + 0x1FF) & ~0x1FF
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32 magic
    struct.pack_into("<II", opt, 96 + 14 * 8, clr_rva, 72)  # data directory 14 → CLR header
    section = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHI", len(section_data), clr_rva, len(section_data), raw_ptr, 0, 0, 0, 0, 0x60000020
    )
    header = dos + coff + bytes(opt) + section
    header += b"\x00" * (raw_ptr - len(header))
    return header + section_data


def test_clr_assembly_identity() -> None:
    from sorb.binary.embedded.clr import parse_assembly_identity

    blob = make_dotnet_assembly(
        "Acme.WebApi", (1, 2, 3, 4), [("Newtonsoft.Json", (13, 0, 0, 0))]
    )
    identity = parse_assembly_identity(blob)
    assert identity is not None
    assert identity.name == "Acme.WebApi" and identity.version == "1.2.3.4"
    assert identity.references == (("Newtonsoft.Json", "13.0.0.0"),)
    assert parse_assembly_identity(b"MZ" + b"\x00" * 200) is None

    findings = catalog({"bin/Acme.WebApi.dll": blob}, "bin/Acme.WebApi.dll")
    acme = by_name(findings)["Acme.WebApi"]
    assert acme.evidence[0].technique == "assembly-identity"


# -- Ruby + PHP ----------------------------------------------------------------------

GEMFILE_LOCK = """GEM
  remote: https://rubygems.org/
  specs:
    mini_portile2 (2.8.5)
    nokogiri (1.16.0)
      mini_portile2 (~> 2.8.2)
    rake (13.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri (~> 1.16)
  rake

BUNDLED WITH
   2.4.10
"""


def test_gemfile_lock_edges_match_files_own_graph() -> None:
    findings = catalog({"Gemfile.lock": GEMFILE_LOCK}, "Gemfile.lock")
    names = by_name(findings)
    assert names["nokogiri"].claim.version == "1.16.0"
    nokogiri_deps = [
        e for e in names["nokogiri"].edges if e.kind is EdgeType.DEPENDS_ON and "mini_portile2" in e.dst
    ]
    assert nokogiri_deps and nokogiri_deps[0].requested == "~> 2.8.2"
    # DEPENDENCIES section marks direct project deps
    direct = [e for e in names["nokogiri"].edges if e.src.startswith("project:")]
    assert direct and direct[0].direct is True
    assert not [e for e in names["mini_portile2"].edges if e.src.startswith("project:")]


def test_composer_installed_wins_tier_over_lock() -> None:
    lock = json.dumps(
        {"packages": [{"name": "monolog/monolog", "version": "3.5.0",
                       "license": ["MIT"], "require": {"php": ">=8.1", "psr/log": "^2.0 || ^3.0"}}],
         "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.0"}]}
    )
    installed = json.dumps(
        {"packages": [{"name": "monolog/monolog", "version": "3.5.1",
                       "dist": {"shasum": "abc"}}], "dev-package-names": []}
    )
    lock_f = by_name(catalog({"composer.lock": lock}, "composer.lock"))
    inst_f = by_name(catalog({"vendor/composer/installed.json": installed}, "vendor/composer/installed.json"))
    assert lock_f["monolog/monolog"].evidence[0].tier is Tier.LOCKED
    assert inst_f["monolog/monolog"].evidence[0].tier is Tier.INSTALLED  # wins at reconcile
    assert dict(lock_f["phpunit/phpunit"].claim.attrs).get("dev") == "true"
    psr_edges = [e for e in lock_f["monolog/monolog"].edges if "psr/log" in e.dst]
    assert psr_edges  # php/ext-* platform reqs skipped, real packages kept


# -- long tail --------------------------------------------------------------------------


def test_longtail_formats() -> None:
    cases: list[tuple[str, str, str, str, str]] = [
        # (path, content, expected name, expected version, ecosystem)
        ("mix.lock",
         '%{\n  "jason": {:hex, :jason, "1.4.1", "af1504e35f629ddcdd6addb3513c3853991f694921b1b9368b0bd32beb9f1b63", [:mix], [], "hexpm"},\n}\n',
         "jason", "1.4.1", "hex"),
        ("stack.yaml.lock",
         'packages:\n- completed:\n    hackage: aeson-2.2.1.0@sha256:deadbeef,1234\n    pantry-tree:\n      size: 100\n',
         "aeson", "2.2.1.0", "hackage"),
        ("cabal.project.freeze",
         "constraints: any.aeson ==2.2.1.0,\n             any.base ==4.18.1.0\n",
         "aeson", "2.2.1.0", "hackage"),
        ("Package.resolved",
         json.dumps({"pins": [{"identity": "swift-nio", "location": "https://github.com/apple/swift-nio.git",
                                "state": {"version": "2.62.0", "revision": "abc"}}], "version": 2}),
         "swift-nio", "2.62.0", "swift"),
        ("Podfile.lock",
         'PODS:\n  - Alamofire (5.8.1)\n  - "Moya (15.0.0)":\n    - Alamofire (~> 5.0)\n\nDEPENDENCIES:\n  - Moya\n',
         "Alamofire", "5.8.1", "cocoapods"),
        ("Cartfile.resolved",
         'github "Alamofire/Alamofire" "5.8.1"\ngit "https://example.com/repo.git" "abc123"\n',
         "Alamofire", "5.8.1", "carthage"),
        ("renv.lock",
         json.dumps({"Packages": {"jsonlite": {"Package": "jsonlite", "Version": "1.8.8", "Hash": "e1b9c55"}}}),
         "jsonlite", "1.8.8", "cran"),
        ("Manifest.toml",
         '[[deps.HTTP]]\nversion = "1.10.1"\nuuid = "cd3eb016"\n',
         "HTTP", "1.10.1", "julia"),
        ("nimble.lock",
         json.dumps({"packages": {"karax": {"version": "1.3.3", "checksums": {"sha1": "abc"}}}}),
         "karax", "1.3.3", "nimble"),
        ("shard.lock",
         "version: 2.0\nshards:\n  kemal:\n    git: https://github.com/kemalcr/kemal.git\n    version: 1.4.0\n",
         "kemal", "1.4.0", "shards"),
        ("build.zig.zon",
         '.{\n  .name = "app",\n  .dependencies = .{\n    .zap = .{\n      .url = "https://github.com/zigzap/zap/archive/refs/tags/v0.5.1.tar.gz",\n      .hash = "1220deadbeef",\n    },\n  },\n}\n',
         "zap", "0.5.1", "zig"),
    ]
    for path, content, name, version, eco in cases:
        findings = catalog({path: content}, path)
        hit = next((f for f in findings if f.claim.name == name), None)
        assert hit is not None, f"{path}: {name} not found in {[f.claim.name for f in findings]}"
        assert hit.claim.version == version, f"{path}: {hit.claim.version}"
        assert hit.claim.ecosystem == eco, path
        assert hit.evidence[0].tier is Tier.LOCKED, path


def test_cargo_workspace_inheritance() -> None:
    """Inherited specs are carried down, but a spec is not a resolved version.

    In Cargo `serde = "1.0.203"` is shorthand for `^1.0.203`, so it is recorded
    as a request; only Cargo.lock says which version is built. Emitting the
    range as a version would invent a component that was never installed.
    """
    root = '[workspace]\nmembers = ["crates/api"]\n[workspace.dependencies]\nserde = { version = "1.0.203", features = ["derive"] }\ntokio = "1.38.0"\n'
    member = '[package]\nname = "api"\nversion = "0.1.0"\n[dependencies]\nserde = { workspace = true }\ntokio = { workspace = true }\nlocal-only = "2.0.0"\npinned = "=3.1.0"\n'
    findings = by_name(
        catalog({"Cargo.toml": root, "crates/api/Cargo.toml": member}, "crates/api/Cargo.toml")
    )
    assert findings["serde"].claim.requested == "1.0.203"  # inherited from the workspace root
    assert findings["serde"].claim.version is None
    assert dict(findings["serde"].claim.attrs)["workspace-inherited"] == "true"
    assert findings["tokio"].claim.requested == "1.38.0"
    assert findings["local-only"].claim.requested == "2.0.0"
    # `=x.y.z` is an exact pin, so that one is a version
    assert findings["pinned"].claim.version == "3.1.0"
    assert findings["pinned"].claim.purl == "pkg:cargo/pinned@3.1.0"


# -- license detection ----------------------------------------------------------------------

MIT_TEXT = """MIT License

Copyright (c) 2024 Acme Corp

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

APACHE_HEADER_MODIFIED = """Copyright 2024 Acme Corp

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. This paragraph was added by legal.
"""


def test_license_detection_and_mismatch() -> None:
    from sorb.ident.licenses import detect_license, parse_spdx_expression

    mit = detect_license(MIT_TEXT)
    assert mit is not None and mit.spdx_id == "MIT" and mit.score > 0.95

    apache = detect_license(APACHE_HEADER_MODIFIED)
    assert apache is not None and apache.spdx_id == "Apache-2.0"  # modified header still detects

    assert detect_license("this is not a license at all " * 5) is None

    assert parse_spdx_expression("MIT OR  Apache-2.0") == "MIT OR Apache-2.0"
    assert parse_spdx_expression("(MIT OR GPL-3.0-only) AND Apache-2.0") == "(MIT OR GPL-3.0-only) AND Apache-2.0"
    assert parse_spdx_expression("GPL-2.0-only WITH Classpath-exception-2.0") == "GPL-2.0-only WITH Classpath-exception-2.0"
    import pytest

    from sorb.ident.licenses import SpdxExpressionError

    with pytest.raises(SpdxExpressionError):
        parse_spdx_expression("MIT OR")


def test_license_file_cataloger_declared_vs_detected() -> None:
    findings = catalog(
        {"LICENSE": MIT_TEXT, "package.json": json.dumps({"name": "x", "license": "Apache-2.0"})},
        "LICENSE",
    )
    codes = {a.code for f in findings for a in f.annotations}
    assert "license-detected" in codes
    assert "license-mismatch" in codes  # declared Apache-2.0 vs detected MIT

    agree = catalog(
        {"LICENSE": MIT_TEXT, "package.json": json.dumps({"name": "x", "license": "MIT"})},
        "LICENSE",
    )
    agree_codes = {a.code for f in agree for a in f.annotations}
    assert "license-mismatch" not in agree_codes


# -- Go replace directives ------------------------------------------------------------------


def test_go_local_path_replace_is_not_a_package() -> None:
    """`=> ./staging/...` builds from a directory; there is no package to name."""
    gomod = (
        "module k8s.io/kubernetes\n\ngo 1.22\n\n"
        "require (\n\tk8s.io/api v0.0.0\n\tgithub.com/spf13/cobra v1.8.0\n)\n\n"
        "replace (\n\tk8s.io/api => ./staging/src/k8s.io/api\n)\n"
    )
    findings = catalog({"go.mod": gomod}, "go.mod")
    purls = {f.claim.purl for f in findings}
    assert "pkg:golang/k8s.io/api@v0.0.0" in purls
    assert not any(p and "staging" in p for p in purls), "a directory became a component"
    api = by_name(findings)["k8s.io/api"]
    assert any(a.code == "replaced-by-local-path" for a in api.annotations)


def test_go_module_replace_still_emits_both_sides() -> None:
    gomod = (
        "module example.com/app\n\ngo 1.22\n\n"
        "require github.com/acme/mux v1.8.2\n\n"
        "replace github.com/acme/mux => github.com/gorilla/mux v1.8.1\n"
    )
    purls = {f.claim.purl for f in catalog({"go.mod": gomod}, "go.mod")}
    assert "pkg:golang/github.com/acme/mux@v1.8.2" in purls
    assert "pkg:golang/github.com/gorilla/mux@v1.8.1" in purls


def test_go_major_version_suffix_stays_in_the_module_path() -> None:
    """`.../backoff` and `.../backoff/v4` are different modules to Go."""
    gomod = "module m\n\ngo 1.22\n\nrequire github.com/cenkalti/backoff/v4 v4.3.0\n"
    purls = {f.claim.purl for f in catalog({"go.mod": gomod}, "go.mod")}
    assert "pkg:golang/github.com/cenkalti/backoff/v4@v4.3.0" in purls


# -- Gemfile.lock platform variants ----------------------------------------------------------


def test_gemfile_lock_collapses_platform_variants() -> None:
    """Bundler lists one spec per platform; only one is ever installed.

    The platform is not part of the gem version, so carrying it there would
    produce an identity no advisory could match.
    """
    lock = (
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        "    nokogiri (1.16.5)\n      racc (~> 1.4)\n"
        "    nokogiri (1.16.5-x86_64-darwin)\n      racc (~> 1.4)\n"
        "    nokogiri (1.16.5-x86_64-linux)\n      racc (~> 1.4)\n"
        "    racc (1.8.0)\n"
        "\nDEPENDENCIES\n  nokogiri\n"
    )
    findings = catalog({"Gemfile.lock": lock}, "Gemfile.lock")
    nokogiri = [f for f in findings if f.claim.name == "nokogiri"]
    assert len(nokogiri) == 1
    assert nokogiri[0].claim.version == "1.16.5"
    assert nokogiri[0].claim.purl == "pkg:gem/nokogiri@1.16.5"
    assert dict(nokogiri[0].claim.attrs)["platforms"] == "x86_64-darwin,x86_64-linux"


def test_gemfile_lock_keeps_dotted_prereleases() -> None:
    lock = (
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        "    rails (7.2.0.beta2)\n"
        "\nDEPENDENCIES\n  rails\n"
    )
    rails = by_name(catalog({"Gemfile.lock": lock}, "Gemfile.lock"))["rails"]
    assert rails.claim.version == "7.2.0.beta2"


# -- conda -------------------------------------------------------------------------------


def test_conda_environment_records_ranges_as_requests() -> None:
    """Conda's bare `=` is a fuzzy pin, not an exact version.

    `numpy=1.26.4` also matches `1.26.4.1`, so it is a request; only `==` pins.
    The installed record in conda-meta is where exact versions come from.
    """
    env = """name: demo
channels: [conda-forge]
dependencies:
  - python=3.12
  - numpy==1.26.4
  - conda-forge::click>=8.1
  - pyyaml
  - pip:
    - requests==2.31.0
    - rich>=13
"""
    found = {f.claim.name: f.claim for f in catalog({"environment.yml": env}, "environment.yml")}
    assert set(found) == {"python", "numpy", "click", "pyyaml", "requests", "rich"}

    assert found["numpy"].version == "1.26.4"  # == pins
    assert found["numpy"].purl == "pkg:conda/numpy@1.26.4"
    assert found["python"].version is None and found["python"].requested == "=3.12"
    assert found["click"].requested == ">=8.1"
    assert dict(found["click"].attrs)["conda-channel"] == "conda-forge"
    assert found["pyyaml"].version is None and found["pyyaml"].requested is None

    # the nested pip list is a different ecosystem in the same file
    assert found["requests"].ecosystem == "pypi"
    assert found["requests"].version == "2.31.0"
    assert found["rich"].ecosystem == "pypi" and found["rich"].version is None


def test_conda_meta_is_installed_state() -> None:
    """`conda-meta/<pkg>.json` is conda's install record, like `*.dist-info`."""
    meta = json.dumps(
        {
            "name": "numpy",
            "version": "1.26.4",
            "build": "py312h7f4fdc5_0",
            "channel": "https://conda.anaconda.org/conda-forge/linux-64",
            "sha256": "ab" * 32,
            "depends": ["python >=3.12,<3.13.0a0"],
        }
    )
    path = "envs/demo/conda-meta/numpy-1.26.4-py312h7f4fdc5_0.json"
    findings = catalog({path: meta}, path)
    assert len(findings) == 1
    claim = findings[0].claim
    assert claim.name == "numpy" and claim.version == "1.26.4"
    assert claim.purl == "pkg:conda/numpy@1.26.4"
    assert findings[0].evidence[0].tier is Tier.INSTALLED
    assert dict(claim.hashes)["sha256"] == "ab" * 32


def test_pdm_lock_is_locked_tier() -> None:
    """PDM's lockfile is `[[package]]`, structurally like Cargo.lock."""
    lock = """# This file is @generated by PDM.
[metadata]
groups = ["default"]

[[package]]
name = "anyio"
version = "4.13.0"
requires_python = ">=3.9"

[[package]]
name = "certifi"
version = "2024.2.2"
"""
    found = {f.claim.name: f for f in catalog({"pdm.lock": lock}, "pdm.lock")}
    assert set(found) == {"anyio", "certifi"}
    assert found["anyio"].claim.version == "4.13.0"
    assert found["anyio"].claim.purl == "pkg:pypi/anyio@4.13.0"
    assert found["anyio"].evidence[0].tier is Tier.LOCKED


def test_flake_lock_pins_inputs_by_revision() -> None:
    """A flake input is pinned by its git rev; `root` has none and is skipped."""
    lock = json.dumps(
        {
            "nodes": {
                "nixpkgs": {
                    "locked": {
                        "owner": "NixOS", "repo": "nixpkgs", "type": "github",
                        "rev": "38a4887411571457d700c51c64a6e49ead2ed5ab",
                        "narHash": "sha256-kh35kIx7el4Jk8Ki3BH9/Pn1eZYSYLJ6LMALos0zOy0=",
                    }
                },
                "root": {"inputs": {"nixpkgs": "nixpkgs"}},
            },
            "root": "root",
            "version": 7,
        }
    )
    findings = catalog({"flake.lock": lock}, "flake.lock")
    assert [f.claim.name for f in findings] == ["nixpkgs"]
    claim = findings[0].claim
    assert claim.version == "38a4887411571457d700c51c64a6e49ead2ed5ab"
    assert claim.purl.startswith("pkg:nix/nixpkgs@")
    # narHash is base64 SRI over a store path, not a hex content digest
    assert not claim.hashes
