"""Signature DB, fingerprint engines (symbols/constants/
functions/sourcetree), negative-corpus precision, and pack install/verify."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sorb.binary.fingerprint import (
    crate_namespace_hints,
    function_hashes,
    match_constants,
    match_functions,
    match_source_tree,
    match_symbols,
)
from sorb.binary.info import BinaryInfo, Section, Symbol
from sorb.binary.packs import build_pack, install_pack
from sorb.binary.sigdb import SignatureDB
from sorb.errors import SubsystemDegraded


def _sigdb(tmp_path: Path) -> SignatureDB:
    db = SignatureDB.create(tmp_path / "sig.db")
    # zlib: constants (CRC table fragment + version string), symbols, functions
    zlib_id = db.add_library("zlib", "1.2.13", "pkg:generic/zlib@1.2.13", "generic")
    db.add_constants(zlib_id, [
        (b"deflate 1.2.13 Copyright", 0.99),
        (b"\x00\x00\x00\x00\x77\x07\x30\x96", 0.85),  # CRC table start
    ])
    db.add_symbols(zlib_id, [f"zlib_sym_{i}" for i in range(20)])
    db.add_functions(zlib_id, [f"{i:024x}" for i in range(40)])
    db.add_sourcefiles(zlib_id, [
        (f"src/file{i}.c", hashlib.sha256(f"zlib-file-{i}".encode()).hexdigest())
        for i in range(44)
    ])
    # openssl: version-string constant
    ossl_id = db.add_library("openssl", "3.0.13", "pkg:generic/openssl@3.0.13", "generic")
    db.add_constants(ossl_id, [(b"OpenSSL 3.0.13 30 Jan 2024", 0.99)])
    db.commit()
    return db


def test_sigdb_roundtrip_and_validation(tmp_path: Path) -> None:
    db = _sigdb(tmp_path)
    db.set_meta("pack_version", "2026.07.10")
    db.commit()
    db.close()
    reopened = SignatureDB.open(tmp_path / "sig.db")
    assert reopened.version == "2026.07.10"
    assert reopened.library(1).name == "zlib"


def test_constants_identify_with_evidence(tmp_path: Path) -> None:
    """OpenSSL-static identified via constants, evidence names
    which constants matched."""
    db = _sigdb(tmp_path)
    blob = b"\x00" * 500 + b"OpenSSL 3.0.13 30 Jan 2024" + b"\x00" * 500
    matches = match_constants(blob, db)
    assert len(matches) == 1
    m = matches[0]
    assert m.name == "openssl" and m.version == "3.0.13"
    assert m.technique == "constants" and m.confidence <= 0.85
    assert any("OpenSSL 3.0.13" in e for e in m.evidence)


def test_symbols_vote_threshold(tmp_path: Path) -> None:
    db = _sigdb(tmp_path)
    # 10 of zlib's 20 known symbols present as exports → clears the ≥8 threshold
    info = BinaryInfo(
        fmt="elf",
        exported_symbols=[Symbol(name=f"zlib_sym_{i}", kind="export") for i in range(10)],
    )
    matches = match_symbols(info, db)
    assert matches and matches[0].name == "zlib"
    assert matches[0].match_ratio == 0.5

    # only 3 symbols → below threshold, no match
    weak = BinaryInfo(fmt="elf", exported_symbols=[Symbol(name=f"zlib_sym_{i}") for i in range(3)])
    assert match_symbols(weak, db) == []


def test_function_shape_reference(tmp_path: Path) -> None:
    """Function-boundary sweep + normalized hashing identifies a static
    lib; below-threshold does not force-match."""
    # a code blob with recognizable prologues and RETs
    def make_fn(seed: int) -> bytes:
        return b"\x55\x48\x89\xe5" + bytes([(seed * 7 + i) % 256 for i in range(20)]) + b"\xc3"

    code = b"".join(make_fn(i) for i in range(30))
    hashes = function_hashes(code)
    assert len(hashes) >= 12  # found the functions

    # seed a sig db with these exact hashes
    db = SignatureDB.create(tmp_path / "fn.db")
    lib_id = db.add_library("mylib", "1.0", "pkg:generic/mylib@1.0", "generic")
    db.add_functions(lib_id, sorted(hashes))
    db.commit()

    info = BinaryInfo(fmt="elf", sections=[Section(name=".text", offset=0, size=len(code))])
    matches = match_functions(code, info, db)
    assert matches and matches[0].name == "mylib"
    assert matches[0].technique == "functions"

    # a blob with too few functions lands nowhere (unidentified, never forced)
    tiny = make_fn(1)
    assert match_functions(tiny, BinaryInfo(fmt="elf"), db) == []


def test_vendored_source_tree_modified_flag(tmp_path: Path) -> None:
    """Patched vendored zlib → correct version + modified flag
    + N/44-style evidence."""
    db = _sigdb(tmp_path)
    # 41 of zlib's 44 files match (3 locally patched)
    file_hashes = {
        f"third_party/zlib/file{i}.c": hashlib.sha256(f"zlib-file-{i}".encode()).hexdigest()
        for i in range(41)
    }
    matches = match_source_tree(file_hashes, db)
    assert matches and matches[0].name == "zlib" and matches[0].version == "1.2.13"
    assert matches[0].modified is True  # 41/44 = partial → patched
    assert matches[0].match_ratio == pytest.approx(41 / 44, abs=0.01)
    assert any("41/44" in e for e in matches[0].evidence)


def test_negative_corpus_zero_false_positives(tmp_path: Path) -> None:
    """A negative corpus (binaries known NOT to contain the
    library) yields zero false identifications."""
    db = _sigdb(tmp_path)
    negatives = [
        b"\x00\x01\x02\x03" * 1000,  # random-ish
        b"just some text, no library constants here" * 50,
        b"OpenSSL is a great project but this string isn't the version marker" * 10,
    ]
    for blob in negatives:
        assert match_constants(blob, db) == [], "no constant should match a negative"


def test_demangle_hints() -> None:
    hints = crate_namespace_hints(["_ZN4core3fmt9Formatter", "_RNvCs_7mycrate4main"])
    assert "core" in hints  # C++ Itanium length-prefixed
    assert "mycrate" in hints  # Rust v0 length-prefixed


# -- pack install / verify -------------------------------------------------------------------


def test_pack_install_requires_signature(tmp_path: Path) -> None:
    from sorb.emit.signing import generate_keypair, sign_detached

    db = SignatureDB.create(tmp_path / "sig.db")
    db.add_library("zlib", "1.2.13", None, "generic")
    db.commit()
    db.close()
    pack = build_pack("signatures", "2026.07.10", {"signatures.db": (tmp_path / "sig.db").read_bytes()})

    packs_dir = tmp_path / "packs"
    # unsigned → refused
    with pytest.raises(SubsystemDegraded, match="unsigned"):
        install_pack(pack, packs_dir=packs_dir)

    # signed → installed, verified
    key, pub = generate_keypair(tmp_path / "keys")
    sig = sign_detached(pack, private_key_pem=key.read_bytes())
    installed = install_pack(
        pack, packs_dir=packs_dir, signature=sig, public_key_pem=pub.read_bytes()
    )
    assert installed.verified and installed.name == "signatures"
    assert (installed.path / "signatures.db").is_file()

    # tampered pack → refused (signature no longer matches). Flip a byte in the
    # payload region (tar header of the first data member, past pack.json).
    idx = pack.find(b"signatures.db")
    tampered = bytearray(pack)
    tampered[idx + 200] ^= 0xFF
    with pytest.raises(SubsystemDegraded, match="verification failed"):
        install_pack(bytes(tampered), packs_dir=packs_dir, signature=sig, public_key_pem=pub.read_bytes())


def test_pack_build_pipeline(tmp_path: Path) -> None:
    """The offline core of the signature-pack build pipeline produces a queryable db."""
    import sys

    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "data-packs" / "signatures"))
    from build import LibraryArtifact, build_signatures_db, emit_pack

    art = LibraryArtifact(
        name="zlib", version="1.2.13", purl="pkg:generic/zlib@1.2.13",
        symbols=["inflate", "deflate", "crc32"],
        constants=[(b"deflate 1.2.13", 0.99)],
    )
    db_path = build_signatures_db([art], tmp_path / "built.db")
    db = SignatureDB.open(db_path)
    assert db.library(1).name == "zlib"
    assert match_constants(b"xx deflate 1.2.13 yy", db)[0].name == "zlib"
    pack = emit_pack(db_path, "2026.07.10")
    assert pack[:8]  # a tar was produced
