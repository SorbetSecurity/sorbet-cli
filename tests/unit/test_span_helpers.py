"""Line-span helpers: correct offsets, and cost that does not grow per call.

Catalogers call these once per finding, so a per-call rescan of the file makes
a large lockfile quadratic.
"""

from __future__ import annotations

from sorb.catalogers import base as cat_base
from sorb.catalogers.base import find_span, snippet_at

TEXT = "alpha\nbeta\ngamma\ndelta\n"


def test_find_span_reports_one_based_lines() -> None:
    assert find_span(TEXT, "alpha") == (1, 1)
    assert find_span(TEXT, "beta") == (2, 2)
    assert find_span(TEXT, "delta") == (4, 4)
    assert find_span(TEXT, "absent") is None


def test_find_span_handles_edges() -> None:
    assert find_span("only-one-line", "only") == (1, 1)
    assert find_span("", "x") is None
    # a token spanning the newline still reports the line it starts on
    assert find_span(TEXT, "beta\ngamma") == (2, 2)


def test_snippet_at_returns_the_line_with_context() -> None:
    assert snippet_at(TEXT, "gamma") == "gamma"
    assert snippet_at(TEXT, "gamma", context=1) == "beta\ngamma\ndelta"
    assert snippet_at(TEXT, "alpha", context=2) == "alpha\nbeta\ngamma"
    assert snippet_at(TEXT, "absent") is None


def test_alternating_texts_never_cross_contaminate() -> None:
    """The offset memo must key on the text it was built from."""
    a = "\n".join(f"a{i}" for i in range(50))
    b = "x\n" * 10 + "target"
    for _ in range(5):
        assert find_span(a, "a49") == (50, 50)
        assert find_span(b, "target") == (11, 11)


def test_repeated_lookups_build_the_line_index_once(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """1000 lookups in one file must not cost 1000 scans of it.

    Counting index builds rather than elapsed time keeps this immune to how
    loaded the machine is, while still failing a per-call rescan.
    """
    big = "\n".join(f'  "package-{i}": {{"version": "1.0.{i}"}},' for i in range(20_000))
    tokens = [f"package-{i}" for i in range(0, 20_000, 20)]

    builds = 0
    real_index = cat_base._LineIndex

    class Counting(real_index):  # type: ignore[misc, valid-type]
        def __init__(self, text: str) -> None:
            nonlocal builds
            builds += 1
            super().__init__(text)

    monkeypatch.setattr(cat_base, "_LineIndex", Counting)
    monkeypatch.setattr(cat_base, "_last_index", None)
    for token in tokens:
        assert find_span(big, token) is not None
    assert builds == 1, f"{len(tokens)} lookups rebuilt the index {builds} times"


# -- dispatch: the indexed fast path must agree with plain matching ----------------------


def _reference_dispatch(entry):  # type: ignore[no-untyped-def]
    """Dispatch by testing every matcher directly, with no index."""
    from sorb.catalogers.base import registered

    return [c for c in registered() if any(m.matches(entry) for m in c.matchers)]


def test_dispatch_index_agrees_with_direct_matching() -> None:
    """The exact-name and extension tables must not change which catalogers run."""
    from sorb.catalogers.base import dispatch
    from sorb.source.base import Entry

    names = [
        "package.json", "package-lock.json", "go.mod", "Cargo.toml", "pom.xml",
        "requirements.txt", "Gemfile.lock", "composer.lock", "x.pem", "a.dll",
        "c.jar", "d.apk", "f.wasm", "libssl.so.3", "status", "METADATA",
        "Dockerfile", "main.tf", "model.safetensors", "README.md", "noext",
        "archive.tar.gz", ".gitignore", "app.csproj",
        # multi-segment suffixes: the last extension is not the whole pattern
        "myapp.deps.json", "project.assets.json", "lib.so.1.2.3", "a.tar.zst",
    ]
    dirs = ["", "src/", "node_modules/foo/", "var/lib/dpkg/", "a/b/c/"]
    magics = [b"", b"MZ\x90\x00", b"PK\x03\x04", b"\x7fELF", b"\xfe\xed\xfe\xed", b"\x00asm"]
    for d in dirs:
        for n in names:
            for magic in magics:
                entry = Entry(path=d + n, size=100, sniff=magic)
                assert [c.id for c in dispatch(entry)] == [
                    c.id for c in _reference_dispatch(entry)
                ], f"dispatch disagreed for {entry.path!r} magic={magic!r}"


def test_dispatch_rebuilds_its_index_when_a_cataloger_registers() -> None:
    from sorb.catalogers.base import Cataloger, Matcher, dispatch, register, registered
    from sorb.source.base import Entry

    entry = Entry(path="late.acme", size=1, sniff=b"")
    before = [c.id for c in dispatch(entry)]

    class Late(Cataloger):
        id = "test/late-registration"
        version = 1
        matchers = [Matcher(basename="*.acme")]

        def parse(self, ctx, entry, blob):  # type: ignore[no-untyped-def]
            return ()

    registry = registered()
    try:
        register(Late())
        assert "test/late-registration" in [c.id for c in dispatch(entry)]
    finally:
        from sorb.catalogers import base as cat_base

        cat_base._REGISTRY[:] = registry
        cat_base._index = None
    assert [c.id for c in dispatch(entry)] == before
