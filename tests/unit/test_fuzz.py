"""Fuzzing harness: every parser family contains pathological inputs,
and a known-edge-case regression corpus runs green."""

from __future__ import annotations

import pytest

from sorb.fuzz import FUZZ_TARGETS, Crash, run_once, seed_corpus, smoke_fuzz


def test_every_parser_family_has_a_target() -> None:
    # the families we ship parsers for all have fuzz targets
    expected = {"binary", "regf", "fat", "rpm-header", "hcl", "tar",
                "safetensors", "gguf", "certificate", "dpkg", "partition"}
    assert expected <= set(FUZZ_TARGETS)


@pytest.mark.parametrize("target", sorted(FUZZ_TARGETS))
def test_smoke_fuzz_contains_pathological_input(target: str) -> None:
    seeds = seed_corpus().get(target, [b""])
    crashes = smoke_fuzz(target, seeds, iterations=150)
    assert not crashes, f"{target} failed containment: {[c.kind for c in crashes][:5]}"


def test_known_edge_case_regression_corpus() -> None:
    """A curated corpus of inputs that must never crash a parser (regression)."""
    import struct

    corpus: dict[str, list[bytes]] = {
        "safetensors": [struct.pack("<Q", 2**63) + b"{}", b"\x00" * 8, struct.pack("<Q", 4) + b"{"],
        "gguf": [b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 2**40) + struct.pack("<Q", 2**40)],
        "regf": [b"regf" + b"\xff" * 4092, b"regf"],
        "fat": [b"\xeb\x3c\x90" + b"\x00" * 509 + b"\x55\xaa"],  # zero BPB
        "partition": [b"\x00" * 508 + b"\xee\x55\xaa"],  # GPT-protective, no header
        "tar": [b"\x00" * 1024, b"garbage-not-a-tar"],
        "binary": [b"\x7fELF" + b"\xff" * 60, b"MZ" + b"\xff" * 200],
        "hcl": ["{" * 200, "a = " * 100],  # deeply nested-ish / repetitive
    }
    failures: list[Crash] = []
    for target, inputs in corpus.items():
        for data in inputs:
            raw = data.encode() if isinstance(data, str) else data
            crash = run_once(target, raw)
            if crash is not None:
                failures.append(crash)
    assert not failures, f"regression corpus crashed: {failures}"


def test_seed_corpus_seeds_are_well_formed() -> None:
    # the seeds themselves must parse cleanly (reach real code, not just error out)
    for target, seeds in seed_corpus().items():
        for seed in seeds:
            assert run_once(target, seed) is None, f"{target} crashed on its own seed"
