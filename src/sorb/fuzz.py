"""Fuzzing harness.

Every byte-parser family gets a target: the ELF/PE/Mach-O/WASM adapters, tar/zip,
the registry hive, rpm headers, HCL, FAT, the model-format headers, and the
lockfile/DB stanza parsers. Under `atheris` (when installed) these run as coverage-
guided fuzz targets; here — offline, deterministic — a pure-Python `smoke_fuzz`
mutates seed corpora and asserts the containment contract: **a pathological
file degrades one finding, never the scan**. A parser may raise (the pipeline
catches it), but it must not stack-overflow (`RecursionError`), exhaust memory,
or hang — those are the findings this harness exists to catch.
"""

from __future__ import annotations

import io
import struct
import tarfile
import time
from collections.abc import Callable
from dataclasses import dataclass

FuzzTarget = Callable[[bytes], object]

# per-input soft budget; a parser taking longer on tiny input suggests a hang/DoS.
_TIME_BUDGET_S = 2.0


# -- targets (each runs one parser on raw bytes) -----------------------------------------


def _t_binary(data: bytes) -> object:
    from sorb.binary.formats import parse_binary

    return parse_binary(data)


def _t_regf(data: bytes) -> object:
    from sorb.host.regf import Hive

    hive = Hive(data)  # raises ValueError on bad magic (contained)
    return list(hive.root().subkeys())


def _t_fat(data: bytes) -> object:
    from sorb.source.fatfs import FatFs, looks_like_fat

    if not looks_like_fat(data):
        return None
    return list(FatFs(data).iter_files())


def _t_rpm_header(data: bytes) -> object:
    from sorb.catalogers.os_rpm import parse_header_blob

    return parse_header_blob(data)


def _t_hcl(data: bytes) -> object:
    from sorb.iac.hcl import parse_hcl

    return parse_hcl(data.decode("utf-8", "replace"))


def _t_tar(data: bytes) -> object:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        return tf.getmembers()


def _t_safetensors(data: bytes) -> object:
    from sorb.catalogers.mlbom import _safetensors

    return _safetensors(data)


def _t_gguf(data: bytes) -> object:
    from sorb.catalogers.mlbom import _gguf

    return _gguf(data)


def _t_certificate(data: bytes) -> object:
    from sorb.catalogers.cbom import _extract

    return _extract("f.pem", data)


def _t_dpkg(data: bytes) -> object:
    from sorb.catalogers.os_pkgs import _parse_stanzas

    return list(_parse_stanzas(data.decode("utf-8", "replace")))


def _t_partition(data: bytes) -> object:
    from sorb.source.diskimage import parse_partitions

    return parse_partitions(data)


FUZZ_TARGETS: dict[str, FuzzTarget] = {
    "binary": _t_binary, "regf": _t_regf, "fat": _t_fat, "rpm-header": _t_rpm_header,
    "hcl": _t_hcl, "tar": _t_tar, "safetensors": _t_safetensors, "gguf": _t_gguf,
    "certificate": _t_certificate, "dpkg": _t_dpkg, "partition": _t_partition,
}


# -- robustness result -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Crash:
    target: str
    kind: str  # "recursion" | "memory" | "hang" | "uncontained"
    detail: str
    input_len: int


def run_once(target: str, data: bytes) -> Crash | None:
    """Run one input through a target. Returns a Crash on a containment failure,
    else None. Ordinary parse exceptions are *contained* (the pipeline catches
    them) and are not crashes."""
    fn = FUZZ_TARGETS[target]
    t0 = time.perf_counter()
    try:
        fn(data)
    except RecursionError as e:
        return Crash(target, "recursion", repr(e), len(data))
    except MemoryError as e:  # pragma: no cover - rare
        return Crash(target, "memory", repr(e), len(data))
    except (SystemExit, KeyboardInterrupt) as e:  # pragma: no cover
        return Crash(target, "uncontained", repr(e), len(data))
    except Exception:
        pass  # a normal, contained parse failure — R4 satisfied
    if time.perf_counter() - t0 > _TIME_BUDGET_S:
        return Crash(target, "hang", f">{_TIME_BUDGET_S}s on {len(data)}B", len(data))
    return None


# -- deterministic mutation (no external RNG dependency) ---------------------------------


def _lcg(seed: int):  # type: ignore[no-untyped-def]
    state = seed & 0xFFFFFFFF
    while True:
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        yield state


def mutate(seed: bytes, rng, n: int = 8) -> bytes:  # type: ignore[no-untyped-def]
    """A handful of byte-level mutations: flips, truncation, growth, zeroing."""
    if not seed:
        return bytes(next(rng) % 256 for _ in range(next(rng) % 64))
    buf = bytearray(seed)
    for _ in range(n):
        op = next(rng) % 4
        pos = next(rng) % len(buf)
        if op == 0:  # bit flip
            buf[pos] ^= 1 << (next(rng) % 8)
        elif op == 1:  # random byte
            buf[pos] = next(rng) % 256
        elif op == 2:  # truncate
            buf = buf[: max(0, pos)]
            if not buf:
                buf = bytearray(b"\x00")
        else:  # duplicate a chunk (grow)
            buf[pos:pos] = buf[pos : pos + 4]
    return bytes(buf)


def smoke_fuzz(target: str, seeds: list[bytes], *, iterations: int = 200, seed: int = 1234) -> list[Crash]:
    """Mutate seeds and run them through `target`; return containment failures."""
    rng = _lcg(seed)
    crashes: list[Crash] = []
    inputs = [b"", b"\x00", b"\xff" * 8, *seeds]
    for _ in range(iterations):
        base = seeds[next(rng) % len(seeds)] if seeds else b""
        inputs.append(mutate(base, rng))
    for data in inputs:
        crash = run_once(target, data)
        if crash is not None:
            crashes.append(crash)
    return crashes


def seed_corpus() -> dict[str, list[bytes]]:
    """Minimal valid-ish seeds per family (enough to reach real parse paths)."""
    return {
        "binary": [b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 60, b"MZ" + b"\x00" * 64,
                   b"\xca\xfe\xba\xbe" + b"\x00" * 32, b"\x00asm\x01\x00\x00\x00"],
        "regf": [b"regf" + b"\x00" * 4092],
        "fat": [_fat_seed()],
        "rpm-header": [b"\x8e\xad\xe8\x01" + b"\x00" * 60],
        "hcl": [b'resource "x" "y" {\n  a = 1\n}\n', b"# comment\n"],
        "tar": [_tar_seed()],
        "safetensors": [struct.pack("<Q", 2) + b"{}"],
        "gguf": [b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 0)],
        "certificate": [b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"],
        "dpkg": [b"Package: x\nVersion: 1\nStatus: install ok installed\n\n"],
        "partition": [b"\x00" * 510 + b"\x55\xaa"],
    }


def _tar_seed() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("f")
        info.size = 3
        tf.addfile(info, io.BytesIO(b"abc"))
    return buf.getvalue()


def _fat_seed() -> bytes:
    img = bytearray(512 * 64)
    struct.pack_into("<H", img, 0x0B, 512)
    img[0x0D] = 1
    struct.pack_into("<H", img, 0x0E, 1)
    img[0x10] = 1
    struct.pack_into("<H", img, 0x11, 16)
    struct.pack_into("<H", img, 0x13, 64)
    struct.pack_into("<H", img, 0x16, 1)
    img[0x36:0x3B] = b"FAT16"
    img[510:512] = b"\x55\xaa"
    return bytes(img)


# -- atheris entry (only when the runtime is installed) ----------------------------------


def atheris_main(target: str) -> None:  # pragma: no cover - needs atheris
    import atheris

    fn = FUZZ_TARGETS[target]

    def one_input(data: bytes) -> None:
        try:
            fn(data)
        except Exception:  # noqa: BLE001 - contained; atheris flags only real crashes
            pass

    atheris.Setup([f"sorb-fuzz-{target}"], one_input)
    atheris.Fuzz()
