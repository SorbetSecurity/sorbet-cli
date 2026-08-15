"""ML-BOM — model & dataset catalogers.

Header parsers for the four dominant model formats — safetensors, GGUF, ONNX,
TorchScript/pickle — recovering architecture and tensor metadata without loading
(let alone executing) the model. Pickle-bearing formats (`.pt`/`.pth`/`.pkl` and
torch zips) get a **deserialization-risk annotation**: loading them runs
arbitrary code, which a BOM must surface. Hugging Face cache paths
(`…/models--org--name/snapshots/<rev>/…`) yield exact repo+revision identity.
Emitted as CycloneDX `machine-learning-model` components (`sorb.emit.cyclonedx`).
"""

from __future__ import annotations

import json
import re
import struct
from collections.abc import Iterable

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.model import Annotation, ComponentClaim, Finding, Tier
from sorb.source.base import Entry

_HF_RE = re.compile(r"models--([^/]+?)--([^/]+?)/snapshots/([^/]+)/")
_PICKLE_MAGIC = b"\x80"  # pickle protocol 2+ opcode PROTO
_ZIP_MAGIC = b"PK\x03\x04"


class ModelCataloger(Cataloger):
    id = "ml/model"
    version = 1
    matchers = [
        Matcher(glob="*.safetensors"), Matcher(glob="*.gguf"), Matcher(glob="*.onnx"),
        Matcher(glob="*.pt"), Matcher(glob="*.pth"), Matcher(glob="*.pkl"),
        Matcher(glob="*.ckpt"),
    ]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        name = entry.path.rsplit("/", 1)[-1]
        lower = name.lower()
        info: dict[str, str] = {}
        risk = False
        if lower.endswith(".safetensors"):
            info = _safetensors(blob)
            fmt = "safetensors"
        elif lower.endswith(".gguf") or blob[:4] == b"GGUF":
            info = _gguf(blob)
            fmt = "gguf"
        elif lower.endswith(".onnx"):
            info = _onnx(blob)
            fmt = "onnx"
        elif lower.endswith((".pt", ".pth", ".pkl", ".ckpt")):
            fmt = "torchscript" if blob[:4] == _ZIP_MAGIC else "pickle"
            risk = blob[:4] == _ZIP_MAGIC or blob[:1] == _PICKLE_MAGIC
        else:
            return

        hf = _HF_RE.search(entry.path)
        attrs: list[tuple[str, str]] = [("model_format", fmt), ("kind", "ml-model")]
        for k, v in info.items():
            attrs.append((k, v))
        display = name
        version = None
        if hf:
            org, repo, rev = hf.group(1), hf.group(2), hf.group(3)
            display = f"{org}/{repo}"
            version = rev
            attrs += [("hf_repo", f"{org}/{repo}"), ("hf_revision", rev)]
        if risk:
            attrs.append(("pickle_risk", "true"))

        annotations: tuple[Annotation, ...] = ()
        if risk:
            annotations = (Annotation(
                code="ml-pickle-risk", subject=f"file:{entry.path}",
                detail="pickle-bearing model — loading executes arbitrary code",
            ),)
        yield Finding(
            claim=ComponentClaim(
                ctype="machine-learning-model", name=display, version=version,
                ecosystem="ml", attrs=tuple(attrs),
            ),
            evidence=(
                ctx.evidence("installed-state", Tier.INSTALLED, entry,
                             captured=f"{fmt} model" + (f" ({info.get('architecture')})"
                                                        if info.get("architecture") else "")),
            ),
            annotations=annotations,
        )


def _safetensors(blob: bytes) -> dict[str, str]:
    try:
        n = int.from_bytes(blob[:8], "little")
        if n <= 0 or n > len(blob):
            return {}
        header = json.loads(blob[8:8 + n])
        meta = header.get("__metadata__", {}) if isinstance(header, dict) else {}
        tensors = [k for k in header if k != "__metadata__"]
        out = {"tensor_count": str(len(tensors))}
        arch = meta.get("architecture") or meta.get("model_type") or meta.get("format")
        if arch:
            out["architecture"] = str(arch)
        return out
    except (ValueError, json.JSONDecodeError):
        return {}


def _gguf(blob: bytes) -> dict[str, str]:
    try:
        if blob[:4] != b"GGUF":
            return {}
        tensor_count = struct.unpack_from("<Q", blob, 8)[0]
        kv_count = struct.unpack_from("<Q", blob, 16)[0]
        out = {"tensor_count": str(tensor_count)}
        pos = 24
        wanted = {"general.architecture": "architecture", "general.name": "model_name"}
        for _ in range(min(kv_count, 4096)):
            key, pos = _gguf_string(blob, pos)
            vtype = struct.unpack_from("<I", blob, pos)[0]
            pos += 4
            value, pos = _gguf_value(blob, pos, vtype)
            if key in wanted and isinstance(value, str):
                out[wanted[key]] = value
            if pos >= len(blob):
                break
        return out
    except (struct.error, IndexError):
        return {}


def _gguf_string(blob: bytes, pos: int) -> tuple[str, int]:
    n = struct.unpack_from("<Q", blob, pos)[0]
    s = blob[pos + 8:pos + 8 + n].decode("utf-8", "replace")
    return s, pos + 8 + n


# GGUF value type ids → (struct fmt, size); 8 = string, 9 = array (skipped)
_GGUF_SCALAR = {0: ("B", 1), 1: ("b", 1), 2: ("H", 2), 3: ("h", 2), 4: ("I", 4),
                5: ("i", 4), 6: ("f", 4), 7: ("?", 1), 10: ("Q", 8), 11: ("q", 8),
                12: ("d", 8)}


def _gguf_value(blob: bytes, pos: int, vtype: int) -> tuple[object, int]:
    if vtype == 8:  # string
        return _gguf_string(blob, pos)
    if vtype in _GGUF_SCALAR:
        fmt, size = _GGUF_SCALAR[vtype]
        val = struct.unpack_from("<" + fmt, blob, pos)[0]
        return val, pos + size
    if vtype == 9:  # array: elem_type(u32) + count(u64) + elems — skip its bytes
        elem_type = struct.unpack_from("<I", blob, pos)[0]
        count = struct.unpack_from("<Q", blob, pos + 4)[0]
        pos += 12
        for _ in range(count):
            _, pos = _gguf_value(blob, pos, elem_type)
        return None, pos
    return None, pos  # unknown → stop cleanly


def _onnx(blob: bytes) -> dict[str, str]:
    """Best-effort ONNX (protobuf ModelProto): pull producer_name / version."""
    out: dict[str, str] = {"format": "onnx"}
    # field 2 (producer_name, string): tag 0x12; field 3 (producer_version): 0x1a
    for tag, key in ((b"\x12", "producer"), (b"\x1a", "producer_version")):
        i = blob.find(tag)
        if 0 <= i < 4096:
            length = blob[i + 1]
            val = blob[i + 2:i + 2 + length]
            if val.isascii():
                out[key] = val.decode("ascii", "replace")
    return out


register(ModelCataloger())
