"""Minimal protobuf wire codec for `plugin_v1.proto`.

Only the handful of scalar and length-delimited fields the plugin protocol
uses, so `sorbet[grpc]` needs the `grpcio` transport but no code generation
step and no `protobuf` runtime.
"""

from __future__ import annotations

MAX_MESSAGE_BYTES = 64 * 1024 * 1024


class WireError(ValueError):
    """A plugin sent a malformed protobuf message."""


def _varint(value: int) -> bytes:
    if value < 0:
        raise WireError("negative values are not representable as a varint")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise WireError("truncated varint")
        if shift > 63:
            raise WireError("varint overflows 64 bits")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _tag(field: int, wire_type: int) -> bytes:
    return _varint(field << 3 | wire_type)


def encode_bytes_field(field: int, value: bytes) -> bytes:
    return _tag(field, 2) + _varint(len(value)) + value


def encode_string_field(field: int, value: str) -> bytes:
    return encode_bytes_field(field, value.encode("utf-8"))


def encode_uint_field(field: int, value: int) -> bytes:
    return _tag(field, 0) + _varint(value)


def fields(buf: bytes) -> list[tuple[int, bytes | int]]:
    """Decode a message into (field number, value) pairs.

    Length-delimited fields yield bytes; varints yield ints. Fixed-width and
    group wire types are skipped — the protocol uses neither.
    """
    if len(buf) > MAX_MESSAGE_BYTES:
        raise WireError(f"message exceeds {MAX_MESSAGE_BYTES} bytes")
    out: list[tuple[int, bytes | int]] = []
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        field, wire_type = key >> 3, key & 0x7
        if wire_type == 0:
            value, pos = _read_varint(buf, pos)
            out.append((field, value))
        elif wire_type == 2:
            length, pos = _read_varint(buf, pos)
            if length > len(buf) - pos:
                raise WireError("length-delimited field runs past the message")
            out.append((field, buf[pos : pos + length]))
            pos += length
        elif wire_type in (1, 5):
            pos += 8 if wire_type == 1 else 4
            if pos > len(buf):
                raise WireError("truncated fixed-width field")
        else:
            raise WireError(f"unsupported wire type {wire_type}")
    return out


def first_bytes(buf: bytes, field: int) -> bytes:
    for num, value in fields(buf):
        if num == field and isinstance(value, bytes):
            return value
    return b""


def repeated_strings(buf: bytes, field: int) -> list[str]:
    return [
        value.decode("utf-8", "replace")
        for num, value in fields(buf)
        if num == field and isinstance(value, bytes)
    ]


def encode_analyze_request(path: str, size: int, blob: bytes) -> bytes:
    """`AnalyzeRequest { string path = 1; uint64 size = 2; bytes blob = 3; }`"""
    return (
        encode_string_field(1, path) + encode_uint_field(2, size) + encode_bytes_field(3, blob)
    )


def decode_findings_json(payload: bytes) -> bytes:
    """`FindingsJson { bytes json = 1; }`"""
    return first_bytes(payload, 1)


def decode_globs(payload: bytes) -> list[str]:
    """`Globs { repeated string globs = 1; }`"""
    return repeated_strings(payload, 1)
