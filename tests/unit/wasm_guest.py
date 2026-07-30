"""Build ABI-v1 WASM plugin guests for the host-bridge tests.

The guest is generated from the payload it should return so the data-section
offsets and lengths can never drift out of sync with it.
"""

from __future__ import annotations

GLOBS_ADDR = 16
PAYLOAD_ADDR = 1024
HEAP_ADDR = 65536


def _escape(data: bytes) -> str:
    out = []
    for byte in data:
        char = chr(byte)
        if char in '"\\':
            out.append("\\" + char)
        elif 0x20 <= byte < 0x7F:
            out.append(char)
        else:
            out.append(f"\\{byte:02x}")
    return "".join(out)


def guest_wat(
    globs: str = "*.acme\n",
    payload: bytes = b"{}",
    abi_version: int = 1,
    exports: tuple[str, ...] = (
        "memory",
        "sorb_abi_version",
        "sorb_alloc",
        "sorb_matcher_globs",
        "sorb_analyze",
    ),
    claim_len: int | None = None,
) -> str:
    """A guest that reports `globs` and returns `payload` from every analyze.

    `exports` lets a test omit one to check the host's ABI-conformance error;
    `claim_len` lets it lie about the returned length.
    """
    glob_bytes = globs.encode()
    reported = len(payload) if claim_len is None else claim_len

    def maybe(name: str, text: str) -> str:
        return text if name in exports else ""

    def export(name: str) -> str:
        return f'(export "{name}") ' if name in exports else ""

    return f"""
(module
  (memory {export("memory")} 4)
  (data (i32.const {GLOBS_ADDR}) "{_escape(glob_bytes)}")
  (data (i32.const {PAYLOAD_ADDR}) "{_escape(payload)}")
  (global $next (mut i32) (i32.const {HEAP_ADDR}))
  {maybe("sorb_abi_version", f'''
  (func (export "sorb_abi_version") (result i32) i32.const {abi_version})''')}
  {maybe("sorb_alloc", '''
  (func (export "sorb_alloc") (param $size i32) (result i32)
    (local $ptr i32)
    global.get $next
    local.set $ptr
    global.get $next
    local.get $size
    i32.add
    global.set $next
    local.get $ptr)''')}
  {maybe("sorb_matcher_globs", f'''
  (func (export "sorb_matcher_globs") (result i64)
    i64.const {GLOBS_ADDR}
    i64.const 32
    i64.shl
    i64.const {len(glob_bytes)}
    i64.or)''')}
  {maybe("sorb_analyze", f'''
  (func (export "sorb_analyze")
        (param $meta_ptr i32) (param $meta_len i32)
        (param $blob_ptr i32) (param $blob_len i32) (result i64)
    i64.const {PAYLOAD_ADDR}
    i64.const 32
    i64.shl
    i64.const {reported}
    i64.or)''')}
)
"""


def trapping_guest_wat() -> str:
    """A guest whose analyze traps — the host must contain it as a gap."""
    return """
(module
  (memory (export "memory") 1)
  (data (i32.const 16) "*\\n")
  (func (export "sorb_abi_version") (result i32) i32.const 1)
  (func (export "sorb_alloc") (param i32) (result i32) i32.const 65536)
  (func (export "sorb_matcher_globs") (result i64)
    i64.const 16 i64.const 32 i64.shl i64.const 2 i64.or)
  (func (export "sorb_analyze")
        (param i32) (param i32) (param i32) (param i32) (result i64)
    unreachable)
)
"""


def wat_to_wasm(wat: str) -> bytes:
    import wasmtime

    return bytes(wasmtime.wat2wasm(wat))
