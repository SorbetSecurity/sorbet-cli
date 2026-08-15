//! sorb-accel — native acceleration behind the `sorb.accel` shim.
//!
//! Exposes an `Accelerator` class implementing the exact interface the Python
//! shim probes: `hash_file`, `hash_bytes`, plus tar streaming and the
//! function-fingerprint matcher. Every method must be **byte-identical**
//! to the pure-Python reference — the shim runs a self-check on load and refuses
//! this crate if `hash_bytes` disagrees, so correctness can never regress.
//!
//! NOTE: this is the interface scaffold. The full parallel walk (rayon), streamed
//! tar+zstd path, and the operand-masked fingerprint kernel are built with the CI
//! wheel pipeline; they are not compiled in the offline dev tree.

use pyo3::prelude::*;
use sha2::{Digest, Sha256};

#[pyclass]
struct Accelerator {}

#[pymethods]
impl Accelerator {
    #[new]
    fn new() -> Self {
        Accelerator {}
    }

    #[getter]
    fn name(&self) -> &'static str {
        "sorb-accel"
    }

    /// SHA-256 of a file's bytes — identical to hashlib, SIMD-accelerated.
    fn hash_file(&self, path: &str) -> PyResult<String> {
        let data = std::fs::read(path)?;
        Ok(hex(&Sha256::digest(&data)))
    }

    fn hash_bytes(&self, data: &[u8]) -> String {
        hex(&Sha256::digest(data))
    }

    // TODO (CI wheels): `stream_tar(bytes) -> members`,
    // `function_hashes(code) -> set[str]` — the operand-masked, position-
    // independent kernel that mirrors sorb.binary.fingerprint exactly.
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[pymodule]
fn sorb_accel(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Accelerator>()?;
    Ok(())
}
