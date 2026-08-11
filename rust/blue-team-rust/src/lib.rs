//! Optional Rust-accelerated pure helpers for the Blue Team AI Agent.
//!
//! This crate is compiled to a CPython extension module (`blue_team_rust`) via
//! maturin/PyO3. The Python package always works without it: `blue_team._rusthash`
//! imports this module when available and falls back to the standard-library
//! `hashlib`/`hmac` implementations otherwise. The functions here are pure and
//! must produce byte-identical output to their Python fallbacks (asserted by the
//! test suite) so the extension is a transparent accelerator, not a behavior
//! change.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sha2::{Digest, Sha256};

/// SHA-256 of ``data`` as a lowercase hex string.
///
/// Equivalent to ``hashlib.sha256(data).hexdigest()``.
#[pyfunction]
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// SHA-256 of ``data`` as raw bytes.
///
/// Equivalent to ``hashlib.sha256(data).digest()``.
#[pyfunction]
fn sha256_bytes<'py>(py: Python<'py>, data: &[u8]) -> &'py PyBytes {
    let mut hasher = Sha256::new();
    hasher.update(data);
    PyBytes::new(py, &hasher.finalize())
}

/// HMAC-SHA256 of ``msg`` keyed by ``key`` as a lowercase hex string.
///
/// Equivalent to ``hmac.new(key, msg, hashlib.sha256).hexdigest()``.
#[pyfunction]
fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    // RFC 2104: block size for SHA-256 is 64 bytes; hash the key first if it is
    // longer, then zero-pad to the block size.
    let mut block_key: Vec<u8> = key.to_vec();
    if block_key.len() > 64 {
        let mut h = Sha256::new();
        h.update(&block_key);
        block_key = h.finalize().to_vec();
    }
    block_key.resize(64, 0);
    let mut ipad = vec![0x36u8; 64];
    let mut opad = vec![0x5cu8; 64];
    for (i, b) in block_key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    hex::encode(outer.finalize())
}

/// Build/extension version string for sanity checks.
#[pyfunction]
fn version() -> &'static str {
    "blue-team-rust 0.0.1"
}

/// Constant-time comparison of two byte slices.
///
/// Returns `true` if `a` and `b` have the same length and every byte matches.
/// The comparison time is independent of the contents (but NOT of the length).
/// Equivalent to Python's `secrets.compare_digest(a, b)` but runs entirely in
/// native Rust with no intermediate allocation.
#[pyfunction]
fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[pymodule]
fn blue_team_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(secure_compare, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
