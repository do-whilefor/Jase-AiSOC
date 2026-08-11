"""Optional Rust-accelerated hashing with a hashlib/hmac fallback.

The Rust extension :mod:`blue_team_rust` is built from ``rust/blue-team-rust`` with
maturin/PyO3. It is an *optional accelerator*: when the compiled extension is
importable these helpers delegate to it; otherwise they fall back to the
standard-library ``hashlib``/``hmac`` implementations, producing byte-identical
output (asserted by ``tests/unit/test_rust_hash.py``). No call site may depend on
the extension being present -- the fallback is the correctness baseline.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

_RUST: Any = None
try:
    import blue_team_rust as _rust  # type: ignore[import-untyped]
except ImportError:
    _rust = None


def rust_available() -> bool:
    """Return whether the compiled ``blue_team_rust`` extension is importable."""

    return _rust is not None


def sha256_hex(data: bytes) -> str:
    """SHA-256 of ``data`` as a lowercase hex string (== ``hashlib``)."""

    if _rust is not None:
        return str(_rust.sha256_hex(data))
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """SHA-256 of ``data`` as raw bytes (== ``hashlib.sha256(...).digest()``)."""

    if _rust is not None:
        return bytes(_rust.sha256_bytes(data))
    return hashlib.sha256(data).digest()


def hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    """HMAC-SHA256 of ``msg`` keyed by ``key`` as hex (== ``hmac.new(...).hexdigest()``)."""

    if _rust is not None:
        return str(_rust.hmac_sha256_hex(key, msg))
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def secure_compare(a: bytes | str, b: bytes | str) -> bool:
    """Constant-time comparison of two byte strings (== ``secrets.compare_digest``).

    Delegates to the Rust accelerator when available; otherwise uses
    ``hmac.compare_digest``. Returns ``True`` only when both arguments have the
    same length and every byte matches. ``str`` arguments are encoded as UTF-8.
    """

    left = a.encode("utf-8") if isinstance(a, str) else a
    right = b.encode("utf-8") if isinstance(b, str) else b
    if _rust is not None:
        return bool(_rust.secure_compare(left, right))
    return hmac.compare_digest(left, right)
