"""Tests for the optional Rust-accelerated hashing wrapper.

These pass whether or not the compiled ``aisoc_rust`` extension is built:
the wrapper must always match the standard-library ``hashlib``/``hmac`` output.
When the extension is present (``rust_available()`` is true) the assertions
exercise the Rust path; otherwise they exercise the fallback.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from aisoc import _rustcore

_CASES = [
    b"",
    b"abc",
    b"The quick brown fox jumps over the lazy dog",
    bytes(range(256)),
    "中文/utf8 细枝末节".encode(),
    b"\x00" * 64,
]


@pytest.mark.parametrize("data", _CASES, ids=lambda v: f"len{len(v)}")
def test_sha256_hex_matches_hashlib(data: bytes) -> None:
    assert _rustcore.sha256_hex(data) == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("data", _CASES, ids=lambda v: f"len{len(v)}")
def test_sha256_bytes_matches_hashlib(data: bytes) -> None:
    assert _rustcore.sha256_bytes(data) == hashlib.sha256(data).digest()


@pytest.mark.parametrize(
    ("key", "msg"),
    [
        (b"", b""),
        (b"key", b"msg"),
        (b"k" * 80, b"m" * 100),
        (bytes(range(32)), b"x" * 1000),
    ],
)
def test_hmac_sha256_hex_matches_hmac(key: bytes, msg: bytes) -> None:
    assert _rustcore.hmac_sha256_hex(key, msg) == hmac.new(key, msg, hashlib.sha256).hexdigest()


def test_rust_available_reflects_extension_import() -> None:
    # When the extension is built and importable, the wrapper reports it.
    import importlib

    ext_importable = importlib.util.find_spec("aisoc_rust") is not None
    assert _rustcore.rust_available() is ext_importable


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (b"abc", b"abc", True),
        (b"abc", b"abd", False),
        (b"abc", b"abcd", False),
        (b"", b"", True),
        (b"x", b"y", False),
        (b"\x00" * 32, b"\x00" * 32, True),
        (b"\x00" * 32, b"\x01" * 32, False),
    ],
)
def test_secure_compare_bytes(a: bytes, b: bytes, expected: bool) -> None:
    assert _rustcore.secure_compare(a, b) is expected


def test_secure_compare_str_matches_bytes() -> None:
    assert _rustcore.secure_compare("hello", "hello") is True
    assert _rustcore.secure_compare("hello", "world") is False


def test_secure_compare_matches_secrets() -> None:
    import secrets

    for a, b in [(b"abc", b"abc"), (b"abc", b"abd"), (b"", b"x")]:
        assert _rustcore.secure_compare(a, b) == secrets.compare_digest(a, b)
