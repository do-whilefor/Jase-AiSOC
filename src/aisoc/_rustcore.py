"""Rust core bridge with deterministic Python fallbacks.

The production target is Linux. ``aisoc_rust`` accelerates CPU-bound helpers and
owns Linux-native probes when the extension is installed. Python fallbacks keep
control-plane and AI development usable without a Rust build, but callers must
not depend on fallback-only behavior.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import stat
from ipaddress import ip_address
from collections import Counter
from pathlib import Path
from typing import Any

_RUST: Any = None
try:
    import aisoc_rust as _rust  # type: ignore[import-untyped]
except ImportError:
    _rust = None


def rust_available() -> bool:
    return _rust is not None


def sha256_hex(data: bytes) -> str:
    if _rust is not None:
        return str(_rust.sha256_hex(data))
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    if _rust is not None:
        return bytes(_rust.sha256_bytes(data))
    return hashlib.sha256(data).digest()


def hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    if _rust is not None:
        return str(_rust.hmac_sha256_hex(key, msg))
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def secure_compare(a: bytes | str, b: bytes | str) -> bool:
    left = a.encode("utf-8") if isinstance(a, str) else a
    right = b.encode("utf-8") if isinstance(b, str) else b
    if _rust is not None:
        return bool(_rust.secure_compare(left, right))
    return hmac.compare_digest(left, right)


def sha256_file(path: Path, *, max_bytes: int) -> tuple[str, int]:
    """Hash one regular non-symlink file with an explicit size bound."""

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    resolved = path.expanduser()
    if _rust is not None:
        digest, size = _rust.sha256_file(os.fspath(resolved), max_bytes)
        return str(digest), int(size)

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(resolved, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("hash target must be a regular file")
        if metadata.st_size > max_bytes:
            raise ValueError("hash target exceeds the configured size limit")
        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("hash target grew beyond the configured size limit")
            hasher.update(chunk)
        final_metadata = os.fstat(descriptor)
        if (
            final_metadata.st_size != metadata.st_size
            or final_metadata.st_mtime_ns != metadata.st_mtime_ns
            or final_metadata.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise ValueError("hash target changed while it was being read")
        return hasher.hexdigest(), total
    finally:
        os.close(descriptor)


def entropy(data: bytes) -> float:
    if _rust is not None:
        return float(_rust.entropy(data))
    if not data:
        return 0.0
    size = len(data)
    value = -sum((count / size) * math.log2(count / size) for count in Counter(data).values())
    return round(value, 6)


def ascii_strings(
    data: bytes,
    *,
    minimum_length: int,
    max_strings: int,
    max_string_length: int,
) -> tuple[str, ...]:
    if _rust is not None:
        return tuple(
            str(item)
            for item in _rust.ascii_strings(
                data,
                minimum_length,
                max_strings,
                max_string_length,
            )
        )

    results: list[str] = []
    current = bytearray()

    def flush() -> None:
        if len(current) >= minimum_length and len(results) < max_strings:
            results.append(bytes(current[:max_string_length]).decode("ascii"))
        current.clear()

    for byte in data:
        if 0x20 <= byte <= 0x7E:
            if len(current) < max_string_length:
                current.append(byte)
        else:
            flush()
            if len(results) >= max_strings:
                break
    if len(results) < max_strings:
        flush()
    return tuple(results)


def inspect_elf(data: bytes) -> tuple[str | None, str, tuple[str, ...]] | None:
    if _rust is None:
        return None
    result = _rust.inspect_elf(data)
    if result is None:
        return None
    architecture, executable_format, warnings = result
    return (
        str(architecture) if architecture is not None else None,
        str(executable_format),
        tuple(str(item) for item in warnings),
    )


def probe_linux(kernel_release: str, architecture: str) -> dict[str, object] | None:
    if _rust is None:
        return None
    result = _rust.probe_linux(kernel_release, architecture)
    return dict(result)


def _normalize_domain(value: str) -> str:
    normalized = value.strip().rstrip(".").lower()
    if not normalized or len(normalized) > 253 or not normalized.isascii():
        raise ValueError("invalid IOC domain")
    for label in normalized.split("."):
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (character.isalnum() or character == "-") for character in label)
        ):
            raise ValueError("invalid IOC domain")
    return normalized


def _normalize_sha256(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError("invalid IOC SHA-256")
    return normalized


class IocMatcher:
    """Exact deterministic IOC matcher backed by Rust when available."""

    def __init__(
        self,
        *,
        ips: tuple[str, ...] = (),
        domains: tuple[str, ...] = (),
        sha256: tuple[str, ...] = (),
    ) -> None:
        self._native = _rust.IocMatcher(list(ips), list(domains), list(sha256)) if _rust else None
        self._ips = {str(ip_address(value.strip())) for value in ips}
        self._domains = {_normalize_domain(value) for value in domains}
        self._sha256 = {_normalize_sha256(value) for value in sha256}

    def contains_ip(self, value: str) -> bool:
        if self._native is not None:
            return bool(self._native.contains_ip(value))
        try:
            return str(ip_address(value.strip())) in self._ips
        except ValueError:
            return False

    def contains_domain(self, value: str) -> bool:
        if self._native is not None:
            return bool(self._native.contains_domain(value))
        try:
            return _normalize_domain(value) in self._domains
        except ValueError:
            return False

    def contains_sha256(self, value: str) -> bool:
        if self._native is not None:
            return bool(self._native.contains_sha256(value))
        try:
            return _normalize_sha256(value) in self._sha256
        except ValueError:
            return False


__all__ = [
    "ascii_strings",
    "entropy",
    "hmac_sha256_hex",
    "inspect_elf",
    "IocMatcher",
    "probe_linux",
    "rust_available",
    "secure_compare",
    "sha256_bytes",
    "sha256_file",
    "sha256_hex",
]
