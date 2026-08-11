"""Encrypted, non-exportable local storage for untrusted malware samples."""

from __future__ import annotations

import asyncio
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aisoc._rustcore import secure_compare, sha256_hex
from aisoc.errors import AuthorizationError, NotFoundError, SampleIntegrityError
from aisoc.storage._safe_open import open_exclusive_under_root, read_bytes_under_root

_TENANT_ID = re.compile(r"^ten_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_HEX_32 = re.compile(r"^[a-f0-9]{32}$")
_MAGIC = b"BTQ1"
_NONCE_BYTES = 12


@dataclass(frozen=True, slots=True)
class QuarantineMetadata:
    """Internal receipt; ``ref`` must never be exposed by a public API."""

    ref: str
    sha256: str
    size: int
    media_type: str


class QuarantineStore(Protocol):
    async def initialize(self) -> None: ...

    async def ready(self) -> bool: ...

    async def put(
        self,
        tenant_id: str,
        data: bytes,
        *,
        media_type: str,
    ) -> QuarantineMetadata: ...

    async def read_for_scan(self, tenant_id: str, ref: str) -> bytes: ...


class LocalQuarantineStore:
    """AES-GCM quarantine using a key independent from the evidence store.

    The public protocol intentionally has no download/export method. The only
    read operation is named for and injected into the internal scan worker.
    """

    def __init__(self, root: Path, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("quarantine encryption key must contain exactly 32 bytes")
        self._root = root.expanduser().resolve()
        self._cipher = AESGCM(key)

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize_sync)

    def _initialize_sync(self) -> None:
        if self._root.exists() and stat.S_ISLNK(self._root.lstat().st_mode):
            raise ValueError("quarantine root must not be a symbolic link")
        self._root.mkdir(parents=True, exist_ok=True)
        if not self._root.is_dir():
            raise ValueError("quarantine root must be a directory")
        with suppress(OSError):
            self._root.chmod(0o700)

    async def ready(self) -> bool:
        return await asyncio.to_thread(self._ready_sync)

    def _ready_sync(self) -> bool:
        try:
            metadata = self._root.lstat()
        except FileNotFoundError:
            return False
        return (
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and os.access(self._root, os.R_OK | os.W_OK)
        )

    async def put(
        self,
        tenant_id: str,
        data: bytes,
        *,
        media_type: str,
    ) -> QuarantineMetadata:
        self._validate_tenant(tenant_id)
        if not media_type or len(media_type) > 255:
            raise ValueError("media_type must contain between 1 and 255 characters")
        digest = sha256_hex(data)
        object_id = uuid4().hex
        ref = f"quarantine://{tenant_id}/{digest}/{object_id}"
        relative = Path(tenant_id, digest[:2], f"{object_id}.quarantine")
        self._safe_path(relative)  # defense-in-depth escape check
        nonce = os.urandom(_NONCE_BYTES)
        aad = self._aad(tenant_id, digest, object_id)
        encrypted = _MAGIC + nonce + self._cipher.encrypt(nonce, data, aad)
        await asyncio.to_thread(self._write_once, self._root, relative, encrypted)
        return QuarantineMetadata(
            ref=ref,
            sha256=digest,
            size=len(data),
            media_type=media_type,
        )

    async def read_for_scan(self, tenant_id: str, ref: str) -> bytes:
        self._validate_tenant(tenant_id)
        digest, object_id = self._parse_ref(tenant_id, ref)
        relative = Path(tenant_id, digest[:2], f"{object_id}.quarantine")
        self._safe_path(relative)  # defense-in-depth escape check
        try:
            encrypted = await asyncio.to_thread(read_bytes_under_root, self._root, relative)
        except FileNotFoundError as error:
            raise NotFoundError("quarantined sample", ref) from error
        except OSError as error:
            raise SampleIntegrityError(ref) from error
        minimum = len(_MAGIC) + _NONCE_BYTES + 16
        if len(encrypted) < minimum or not secure_compare(encrypted[:4], _MAGIC):
            raise SampleIntegrityError(ref)
        nonce = encrypted[len(_MAGIC) : len(_MAGIC) + _NONCE_BYTES]
        ciphertext = encrypted[len(_MAGIC) + _NONCE_BYTES :]
        try:
            data = self._cipher.decrypt(
                nonce,
                ciphertext,
                self._aad(tenant_id, digest, object_id),
            )
        except InvalidTag as error:
            raise SampleIntegrityError(ref) from error
        if not secure_compare(sha256_hex(data), digest):
            raise SampleIntegrityError(ref)
        return data

    def _parse_ref(self, tenant_id: str, ref: str) -> tuple[str, str]:
        parsed = urlsplit(ref)
        if parsed.scheme != "quarantine" or parsed.netloc != tenant_id:
            raise AuthorizationError("quarantine reference is outside the tenant scope")
        if parsed.query or parsed.fragment:
            raise NotFoundError("quarantined sample", ref)
        parts = parsed.path.strip("/").split("/")
        if len(parts) != 2:
            raise NotFoundError("quarantined sample", ref)
        digest, object_id = parts
        if _HEX_64.fullmatch(digest) is None or _HEX_32.fullmatch(object_id) is None:
            raise NotFoundError("quarantined sample", ref)
        return digest, object_id

    def _safe_path(self, relative: Path) -> Path:
        destination = (self._root / relative).resolve()
        if not destination.is_relative_to(self._root):
            raise AuthorizationError("quarantine path escaped the configured store")
        return destination

    @staticmethod
    def _validate_tenant(tenant_id: str) -> None:
        if _TENANT_ID.fullmatch(tenant_id) is None:
            raise ValueError("invalid tenant identifier")

    @staticmethod
    def _aad(tenant_id: str, digest: str, object_id: str) -> bytes:
        return b"\0".join((_MAGIC, tenant_id.encode(), digest.encode(), object_id.encode()))

    @staticmethod
    def _write_once(root: Path, relative: Path, data: bytes) -> None:
        with open_exclusive_under_root(root, relative) as output:
            output.write(data)


__all__ = ["LocalQuarantineStore", "QuarantineMetadata", "QuarantineStore"]
