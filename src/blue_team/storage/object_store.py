"""Immutable, tenant-bound local object storage adapter for the Base profile."""

from __future__ import annotations

import asyncio
import os
import re
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from blue_team._rusthash import secure_compare, sha256_hex
from blue_team.errors import AuthorizationError, EvidenceIntegrityError, NotFoundError
from blue_team.storage._safe_open import open_exclusive_under_root

_TENANT_ID = re.compile(r"^ten_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")


@dataclass(frozen=True, slots=True)
class ObjectMetadata:
    ref: str
    sha256: str
    size: int
    media_type: str


class ObjectStore(Protocol):
    async def initialize(self) -> None: ...

    async def ready(self) -> bool: ...

    async def put(self, tenant_id: str, data: bytes, *, media_type: str) -> ObjectMetadata: ...

    async def get(self, tenant_id: str, ref: str) -> bytes: ...


class LocalObjectStore:
    def __init__(self, root: Path) -> None:
        self._root = root.expanduser().resolve()

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize_sync)

    def _initialize_sync(self) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            self._root.chmod(0o700)

    async def ready(self) -> bool:
        return await asyncio.to_thread(
            lambda: self._root.is_dir() and os.access(self._root, os.R_OK | os.W_OK)
        )

    async def put(self, tenant_id: str, data: bytes, *, media_type: str) -> ObjectMetadata:
        self._validate_tenant(tenant_id)
        if not media_type or len(media_type) > 255:
            raise ValueError("media_type must contain between 1 and 255 characters")
        digest = sha256_hex(data)
        object_id = uuid4().hex
        relative = Path(tenant_id, digest[:2], f"{object_id}.evidence")
        self._safe_path(relative)  # defense-in-depth escape check
        await asyncio.to_thread(self._write_once, self._root, relative, data)
        return ObjectMetadata(
            ref=f"evidence://{tenant_id}/{digest}/{object_id}",
            sha256=digest,
            size=len(data),
            media_type=media_type,
        )

    async def get(self, tenant_id: str, ref: str) -> bytes:
        self._validate_tenant(tenant_id)
        parsed = urlsplit(ref)
        if parsed.scheme != "evidence" or parsed.netloc != tenant_id:
            raise AuthorizationError("evidence reference is outside the tenant scope")
        parts = parsed.path.strip("/").split("/")
        if len(parts) != 2 or not all(re.fullmatch(r"[A-Fa-f0-9]+", part) for part in parts):
            raise NotFoundError("evidence", ref)
        digest, object_id = parts
        if len(digest) != 64 or len(object_id) != 32:
            raise NotFoundError("evidence", ref)
        path = self._safe_path(Path(tenant_id, digest[:2], f"{object_id}.evidence"))
        try:
            data = await asyncio.to_thread(path.read_bytes)
        except FileNotFoundError as error:
            raise NotFoundError("evidence", ref) from error
        if not secure_compare(sha256_hex(data), digest):
            raise EvidenceIntegrityError(ref)
        return data

    def _safe_path(self, relative: Path) -> Path:
        destination = (self._root / relative).resolve()
        if not destination.is_relative_to(self._root):
            raise AuthorizationError("object path escaped the configured store")
        return destination

    @staticmethod
    def _validate_tenant(tenant_id: str) -> None:
        if _TENANT_ID.fullmatch(tenant_id) is None:
            raise ValueError("invalid tenant identifier")

    @staticmethod
    def _write_once(root: Path, relative: Path, data: bytes) -> None:
        with open_exclusive_under_root(root, relative) as output:
            output.write(data)
