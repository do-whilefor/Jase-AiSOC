from __future__ import annotations

from pathlib import Path

import pytest

from blue_team.errors import AuthorizationError, EvidenceIntegrityError
from blue_team.storage import LocalObjectStore


@pytest.mark.asyncio
async def test_local_object_store_is_immutable_and_tenant_bound(tmp_path: Path) -> None:
    store = LocalObjectStore(tmp_path / "evidence")
    await store.initialize()
    tenant_id = "ten_01JTESTTENANT"
    other_tenant = "ten_01JOTHERTEST"

    metadata = await store.put(tenant_id, b"immutable evidence", media_type="text/plain")

    assert metadata.ref.startswith(f"evidence://{tenant_id}/")
    assert metadata.size == len(b"immutable evidence")
    assert await store.get(tenant_id, metadata.ref) == b"immutable evidence"
    with pytest.raises(AuthorizationError):
        await store.get(other_tenant, metadata.ref)


@pytest.mark.asyncio
async def test_local_object_store_detects_on_disk_tampering(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = LocalObjectStore(root)
    await store.initialize()
    tenant_id = "ten_01JTESTTENANT"
    metadata = await store.put(tenant_id, b"original", media_type="text/plain")
    stored_file = next(root.rglob("*.evidence"))
    stored_file.write_bytes(b"tampered")

    with pytest.raises(EvidenceIntegrityError):
        await store.get(tenant_id, metadata.ref)


@pytest.mark.asyncio
async def test_local_object_store_rejects_path_like_tenant_ids(tmp_path: Path) -> None:
    store = LocalObjectStore(tmp_path / "evidence")
    await store.initialize()

    with pytest.raises(ValueError, match="tenant identifier"):
        await store.put("../escape", b"data", media_type="application/octet-stream")
