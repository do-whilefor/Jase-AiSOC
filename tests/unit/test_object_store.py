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


@pytest.mark.asyncio
async def test_local_object_store_rejects_intermediate_directory_symlink(
    tmp_path: Path,
) -> None:
    """An openat traversal must reject a symlink planted in an intermediate dir.

    The old bare ``os.open(path, O_NOFOLLOW)`` only protected the final
    component and would silently follow a symlink in an intermediate directory
    between ``mkdir`` and ``open``. The per-component ``O_NOFOLLOW|O_DIRECTORY``
    traversal now fails instead of writing through a planted symlink. Verified
    directly against the shared helper with a deterministic relative path.
    """
    from blue_team.storage._safe_open import open_exclusive_under_root

    root = tmp_path / "store"
    root.mkdir()
    tenant_dir = root / "ten_01JTESTTENANT"
    tenant_dir.mkdir()
    # Plant a symlink at the intermediate digest-prefix directory that escapes the store.
    escape = tmp_path / "outside"
    escape.mkdir()
    (tenant_dir / "ab").symlink_to(escape)

    # The traversal opens the planted "ab" symlink as a directory component;
    # O_NOFOLLOW|O_DIRECTORY must reject it rather than follow it outside the store.
    with pytest.raises(OSError), open_exclusive_under_root(
        root, Path("ten_01JTESTTENANT", "ab", "file.evidence")
    ):
        pass


@pytest.mark.asyncio
async def test_local_object_store_write_creates_intermediate_directories(
    tmp_path: Path,
) -> None:
    """The openat traversal still creates the intermediate tenant/digest dirs."""
    store = LocalObjectStore(tmp_path / "evidence")
    await store.initialize()
    tenant_id = "ten_01JTESTTENANT"
    metadata = await store.put(tenant_id, b"payload", media_type="text/plain")
    assert await store.get(tenant_id, metadata.ref) == b"payload"
    # The intermediate directory tree was created with the expected layout.
    stored = next((tmp_path / "evidence").rglob("*.evidence"))
    assert stored.parent.parent.name == tenant_id
