"""openat-based, symlink-rejecting write-once file creation for local stores.

Both the evidence :class:`~blue_team.storage.object_store.LocalObjectStore` and
the quarantine :class:`~blue_team.storage.quarantine.LocalQuarantineStore` write
objects once with ``O_CREAT|O_EXCL|O_NOFOLLOW``. A bare ``os.open(path, ...)``
only protects the *final* path component: a symlink planted in an intermediate
directory between ``mkdir`` and ``os.open`` is a TOCTOU window. This helper
walks each component relative to the store root via ``dir_fd`` (POSIX
``openat``/``mkdirat``) with ``O_NOFOLLOW|O_DIRECTORY`` on every directory
component, eliminating the intermediate-path race.

The existing ``_safe_path`` (``resolve()`` + ``is_relative_to``) stays for the
read paths and as defense-in-depth; this module scopes the hardening to the
write-once path only.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import IO


def _validate_components(components: Sequence[str]) -> tuple[str, ...]:
    parts = tuple(components)
    for part in parts:
        if not part or part in (".", "..") or "/" in part or "\x00" in part:
            raise ValueError("invalid path component for openat traversal")
    return parts


@contextmanager
def open_exclusive_under_root(root: Path, relative: Path) -> Iterator[IO[bytes]]:
    """Create and open ``root/relative`` write-once via per-component openat.

    Each directory component is opened with ``O_NOFOLLOW|O_DIRECTORY`` (created
    ``O_EXCL`` with mode ``0o700`` if missing), then the final file is created
    with ``O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC`` (mode ``0o600``)
    relative to its parent directory file descriptor. The traversal rejects a
    symlink planted in any intermediate component rather than silently
    following it.
    """
    parts = _validate_components(relative.parts)
    if not parts:
        raise ValueError("openat traversal requires a non-empty relative path")
    dir_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    file_fd: int | None = None
    try:
        for component in parts[:-1]:
            with suppress(FileExistsError):
                os.mkdir(component, 0o700, dir_fd=dir_fd)
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=dir_fd,
            )
            os.close(dir_fd)
            dir_fd = child
        file_fd = os.open(
            parts[-1],
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=dir_fd,
        )
        with os.fdopen(file_fd, "wb") as handle:
            file_fd = None  # fdopen owns the descriptor now
            yield handle
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(dir_fd)
