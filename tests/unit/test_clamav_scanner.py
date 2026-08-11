"""Tests for the real ClamAV clamd INSTREAM adapter.

These tests exercise the verdict-parsing logic and the protocol framing without
a live clamd daemon, using an in-process asyncio server that speaks the minimal
INSTREAM protocol.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from blue_team.domain.malware import (
    EngineKind,
    EngineStatus,
    FileKind,
    StaticFileProfile,
    ThreatSignal,
)
from blue_team.malware_engine.clamav_scanner import ClamAvAdapter


def _make_profile() -> StaticFileProfile:
    return StaticFileProfile(
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size=0,
        detected_media_type="application/octet-stream",
        kind=FileKind.UNKNOWN,
        entropy=0.0,
    )


class _FakeClamdServer:
    """Minimal clamd INSTREAM server for testing."""

    def __init__(self, *, response: bytes) -> None:
        self._response = response
        self._server: asyncio.Server | None = None
        self._path: str | None = None
        self.received_data = bytearray()

    async def start_unix(self) -> str:
        with NamedTemporaryFile(suffix=".clamd", delete=False) as f:
            f.close()
            path = f.name
        Path(path).unlink(missing_ok=True)
        self._path = path
        self._server = await asyncio.start_unix_server(self._handle, path=path)
        return path

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        if self._path is not None:
            Path(self._path).unlink(missing_ok=True)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Read the command line.
        await reader.readuntil(b"\n")
        # Read chunks until a zero-length chunk.
        while True:
            length_bytes = await reader.readexactly(4)
            length = int.from_bytes(length_bytes, "big")
            if length == 0:
                break
            chunk = await reader.readexactly(length)
            self.received_data.extend(chunk)
        # Send the verdict.
        writer.write(self._response)
        await writer.drain()
        writer.close()
        with suppress(OSError, ConnectionError):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_clamav_clean_verdict() -> None:
    server = _FakeClamdServer(response=b"stream: OK\n")
    socket_path = await server.start_unix()
    try:
        adapter = ClamAvAdapter(socket_path=socket_path)
        result = await adapter.scan(b"clean data", _make_profile())

        assert result.kind is EngineKind.CLAMAV
        assert result.status is EngineStatus.COMPLETED
        assert result.signal is ThreatSignal.CLEAN
        assert result.matched_rules == ()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_clamav_found_verdict() -> None:
    server = _FakeClamdServer(response=b"stream: Eicar-Test-Signature FOUND\n")
    socket_path = await server.start_unix()
    try:
        adapter = ClamAvAdapter(socket_path=socket_path)
        result = await adapter.scan(b"malicious data", _make_profile())

        assert result.status is EngineStatus.COMPLETED
        assert result.signal is ThreatSignal.SUSPICIOUS
        assert result.matched_rules == ("Eicar-Test-Signature",)
        assert result.observations == ("clamav_match:Eicar-Test-Signature",)
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_clamav_found_extracts_family_candidate() -> None:
    server = _FakeClamdServer(response=b"stream: Win.Trojan.Emotet-6123 FOUND\n")
    socket_path = await server.start_unix()
    try:
        adapter = ClamAvAdapter(socket_path=socket_path)
        result = await adapter.scan(b"malicious", _make_profile())

        assert result.family_candidates == ("Emotet",)
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_clamav_error_verdict() -> None:
    server = _FakeClamdServer(response=b"stream: lseek() failed. ERROR\n")
    socket_path = await server.start_unix()
    try:
        adapter = ClamAvAdapter(socket_path=socket_path)
        result = await adapter.scan(b"data", _make_profile())

        assert result.status is EngineStatus.ERROR
        assert result.error_code == "scan_error"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_clamav_connection_unavailable() -> None:
    adapter = ClamAvAdapter(socket_path="/nonexistent/clamd.sock")
    result = await adapter.scan(b"data", _make_profile())

    assert result.status is EngineStatus.UNAVAILABLE
    assert result.error_code == "clamd_unreachable"


@pytest.mark.asyncio
async def test_clamav_timeout() -> None:
    """A clamd that accepts the stream but never sends a verdict triggers a timeout."""

    async def _hang_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\n")
        while True:
            length_bytes = await reader.readexactly(4)
            length = int.from_bytes(length_bytes, "big")
            if length == 0:
                break
            await reader.readexactly(length)
        # Never send a response — hang until the client times out.
        await asyncio.Event().wait()

    with NamedTemporaryFile(suffix=".clamd", delete=False) as f:
        f.close()
        path = f.name
    Path(path).unlink(missing_ok=True)
    server = await asyncio.start_unix_server(_hang_handler, path=path)
    try:
        adapter = ClamAvAdapter(socket_path=path, timeout_seconds=1)
        result = await adapter.scan(b"data", _make_profile())

        assert result.status is EngineStatus.ERROR
        assert result.error_code == "scan_timeout"
    finally:
        # Close without waiting for the hanging handler — it blocks on
        # asyncio.Event().wait() which will be cancelled on event-loop shutdown.
        server.close()
        Path(path).unlink(missing_ok=True)


def test_clamav_requires_socket_or_host_port() -> None:
    with pytest.raises(ValueError, match="requires"):
        ClamAvAdapter()

    with pytest.raises(ValueError, match="not both"):
        ClamAvAdapter(socket_path="/tmp/clamd.sock", host="localhost", port=3310)


@pytest.mark.asyncio
async def test_clamav_streams_full_sample_to_clamd() -> None:
    server = _FakeClamdServer(response=b"stream: OK\n")
    socket_path = await server.start_unix()
    try:
        adapter = ClamAvAdapter(socket_path=socket_path)
        sample = b"x" * 200_000  # larger than one chunk
        await adapter.scan(sample, _make_profile())

        assert bytes(server.received_data) == sample
    finally:
        await server.stop()
