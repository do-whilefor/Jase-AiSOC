from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aisoc._rustcore import sha256_hex
from aisoc.enrich.ioc import IocFeedError, LocalIocEnricher


def _write_feed(path: Path, *, expired: bool = False) -> str:
    now = datetime(2026, 8, 11, 6, 0, tzinfo=UTC)
    payload = {
        "format_version": 1,
        "feed_id": "local.threat-intel",
        "version": "2026-08-11.1",
        "generated_at": now.isoformat(),
        "indicators": [
            {"type": "ip", "value": "203.0.113.7", "confidence": 95, "labels": ["c2"]},
            {"type": "domain", "value": "Bad.Example.", "confidence": 80},
            {
                "type": "sha256",
                "value": "a" * 64,
                "confidence": 90,
                "expires_at": (
                    now - timedelta(minutes=1) if expired else now + timedelta(days=1)
                ).isoformat(),
            },
        ],
    }
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    path.write_bytes(data)
    return sha256_hex(data)


def test_local_ioc_enricher_exact_match_and_normalization(tmp_path: Path) -> None:
    path = tmp_path / "feed.json"
    digest = _write_feed(path)
    enricher = LocalIocEnricher.from_file(path, expected_sha256=digest)

    assert asyncio.run(enricher.enrich_ip("203.0.113.7"))["confidence"] == 95  # type: ignore[index]
    assert (
        asyncio.run(enricher.enrich_domain("BAD.EXAMPLE."))["indicator_type"] == "domain"
    )  # type: ignore[index]
    assert (
        asyncio.run(enricher.enrich_sha256("A" * 64))["feed_id"] == "local.threat-intel"
    )  # type: ignore[index]
    assert asyncio.run(enricher.enrich_ip("203.0.113.8")) is None
    assert asyncio.run(enricher.enrich_domain("sub.bad.example")) is None


def test_expired_ioc_is_not_active(tmp_path: Path) -> None:
    path = tmp_path / "feed.json"
    digest = _write_feed(path, expired=True)
    enricher = LocalIocEnricher.from_file(path, expected_sha256=digest)

    assert asyncio.run(enricher.enrich_sha256("a" * 64)) is None


def test_ioc_feed_digest_is_pinned(tmp_path: Path) -> None:
    path = tmp_path / "feed.json"
    _write_feed(path)

    with pytest.raises(IocFeedError, match="does not match"):
        LocalIocEnricher.from_file(path, expected_sha256="0" * 64)


def test_ioc_feed_rejects_symlink_and_group_writable_file(tmp_path: Path) -> None:
    path = tmp_path / "feed.json"
    digest = _write_feed(path)
    link = tmp_path / "feed-link.json"
    link.symlink_to(path)

    with pytest.raises(IocFeedError, match="opened safely"):
        LocalIocEnricher.from_file(link, expected_sha256=digest)

    path.chmod(0o664)
    with pytest.raises(IocFeedError, match="group/world writable"):
        LocalIocEnricher.from_file(path, expected_sha256=digest)
