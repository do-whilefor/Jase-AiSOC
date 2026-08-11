"""Pinned local IOC feed with exact deterministic matching.

This is a deployment-local feed, not the full P11 managed IOC lifecycle. The
feed is read once at startup through a non-following file descriptor and must
match the SHA-256 pinned in configuration before any indicator is accepted.
"""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aisoc._rustcore import IocMatcher, secure_compare, sha256_hex

_MAX_FEED_BYTES = 8 * 1024 * 1024
_MAX_INDICATORS = 100_000


class IocFeedError(ValueError):
    """The configured IOC feed failed integrity or schema validation."""


class IndicatorKind(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    SHA256 = "sha256"


class _FeedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class IocIndicator(_FeedModel):
    indicator_type: IndicatorKind = Field(alias="type")
    value: Annotated[str, Field(min_length=1, max_length=512)]
    confidence: Annotated[int, Field(ge=0, le=100)] = 50
    labels: tuple[Annotated[str, Field(min_length=1, max_length=64)], ...] = ()
    expires_at: datetime | None = None

    @field_validator("labels")
    @classmethod
    def normalize_labels(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 16:
            raise ValueError("IOC labels cannot exceed 16 entries")
        normalized = tuple(dict.fromkeys(item.lower() for item in value))
        if len(normalized) != len(value):
            raise ValueError("IOC labels must be unique")
        return normalized

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str, info: object) -> str:
        # Cross-field normalization happens in the feed validator where the type
        # is available deterministically.
        return value


class IocFeed(_FeedModel):
    format_version: Literal[1] = 1
    feed_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{2,127}$")]
    version: Annotated[str, Field(min_length=1, max_length=128)]
    generated_at: datetime
    indicators: tuple[IocIndicator, ...] = Field(max_length=_MAX_INDICATORS)

    @model_validator(mode="after")
    def validate_indicators(self) -> "IocFeed":
        seen: set[tuple[IndicatorKind, str]] = set()
        for indicator in self.indicators:
            normalized = normalize_indicator(indicator.indicator_type, indicator.value)
            key = (indicator.indicator_type, normalized)
            if key in seen:
                raise ValueError(f"duplicate IOC indicator: {indicator.indicator_type}:{normalized}")
            seen.add(key)
            if indicator.expires_at is not None and (
                indicator.expires_at.tzinfo is None or indicator.expires_at.utcoffset() is None
            ):
                raise ValueError("IOC expires_at must be timezone-aware")
        if self.generated_at.tzinfo is None or self.generated_at.utcoffset() is None:
            raise ValueError("IOC generated_at must be timezone-aware")
        return self


class LocalIocEnricher:
    """Read-only IOC enrichment provider used before deterministic detection."""

    def __init__(self, feed: IocFeed, *, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        active = tuple(
            indicator
            for indicator in feed.indicators
            if indicator.expires_at is None or indicator.expires_at.astimezone(UTC) > current
        )
        self.feed_id = feed.feed_id
        self.feed_version = feed.version
        self._by_key = {
            (indicator.indicator_type, normalize_indicator(indicator.indicator_type, indicator.value)):
            indicator
            for indicator in active
        }
        self._matcher = IocMatcher(
            ips=tuple(
                key for (kind, key), _indicator in self._by_key.items() if kind is IndicatorKind.IP
            ),
            domains=tuple(
                key
                for (kind, key), _indicator in self._by_key.items()
                if kind is IndicatorKind.DOMAIN
            ),
            sha256=tuple(
                key
                for (kind, key), _indicator in self._by_key.items()
                if kind is IndicatorKind.SHA256
            ),
        )

    @classmethod
    def from_file(cls, path: Path, *, expected_sha256: str) -> "LocalIocEnricher":
        payload = _read_pinned_feed(path, expected_sha256=expected_sha256)
        try:
            feed = IocFeed.model_validate_json(payload)
        except ValueError as error:
            raise IocFeedError("IOC feed schema is invalid") from error
        return cls(feed)

    async def enrich_ip(self, ip: str) -> dict[str, object] | None:
        if not self._matcher.contains_ip(ip):
            return None
        return self._result(IndicatorKind.IP, normalize_indicator(IndicatorKind.IP, ip))

    async def enrich_sha256(self, sha256: str) -> dict[str, object] | None:
        if not self._matcher.contains_sha256(sha256):
            return None
        return self._result(
            IndicatorKind.SHA256,
            normalize_indicator(IndicatorKind.SHA256, sha256),
        )

    async def enrich_domain(self, domain: str) -> dict[str, object] | None:
        if not self._matcher.contains_domain(domain):
            return None
        return self._result(
            IndicatorKind.DOMAIN,
            normalize_indicator(IndicatorKind.DOMAIN, domain),
        )

    def _result(self, kind: IndicatorKind, normalized: str) -> dict[str, object] | None:
        indicator = self._by_key.get((kind, normalized))
        if indicator is None:
            return None
        return {
            "provider": "local_pinned_ioc",
            "feed_id": self.feed_id,
            "feed_version": self.feed_version,
            "indicator_type": kind.value,
            "confidence": indicator.confidence,
            "labels": indicator.labels,
            "expires_at": (
                indicator.expires_at.astimezone(UTC).isoformat()
                if indicator.expires_at is not None
                else None
            ),
        }


def normalize_indicator(kind: IndicatorKind, value: str) -> str:
    if kind is IndicatorKind.IP:
        try:
            return str(ip_address(value.strip()))
        except ValueError as error:
            raise IocFeedError("invalid IOC IP address") from error
    if kind is IndicatorKind.SHA256:
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            raise IocFeedError("invalid IOC SHA-256")
        return normalized

    normalized = value.strip().rstrip(".").lower()
    if not normalized or len(normalized) > 253 or not normalized.isascii():
        raise IocFeedError("invalid IOC domain")
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        raise IocFeedError("invalid IOC domain")
    return normalized


def _read_pinned_feed(path: Path, *, expected_sha256: str) -> bytes:
    expected = expected_sha256.strip().lower()
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        raise IocFeedError("expected IOC feed SHA-256 is invalid")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path.expanduser(), flags)
    except OSError as error:
        raise IocFeedError("IOC feed could not be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise IocFeedError("IOC feed must be a single-link regular file")
        if metadata.st_mode & 0o022:
            raise IocFeedError("IOC feed must not be group/world writable")
        if not 1 <= metadata.st_size <= _MAX_FEED_BYTES:
            raise IocFeedError("IOC feed size is outside the allowed range")
        chunks: list[bytes] = []
        remaining = _MAX_FEED_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_FEED_BYTES:
            raise IocFeedError("IOC feed exceeds the 8 MiB limit")
    finally:
        os.close(descriptor)

    actual = sha256_hex(payload)
    if not secure_compare(actual, expected):
        raise IocFeedError("IOC feed SHA-256 does not match the pinned digest")
    return payload


__all__ = [
    "IndicatorKind",
    "IocFeed",
    "IocFeedError",
    "IocIndicator",
    "LocalIocEnricher",
    "normalize_indicator",
]
