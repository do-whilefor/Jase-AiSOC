"""P3 enrichment: asset (hosts table) + external (IOC/ASN/reputation), never blocking.

External enrichment failures MUST return None and never raise; the orchestrator
rebuilds the SecurityEvent with whatever enrichment succeeded, leaving the event
unchanged if nothing enriched. Results are merged into ``extensions``/``labels``
respecting the 32-extension / 64-label caps.
"""

from __future__ import annotations

from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from aisoc.domain.security_event import SecurityEvent
from aisoc.storage import repositories

_MAX_EXTENSIONS = 32
_MAX_LABELS = 64


class ExternalEnricher(Protocol):
    async def enrich_ip(self, ip: str) -> dict[str, object] | None: ...
    async def enrich_sha256(self, sha256: str) -> dict[str, object] | None: ...
    async def enrich_domain(self, domain: str) -> dict[str, object] | None: ...


class NoOpExternalEnricher:
    """Default external enricher for P3: returns None for everything."""

    async def enrich_ip(self, ip: str) -> dict[str, object] | None:
        return None

    async def enrich_sha256(self, sha256: str) -> dict[str, object] | None:
        return None

    async def enrich_domain(self, domain: str) -> dict[str, object] | None:
        return None


class Enricher:
    """Orchestrate asset + external enrichment; external failure never blocks."""

    def __init__(self, external: ExternalEnricher | None = None) -> None:
        self._external = external or NoOpExternalEnricher()

    async def orchestrate(
        self,
        event: SecurityEvent,
        session: AsyncSession,
        *,
        tenant_id: str,
        host_id: str,
    ) -> SecurityEvent:
        extensions = dict(event.extensions)
        labels = dict(event.labels)
        asset = await self._asset_enrichment(session, tenant_id=tenant_id, host_id=host_id)
        if asset is not None:
            self._merge_extension(extensions, "aisoc.asset", asset)
        external = await self._external_enrichment(event)
        if external is not None:
            self._merge_extension(extensions, "aisoc.enrichment", external)
        if not extensions and not labels:
            return event
        return event.model_copy(update={"extensions": extensions, "labels": labels})

    async def _asset_enrichment(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        host_id: str,
    ) -> dict[str, object] | None:
        try:
            host = await repositories.get_host(session, tenant_id=tenant_id, host_id=host_id)
        except Exception:
            return None
        if host is None:
            return None
        return {
            "hostname": host.hostname,
            "distro": host.distro,
            "kernel": host.kernel,
            "criticality": host.criticality,
        }

    async def _external_enrichment(self, event: SecurityEvent) -> dict[str, object] | None:
        results: dict[str, object] = {}
        if event.network is not None:
            for ip in (event.network.src_ip, event.network.dst_ip):
                if ip is None:
                    continue
                try:
                    enrichment = await self._external.enrich_ip(str(ip))
                except Exception:
                    enrichment = None
                if enrichment is not None:
                    results[f"ip.{ip}"] = enrichment
        if event.process is not None and event.process.sha256 is not None:
            try:
                enrichment = await self._external.enrich_sha256(event.process.sha256)
            except Exception:
                enrichment = None
            if enrichment is not None:
                results[f"sha256.{event.process.sha256}"] = enrichment
        domain = event.extensions.get("network.domain")
        if isinstance(domain, str) and domain:
            try:
                enrichment = await self._external.enrich_domain(domain)
            except Exception:
                enrichment = None
            if enrichment is not None:
                results[f"domain.{domain}"] = enrichment
        return results or None

    @staticmethod
    def _merge_extension(extensions: dict[str, object], name: str, value: object) -> None:
        if name in extensions or len(extensions) >= _MAX_EXTENSIONS:
            return
        extensions[name] = value
