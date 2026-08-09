"""FastAPI dependencies bound to explicit application state."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.agent_core import CertificateSigner
from blue_team.ai_review.runtime import AiReviewRuntime
from blue_team.config import Settings
from blue_team.detection_engine.lifecycle import RuleLifecycleTrustKey
from blue_team.errors import ServiceUnavailableError
from blue_team.storage import Database, ObjectStore, QuarantineStore


def get_settings(request: Request) -> Settings:
    value: Settings = request.app.state.settings
    return value


def get_database(request: Request) -> Database:
    value: Database = request.app.state.database
    return value


def get_object_store(request: Request) -> ObjectStore:
    value: ObjectStore = request.app.state.object_store
    return value


def get_quarantine_store(request: Request) -> QuarantineStore:
    value: QuarantineStore | None = request.app.state.quarantine_store
    settings: Settings = request.app.state.settings
    if not settings.malware_analysis_enabled or value is None:
        raise ServiceUnavailableError("malware quarantine")
    return value


def get_certificate_signer(request: Request) -> CertificateSigner:
    value: CertificateSigner | None = request.app.state.certificate_signer
    if value is None:
        raise ServiceUnavailableError("Agent certificate signer")
    return value


def get_ai_review_runtime(request: Request) -> AiReviewRuntime:
    value: AiReviewRuntime | None = request.app.state.ai_review_runtime
    if value is None:
        raise ServiceUnavailableError("AI review provider")
    return value


def get_rule_lifecycle_trust_keys(request: Request) -> tuple[RuleLifecycleTrustKey, ...]:
    value: tuple[RuleLifecycleTrustKey, ...] = request.app.state.rule_lifecycle_trust_keys
    if not value:
        raise ServiceUnavailableError("rule lifecycle trust store")
    return value


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    database: Database = request.app.state.database
    async with database.session() as session, session.begin():
        yield session
