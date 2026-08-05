"""FastAPI dependencies bound to explicit application state."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from blue_team.agent_core import CertificateSigner
from blue_team.config import Settings
from blue_team.errors import ServiceUnavailableError
from blue_team.storage import Database, ObjectStore


def get_settings(request: Request) -> Settings:
    value: Settings = request.app.state.settings
    return value


def get_database(request: Request) -> Database:
    value: Database = request.app.state.database
    return value


def get_object_store(request: Request) -> ObjectStore:
    value: ObjectStore = request.app.state.object_store
    return value


def get_certificate_signer(request: Request) -> CertificateSigner:
    value: CertificateSigner | None = request.app.state.certificate_signer
    if value is None:
        raise ServiceUnavailableError("Agent certificate signer")
    return value


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    database: Database = request.app.state.database
    async with database.session() as session, session.begin():
        yield session
