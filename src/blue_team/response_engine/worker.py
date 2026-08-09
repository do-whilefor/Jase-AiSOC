"""Standalone lease-based P11 Action Runner with no transaction held during actions."""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from uuid import uuid4

from blue_team.config import Settings, get_settings
from blue_team.response_engine.adapters import ResponseAdapterRegistry
from blue_team.response_engine.runner import (
    execute_response_action,
    rollback_response_action,
)
from blue_team.storage import Database
from blue_team.storage.response_repository import (
    claim_next_response_action,
    complete_response_execution,
    complete_response_rollback,
    fail_response_lease,
)

logger = logging.getLogger(__name__)


class ResponseWorker:
    """Claim, revalidate, execute, verify, and persist outside DB transactions."""

    def __init__(
        self,
        database: Database,
        adapters: ResponseAdapterRegistry,
        *,
        settings: Settings | None = None,
        worker_id: str | None = None,
    ) -> None:
        resolved = settings or get_settings()
        self._database = database
        self._adapters = adapters
        self._worker_id = worker_id or f"response-worker-{uuid4().hex}"
        self._poll_seconds = resolved.response_worker_poll_seconds
        self._lease_seconds = resolved.response_execution_lease_seconds
        if not self._worker_id or len(self._worker_id) > 128:
            raise ValueError("worker_id must contain 1 to 128 characters")
        self._task: asyncio.Task[None] | None = None

    async def run_once(self) -> int:
        async with self._database.session() as session, session.begin():
            lease = await claim_next_response_action(
                session,
                worker_id=self._worker_id,
                lease_seconds=self._lease_seconds,
            )
        if lease is None:
            return 0
        try:
            adapter = self._adapters.require(lease.plan.adapter)
            if lease.mode == "execute":
                result = await execute_response_action(lease.plan, adapter, now=lease.started_at)
            else:
                if lease.execution is None:
                    raise RuntimeError("rollback lease is missing its execution checkpoint")
                rollback = await rollback_response_action(lease.plan, lease.execution, adapter)
        except Exception as error:
            error_code = _response_error_code(error)
            async with self._database.session() as session, session.begin():
                await fail_response_lease(
                    session,
                    lease=lease,
                    worker_id=self._worker_id,
                    error_code=error_code,
                    state_unknown=error_code == "response_execution_state_unknown",
                )
            logger.warning(
                "response action attempt failed",
                extra={
                    "action_id": lease.plan.action_id,
                    "mode": lease.mode,
                    "error_code": error_code,
                },
            )
            return 0
        try:
            async with self._database.session() as session, session.begin():
                if lease.mode == "execute":
                    await complete_response_execution(
                        session,
                        lease=lease,
                        result=result,
                        worker_id=self._worker_id,
                    )
                else:
                    await complete_response_rollback(
                        session,
                        lease=lease,
                        result=rollback,
                        worker_id=self._worker_id,
                    )
        except Exception:
            logger.exception(
                "response result persistence failed; lease left for conservative recovery",
                extra={"action_id": lease.plan.action_id, "mode": lease.mode},
            )
            return 0
        return 1

    async def run_loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception:
                logger.exception("response worker cycle failed")
            await asyncio.sleep(self._poll_seconds)

    def start(self) -> asyncio.Task[None]:
        if self._task is not None and not self._task.done():
            return self._task
        self._task = asyncio.create_task(self.run_loop(), name="response-worker")
        return self._task

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task
        self._task = None


def _response_error_code(error: Exception) -> str:
    name = type(error).__name__.lower()
    if "target" in str(error).lower() or "identity" in str(error).lower():
        return "response_target_revalidation_failed"
    if "adapter" in name or "adapter" in str(error).lower():
        return "response_adapter_failed"
    if "rollback" in str(error).lower():
        return "response_rollback_failed"
    return "response_execution_state_unknown"


__all__ = ["ResponseWorker"]
