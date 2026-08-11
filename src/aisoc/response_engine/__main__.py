"""Standalone local-single-node P11 native response worker."""

from __future__ import annotations

import asyncio
import os
import sys

from aisoc.agent_core.process import load_agent_process_config
from aisoc.config import get_settings
from aisoc.domain.response import FirewallAdapter
from aisoc.observability import configure_logging
from aisoc.response_engine.native import (
    AsyncCommandRunner,
    LocalAgentBoundary,
    build_local_response_registry,
)
from aisoc.response_engine.worker import ResponseWorker
from aisoc.storage import Database


async def _run() -> None:
    settings = get_settings()
    if not settings.response_execution_enabled or not settings.response_worker_enabled:
        raise RuntimeError("standalone response worker requires explicit execution enablement")
    if settings.response_execution_profile != "local_single_node":
        raise RuntimeError("standalone native response worker is limited to local_single_node")
    if not sys.platform.startswith("linux"):
        raise RuntimeError("standalone native response worker requires Linux")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        raise RuntimeError("standalone native response worker requires effective UID 0")
    if settings.response_local_agent_config_path is None:
        raise RuntimeError("standalone response worker requires the private local Agent config")

    agent = load_agent_process_config(settings.response_local_agent_config_path)
    boundary = LocalAgentBoundary(
        tenant_id=agent.tenant_id,
        host_id=agent.host_id,
        agent_id=agent.agent_id,
    )
    command_runner = AsyncCommandRunner(
        timeout_seconds=settings.response_command_timeout_seconds,
        max_output_bytes=settings.response_command_max_output_bytes,
    )
    registry = build_local_response_registry(
        boundary=boundary,
        firewall_adapter=FirewallAdapter(settings.response_firewall_adapter),
        quarantine_root=settings.response_file_quarantine_root,
        allowed_file_roots=settings.response_allowed_file_roots,
        allowed_accounts=settings.response_allowed_accounts,
        minimum_account_uid=settings.response_min_account_uid,
        max_file_bytes=settings.response_file_max_bytes,
        command_runner=command_runner,
    )
    configure_logging(settings)
    database = Database(settings.database_url, echo=settings.database_echo)
    worker = ResponseWorker(
        database,
        registry,
        settings=settings,
        tenant_id=boundary.tenant_id,
        host_id=boundary.host_id,
    )
    try:
        await worker.run_loop()
    finally:
        await database.dispose()


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
