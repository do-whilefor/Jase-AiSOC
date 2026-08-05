"""FastAPI application factory for the P1 Base profile."""

from __future__ import annotations

import asyncio
import os
import stat
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request, Response

from blue_team import __version__
from blue_team.agent_core import CertificateSigner, LocalCertificateAuthority
from blue_team.api_server.error_handlers import install_error_handlers
from blue_team.api_server.routes import (
    agents,
    detections,
    events,
    health,
    hosts,
    incidents,
    tenants,
)
from blue_team.config import Settings, get_settings
from blue_team.detection_engine.worker import DetectionWorker
from blue_team.normalize.worker import NormalizeWorker
from blue_team.observability import Metrics, bind_trace_id, configure_logging, get_logger
from blue_team.observability.logging import reset_trace_id
from blue_team.storage import Database, LocalObjectStore, ObjectStore


def create_app(
    settings: Settings | None = None,
    *,
    database: Database | None = None,
    object_store: ObjectStore | None = None,
    certificate_signer: CertificateSigner | None = None,
) -> FastAPI:
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings)
    logger = get_logger(__name__)
    resolved_database = database or Database(
        resolved_settings.database_url,
        echo=resolved_settings.database_echo,
    )
    resolved_store = object_store or LocalObjectStore(resolved_settings.resolved_object_store_root)
    resolved_signer = certificate_signer or _load_certificate_signer(resolved_settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await resolved_store.initialize()
        normalize_worker: NormalizeWorker | None = None
        detection_worker: DetectionWorker | None = None
        worker_tasks: list[asyncio.Task[None]] = []
        if resolved_settings.workers_enabled:
            normalize_worker = NormalizeWorker(
                resolved_database,
                resolved_store,
                batch_size=resolved_settings.normalize_worker_batch_size,
                poll_seconds=resolved_settings.normalize_worker_poll_seconds,
            )
            detection_worker = DetectionWorker(
                resolved_database,
                settings=resolved_settings,
                poll_seconds=resolved_settings.detection_worker_poll_seconds,
                lookback_seconds=resolved_settings.detection_lookback_seconds,
            )
            worker_tasks.append(normalize_worker.start())
            worker_tasks.append(detection_worker.start())
            logger.info("pipeline_workers_started")
        logger.info(
            "api_server_started",
            environment=resolved_settings.environment,
            version=__version__,
        )
        try:
            yield
        finally:
            for task in worker_tasks:
                task.cancel()
            if worker_tasks:
                await asyncio.gather(*worker_tasks, return_exceptions=True)
            await resolved_database.dispose()
            logger.info("api_server_stopped")

    app = FastAPI(
        title="Blue Team AI Agent API",
        version=__version__,
        summary="Evidence-first Linux security control plane",
        lifespan=lifespan,
        docs_url="/docs" if resolved_settings.environment != "production" else None,
        redoc_url=None,
    )
    app.state.settings = resolved_settings
    app.state.database = resolved_database
    app.state.object_store = resolved_store
    app.state.certificate_signer = resolved_signer
    app.state.metrics = Metrics()

    install_error_handlers(app)
    app.include_router(health.router)
    app.include_router(tenants.router)
    app.include_router(hosts.router)
    app.include_router(incidents.router)
    app.include_router(agents.router)
    app.include_router(events.router)
    app.include_router(detections.router)

    @app.middleware("http")
    async def request_context(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        trace_id = f"trace_{uuid4().hex}"
        request.state.trace_id = trace_id
        token = bind_trace_id(trace_id)
        started = time.perf_counter()
        response: Response | None = None
        try:
            response = await call_next(request)
            return response
        finally:
            elapsed = time.perf_counter() - started
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            status_code = response.status_code if response is not None else 500
            app.state.metrics.http_requests.labels(
                request.method,
                route_path,
                str(status_code),
            ).inc()
            app.state.metrics.http_duration.labels(request.method, route_path).observe(elapsed)
            logger.info(
                "http_request",
                method=request.method,
                route=route_path,
                status=status_code,
                duration_seconds=round(elapsed, 6),
            )
            if response is not None:
                response.headers["X-Trace-ID"] = trace_id
            reset_trace_id(token)

    return app


def _load_certificate_signer(settings: Settings) -> CertificateSigner | None:
    certificate_path = settings.agent_ca_certificate_path
    private_key_path = settings.agent_ca_private_key_path
    if certificate_path is None or private_key_path is None:
        return None
    key_metadata = private_key_path.lstat()
    if stat.S_ISLNK(key_metadata.st_mode) or not stat.S_ISREG(key_metadata.st_mode):
        raise ValueError("Agent CA private key must be a regular file, not a link")
    if os.name != "nt" and stat.S_IMODE(key_metadata.st_mode) & 0o077:
        raise ValueError("Agent CA private key must not be accessible by group or other users")
    return LocalCertificateAuthority.from_pem(
        private_key_path.read_bytes(),
        certificate_path.read_bytes(),
    )
