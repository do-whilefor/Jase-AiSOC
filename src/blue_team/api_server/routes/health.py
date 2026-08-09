"""Liveness, readiness and Prometheus endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST

from blue_team.api_server.dependencies import get_database, get_object_store
from blue_team.storage import Database, ObjectStore

router = APIRouter(tags=["health"])


@router.get("/health/live", summary="Process liveness")
async def liveness() -> dict[str, str]:
    return {"status": "alive"}


@router.get("/health/ready", summary="Dependency readiness")
async def readiness(
    request: Request,
    database: Annotated[Database, Depends(get_database)],
    object_store: Annotated[ObjectStore, Depends(get_object_store)],
) -> JSONResponse:
    checks: dict[str, bool] = {
        "database": await database.ping(),
        "object_store": await object_store.ready(),
    }
    if request.app.state.settings.malware_analysis_enabled:
        quarantine = request.app.state.quarantine_store
        checks["malware_quarantine"] = quarantine is not None and await quarantine.ready()
    ready = all(checks.values())
    return JSONResponse(
        status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "ready" if ready else "not_ready", "checks": checks},
    )


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    return Response(content=request.app.state.metrics.render(), media_type=CONTENT_TYPE_LATEST)
