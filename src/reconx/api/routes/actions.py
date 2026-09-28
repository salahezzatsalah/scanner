"""Endpoints that do something.

Kept deliberately small. A scan takes minutes, so starting one returns
immediately and the client polls ``/scans`` for the outcome. Only one scan runs
per program at a time, for the same reason the scheduler enforces that: two
concurrent runs would double the request rate the scope's limits are meant to
cap.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from reconx.api.app import get_session
from reconx.db.store import get_program
from reconx.orchestrator import Orchestrator, StagePlanError, resolve_stage_names

router = APIRouter(prefix="/api/v1", tags=["actions"])

SessionDep = Annotated[AsyncSession, Depends(get_session)]

# Scans in flight, by program slug. In-process: the API and the scheduler are
# separate processes, and the database is the shared source of truth.
_running: dict[str, asyncio.Task] = {}


def _prune() -> None:
    for slug in [slug for slug, task in _running.items() if task.done()]:
        _running.pop(slug, None)


@router.get("/running")
async def running() -> dict[str, Any]:
    """Which scans this API process has in flight."""
    _prune()
    return {"count": len(_running), "programs": sorted(_running)}


@router.post("/programs/{slug}/scans", status_code=status.HTTP_202_ACCEPTED)
async def start_scan(
    slug: str,
    request: Request,
    session: SessionDep,
    stages: Annotated[
        list[str] | None,
        Body(
            embed=True,
            description="Stage or group names. Defaults to the recon group.",
        ),
    ] = None,
) -> dict[str, Any]:
    """Start a scan in the background.

    Returns as soon as the run is accepted. Poll
    ``GET /api/v1/programs/{slug}/scans`` for progress and the result.
    """
    _prune()
    program = await get_program(session, slug)
    if program is None:
        raise HTTPException(status_code=404, detail=f"no program with slug {slug!r}")

    if slug in _running:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"a scan is already running for {slug!r}. Two concurrent runs would "
                "double the request rate the scope's limits are meant to cap."
            ),
        )

    try:
        planned = resolve_stage_names(stages)
    except StagePlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    from reconx.monitor.scheduler import _scope_from_yaml

    try:
        scope = _scope_from_yaml(program.scope_yaml)
    except Exception as exc:
        raise HTTPException(
            status_code=409,
            detail=f"the stored scope for {slug!r} is no longer valid: {exc}",
        ) from exc

    settings = request.app.state.settings
    orchestrator = Orchestrator(scope, scope_yaml=program.scope_yaml, settings=settings)

    async def run() -> None:
        try:
            await orchestrator.run(planned, trigger="api")
        finally:
            _running.pop(slug, None)

    _running[slug] = asyncio.create_task(run())

    return {
        "accepted": True,
        "program": slug,
        "stages": planned,
        "poll": f"/api/v1/programs/{slug}/scans",
    }
