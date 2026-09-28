"""Read endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx.api.app import get_session
from reconx.db.models import (
    Asset,
    AuditEntry,
    Endpoint,
    Evidence,
    Finding,
    FindingTier,
    Observation,
    Program,
    ScanRun,
)
from reconx.db.store import get_program, list_programs

router = APIRouter(prefix="/api/v1", tags=["data"])

SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def _program_or_404(session: AsyncSession, slug: str) -> Program:
    program = await get_program(session, slug)
    if program is None:
        raise HTTPException(status_code=404, detail=f"no program with slug {slug!r}")
    return program


def _program_payload(program: Program) -> dict[str, Any]:
    return {
        "slug": program.slug,
        "name": program.name,
        "platform": program.platform,
        "program_url": program.program_url,
        "monitoring_enabled": program.monitoring_enabled,
        "authorized_by": program.authorized_by,
        "authorization_date": str(program.authorization_date),
        "created_at": program.created_at.isoformat(),
    }


@router.get("/programs")
async def programs(session: SessionDep) -> dict[str, Any]:
    rows = await list_programs(session)
    return {"count": len(rows), "programs": [_program_payload(row) for row in rows]}


@router.get("/programs/{slug}")
async def program_detail(slug: str, session: SessionDep) -> dict[str, Any]:
    program = await _program_or_404(session, slug)
    payload = _program_payload(program)
    # The scope is included because it is what authorises every scan; anyone
    # reading findings should be able to see what was in bounds.
    payload["scope_yaml"] = program.scope_yaml
    payload["attestation"] = program.attestation
    return payload


@router.get("/programs/{slug}/assets")
async def assets(
    slug: str,
    session: SessionDep,
    live: Annotated[bool | None, Query(description="Filter by liveness")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    program = await _program_or_404(session, slug)
    query = select(Asset).where(Asset.program_id == program.id)
    if live is not None:
        query = query.where(Asset.is_live == live)
    rows = (
        await session.execute(query.order_by(Asset.host).offset(offset).limit(limit))
    ).scalars().all()

    return {
        "program": slug,
        "count": len(rows),
        "assets": [
            {
                "host": row.host,
                "kind": row.kind.value,
                "is_live": row.is_live,
                "http_status": row.http_status,
                "title": row.title,
                "server": row.server,
                "technologies": row.technologies,
                "resolved_values": row.resolved_values,
                "cname": row.cname,
                "sources": row.sources,
                "wildcard_cleared_by": row.wildcard_cleared_by,
                "first_seen": row.first_seen.isoformat(),
                "last_seen": row.last_seen.isoformat(),
            }
            for row in rows
        ],
    }


@router.get("/programs/{slug}/endpoints")
async def endpoints(
    slug: str,
    session: SessionDep,
    with_params: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    program = await _program_or_404(session, slug)
    query = select(Endpoint).where(Endpoint.program_id == program.id)
    rows = (
        await session.execute(
            query.order_by(Endpoint.interesting_score.desc()).offset(offset).limit(limit)
        )
    ).scalars().all()
    if with_params:
        rows = [row for row in rows if row.parameters]

    return {
        "program": slug,
        "count": len(rows),
        "endpoints": [
            {
                "url": row.url,
                "method": row.method,
                "status": row.status,
                "content_type": row.content_type,
                "title": row.title,
                "source": row.source,
                "parameters": row.parameters,
                "reflected_parameters": row.reflected_parameters,
                "interesting_score": row.interesting_score,
                "first_seen": row.first_seen.isoformat(),
            }
            for row in rows
        ],
    }


@router.get("/programs/{slug}/findings")
async def findings(
    slug: str,
    session: SessionDep,
    tier: Annotated[
        str | None,
        Query(description="confirmed, probable, needs_review or discarded"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    """Findings with their verification verdict.

    Without a tier filter, only what surfaced is returned. Pass
    ``tier=discarded`` to audit what the filter rejected and why.
    """
    program = await _program_or_404(session, slug)
    query = select(Finding).where(Finding.program_id == program.id)

    if tier:
        try:
            query = query.where(Finding.tier == FindingTier(tier))
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"unknown tier {tier!r}; use one of "
                + ", ".join(t.value for t in FindingTier),
            ) from exc
    else:
        query = query.where(
            Finding.tier.in_([FindingTier.CONFIRMED, FindingTier.PROBABLE])
        )

    rows = (
        await session.execute(
            query.order_by(Finding.priority.desc()).offset(offset).limit(limit)
        )
    ).scalars().all()

    payload: list[dict[str, Any]] = []
    for row in rows:
        evidence = (
            await session.execute(select(Evidence).where(Evidence.finding_id == row.id))
        ).scalars().all()
        payload.append(
            {
                "id": row.id,
                "vuln_class": row.vuln_class,
                "title": row.title,
                "severity": row.severity.value,
                "tier": row.tier.value,
                "confidence": row.confidence,
                "priority": row.priority,
                "description": row.description,
                "discard_reason": row.discard_reason,
                "signals": row.signals,
                "reproduced": f"{row.reproduced_count}/{row.attempt_count}",
                "tested_while_throttled": row.tested_while_throttled,
                "detector": row.detector,
                "affected_hosts": row.affected_hosts,
                "recommendation": row.recommendation,
                "first_seen": row.first_seen.isoformat(),
                "evidence": [
                    {
                        "label": item.label,
                        "request_url": item.request_url,
                        "response_status": item.response_status,
                        "curl_command": item.curl_command,
                        "note": item.note,
                    }
                    for item in evidence
                ],
            }
        )

    return {"program": slug, "count": len(payload), "findings": payload}


@router.get("/programs/{slug}/recommendations")
async def recommendations(
    slug: str,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> dict[str, Any]:
    """What to do next, ordered, with the reasoning."""
    from reconx.triage.recommend import recommend

    program = await _program_or_404(session, slug)
    actions = await recommend(session, program, limit=limit)
    return {
        "program": slug,
        "count": len(actions),
        "recommendations": [action.as_dict() for action in actions],
    }


@router.get("/programs/{slug}/observations")
async def observations(
    slug: str,
    session: SessionDep,
    kind: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> dict[str, Any]:
    program = await _program_or_404(session, slug)
    query = select(Observation).where(Observation.program_id == program.id)
    if kind:
        query = query.where(Observation.kind == kind)
    rows = (
        await session.execute(query.order_by(Observation.kind, Observation.key).limit(limit))
    ).scalars().all()
    return {
        "program": slug,
        "count": len(rows),
        "observations": [
            {"kind": r.kind, "key": r.key, "value": r.value, "source": r.source}
            for r in rows
        ],
    }


@router.get("/programs/{slug}/scans")
async def scans(
    slug: str, session: SessionDep, limit: Annotated[int, Query(ge=1, le=200)] = 20
) -> dict[str, Any]:
    program = await _program_or_404(session, slug)
    rows = (
        await session.execute(
            select(ScanRun)
            .where(ScanRun.program_id == program.id)
            .order_by(ScanRun.started_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return {
        "program": slug,
        "count": len(rows),
        "scans": [
            {
                "id": row.id,
                "status": row.status.value,
                "trigger": row.trigger,
                "stages_requested": row.stages_requested,
                "started_at": row.started_at.isoformat(),
                "finished_at": row.finished_at.isoformat() if row.finished_at else None,
                "requests_made": row.requests_made,
                "out_of_scope_blocked": row.out_of_scope_blocked,
                "summary": row.summary,
                "error": row.error,
            }
            for row in rows
        ],
    }


@router.get("/programs/{slug}/audit")
async def audit(
    slug: str,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
    blocked_only: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    """The request log, including refusals.

    This is the record of what was touched and when.
    """
    program = await _program_or_404(session, slug)
    query = select(AuditEntry).where(AuditEntry.program_id == program.id)
    if blocked_only:
        query = query.where(AuditEntry.blocked == True)  # noqa: E712
    rows = (
        await session.execute(query.order_by(AuditEntry.timestamp.desc()).limit(limit))
    ).scalars().all()
    return {
        "program": slug,
        "count": len(rows),
        "entries": [
            {
                "timestamp": r.timestamp.isoformat(),
                "method": r.method,
                "url": r.url,
                "status": r.status,
                "duration_ms": r.duration_ms,
                "blocked": r.blocked,
                "block_reason": r.block_reason,
                "matched_rule": r.matched_rule,
            }
            for r in rows
        ],
    }


@router.get("/programs/{slug}/report", response_class=PlainTextResponse)
async def report_markdown(
    slug: str,
    session: SessionDep,
    include_discarded: Annotated[bool, Query()] = False,
) -> PlainTextResponse:
    from reconx.report.markdown import build_markdown_report

    program = await _program_or_404(session, slug)
    text = await build_markdown_report(
        session, program, include_discarded=include_discarded
    )
    return PlainTextResponse(text, media_type="text/markdown; charset=utf-8")


@router.get("/programs/{slug}/report.html", response_class=HTMLResponse)
async def report_html(
    slug: str,
    session: SessionDep,
    include_discarded: Annotated[bool, Query()] = True,
) -> HTMLResponse:
    from reconx.report.html import build_html_report

    program = await _program_or_404(session, slug)
    html = await build_html_report(
        session, program, include_discarded=include_discarded
    )
    return HTMLResponse(html)


@router.get("/tools")
async def tools() -> dict[str, Any]:
    """Which external scanners are installed, and what is lost without each."""
    from reconx.scope.guard import ScopeGuard
    from reconx.scope.model import Scope
    from reconx.tools.registry import detect_all

    placeholder = Scope.model_validate(
        {
            "program": "tool detection",
            "authorization": {
                "authorized_by": "api",
                "date": "2000-01-01",
                "attestation": "tool detection only; no scanning is performed",
            },
            "in_scope": ["example.invalid"],
        }
    )
    statuses = await detect_all(ScopeGuard(placeholder))
    return {
        "count": len(statuses),
        "tools": [status.as_dict() for status in statuses.values()],
    }
