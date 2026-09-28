"""JSON export.

The machine-readable form of a report, for feeding a dashboard, diffing two
points in time, or archiving alongside a submission. Discarded findings are
included by default here, unlike the human reports: an archive that drops them
loses the record of what was considered and rejected.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx import __version__
from reconx.db.models import (
    Asset,
    Endpoint,
    Evidence,
    Finding,
    FindingTier,
    Observation,
    Program,
    ScanRun,
    StageRun,
)

__all__ = ["build_json_report", "dump_json_report"]


def _iso(value: datetime | date | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.isoformat()
    return value.isoformat()


async def build_json_report(
    session: AsyncSession, program: Program, *, include_discarded: bool = True
) -> dict[str, Any]:
    """Build the full export as a plain dictionary."""
    assets = list(
        (
            await session.execute(
                select(Asset).where(Asset.program_id == program.id).order_by(Asset.host)
            )
        ).scalars().all()
    )
    endpoints = list(
        (
            await session.execute(
                select(Endpoint)
                .where(Endpoint.program_id == program.id)
                .order_by(Endpoint.interesting_score.desc())
            )
        ).scalars().all()
    )
    findings = list(
        (
            await session.execute(
                select(Finding)
                .where(Finding.program_id == program.id)
                .order_by(Finding.priority.desc())
            )
        ).scalars().all()
    )
    observations = list(
        (
            await session.execute(
                select(Observation).where(Observation.program_id == program.id)
            )
        ).scalars().all()
    )
    runs = list(
        (
            await session.execute(
                select(ScanRun)
                .where(ScanRun.program_id == program.id)
                .order_by(ScanRun.started_at.desc())
                .limit(20)
            )
        ).scalars().all()
    )

    finding_payload: list[dict[str, Any]] = []
    for finding in findings:
        if not include_discarded and finding.tier is FindingTier.DISCARDED:
            continue
        evidence = list(
            (
                await session.execute(
                    select(Evidence).where(Evidence.finding_id == finding.id)
                )
            ).scalars().all()
        )
        finding_payload.append(
            {
                "vuln_class": finding.vuln_class,
                "title": finding.title,
                "severity": finding.severity.value,
                "tier": finding.tier.value,
                "confidence": finding.confidence,
                "priority": finding.priority,
                "description": finding.description,
                "discard_reason": finding.discard_reason,
                "signals": finding.signals,
                "reproduced_count": finding.reproduced_count,
                "attempt_count": finding.attempt_count,
                "tested_while_throttled": finding.tested_while_throttled,
                "detector": finding.detector,
                "dedup_key": finding.dedup_key,
                "affected_hosts": finding.affected_hosts,
                "recommendation": finding.recommendation,
                "triage_status": finding.triage_status,
                "first_seen": _iso(finding.first_seen),
                "last_seen": _iso(finding.last_seen),
                "evidence": [
                    {
                        "kind": item.kind,
                        "label": item.label,
                        "request_method": item.request_method,
                        "request_url": item.request_url,
                        "response_status": item.response_status,
                        "response_excerpt": item.response_excerpt,
                        "curl_command": item.curl_command,
                        "note": item.note,
                    }
                    for item in evidence
                ],
            }
        )

    stage_summary: list[dict[str, Any]] = []
    if runs:
        stage_rows = list(
            (
                await session.execute(
                    select(StageRun).where(StageRun.scan_run_id == runs[0].id)
                )
            ).scalars().all()
        )
        stage_summary = [
            {
                "stage": row.stage,
                "status": row.status.value,
                "items_in": row.items_in,
                "items_out": row.items_out,
                "items_filtered": row.items_filtered,
                "filter_reasons": row.filter_reasons,
                "tools_used": row.tools_used,
                "error": row.error,
            }
            for row in stage_rows
        ]

    return {
        "reconx_version": __version__,
        "generated_at": _iso(datetime.now(UTC)),
        "program": {
            "slug": program.slug,
            "name": program.name,
            "platform": program.platform,
            "program_url": program.program_url,
            "authorized_by": program.authorized_by,
            "authorization_date": _iso(program.authorization_date),
            "attestation": program.attestation,
            "scope_yaml": program.scope_yaml,
            "monitoring_enabled": program.monitoring_enabled,
        },
        "totals": {
            "assets": len(assets),
            "live_assets": len([a for a in assets if a.is_live]),
            "endpoints": len(endpoints),
            "findings_surfaced": len(
                [
                    f
                    for f in findings
                    if f.tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE)
                ]
            ),
            "findings_confirmed": len(
                [f for f in findings if f.tier is FindingTier.CONFIRMED]
            ),
            "findings_discarded": len(
                [f for f in findings if f.tier is FindingTier.DISCARDED]
            ),
        },
        "findings": finding_payload,
        "assets": [
            {
                "host": row.host,
                "kind": row.kind.value,
                "is_live": row.is_live,
                "http_status": row.http_status,
                "scheme": row.scheme,
                "port": row.port,
                "title": row.title,
                "server": row.server,
                "technologies": row.technologies,
                "resolved_values": row.resolved_values,
                "cname": row.cname,
                "sources": row.sources,
                "wildcard_suspect": row.wildcard_suspect,
                "wildcard_cleared_by": row.wildcard_cleared_by,
                "tls_issuer": row.tls_issuer,
                "tls_not_after": _iso(row.tls_not_after),
                "first_seen": _iso(row.first_seen),
                "last_seen": _iso(row.last_seen),
            }
            for row in assets
        ],
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
                "first_seen": _iso(row.first_seen),
            }
            for row in endpoints
        ],
        "observations": [
            {
                "kind": row.kind,
                "key": row.key,
                "value": row.value,
                "source": row.source,
                "first_seen": _iso(row.first_seen),
            }
            for row in observations
        ],
        "scans": [
            {
                "id": row.id,
                "status": row.status.value,
                "trigger": row.trigger,
                "stages_requested": row.stages_requested,
                "started_at": _iso(row.started_at),
                "finished_at": _iso(row.finished_at),
                "requests_made": row.requests_made,
                "dns_queries": row.dns_queries,
                "out_of_scope_blocked": row.out_of_scope_blocked,
                "error": row.error,
            }
            for row in runs
        ],
        "last_run_stages": stage_summary,
    }


async def dump_json_report(
    session: AsyncSession, program: Program, *, include_discarded: bool = True, indent: int = 2
) -> str:
    payload = await build_json_report(
        session, program, include_discarded=include_discarded
    )
    return json.dumps(payload, indent=indent, ensure_ascii=False, default=str)
