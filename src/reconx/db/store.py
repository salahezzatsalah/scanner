"""Data access helpers.

Stages talk to the database through these functions rather than writing queries
inline, for two reasons: upserts need to merge rather than clobber (an asset
found by three sources should record all three), and almost every write needs to
report **whether the row is new**. That boolean is what the diff engine turns
into "a new subdomain appeared four hours ago", which on a wildcard program is
the most valuable thing ReconX produces.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx.db.models import (
    Asset,
    AssetKind,
    AuditEntry,
    Baseline,
    BaselineKind,
    Endpoint,
    Evidence,
    Finding,
    FindingTier,
    Observation,
    Program,
    RunStatus,
    ScanRun,
    ScheduleEntry,
    Severity,
    StageRun,
    utcnow,
)
from reconx.scope.model import Scope

__all__ = [
    "upsert_program",
    "get_program",
    "list_programs",
    "upsert_asset",
    "upsert_endpoint",
    "record_observation",
    "save_baseline",
    "get_baselines",
    "upsert_finding",
    "add_evidence",
    "start_scan_run",
    "finish_scan_run",
    "start_stage_run",
    "finish_stage_run",
    "write_audit_entries",
    "upsert_schedule_entry",
]


async def _insert_or_reselect(session: AsyncSession, obj: Any, query) -> tuple[Any, bool]:
    """Insert a row, tolerating a concurrent insert of the same row.

    Stages at the same dependency level run concurrently in separate sessions,
    so two of them can propose the same host at the same moment. The loser of
    that race must find the winner's row rather than raising, so the insert runs
    in a savepoint that can be rolled back without losing the rest of the
    session's work.

    Returns ``(row, created)``.
    """
    try:
        async with session.begin_nested():
            session.add(obj)
            await session.flush()
    except IntegrityError:
        existing = (await session.execute(query)).scalars().first()
        if existing is None:
            raise
        return existing, False
    return obj, True


def _merge_unique(existing: Sequence[str] | None, incoming: Iterable[str] | None) -> list[str]:
    """Union two string lists, preserving first-seen order."""
    out: list[str] = list(existing or [])
    seen = set(out)
    for item in incoming or []:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# programs
# ---------------------------------------------------------------------------


async def upsert_program(session: AsyncSession, scope: Scope, scope_yaml: str) -> Program:
    """Create or update a program from a validated scope.

    The raw YAML is stored verbatim so the authorization in force at scan time
    is always recoverable.
    """
    existing = await get_program(session, scope.slug)
    if existing is None:
        program = Program(
            slug=scope.slug,
            name=scope.program,
            platform=scope.platform,
            program_url=scope.program_url,
            notes=scope.notes,
            scope_yaml=scope_yaml,
            authorized_by=scope.authorization.authorized_by,
            authorization_date=scope.authorization.date,
            attestation=scope.authorization.attestation,
            authorization_reference=scope.authorization.reference,
        )
        session.add(program)
        await session.flush()
        return program

    existing.name = scope.program
    existing.platform = scope.platform
    existing.program_url = scope.program_url
    existing.notes = scope.notes
    existing.scope_yaml = scope_yaml
    existing.authorized_by = scope.authorization.authorized_by
    existing.authorization_date = scope.authorization.date
    existing.attestation = scope.authorization.attestation
    existing.authorization_reference = scope.authorization.reference
    existing.updated_at = utcnow()
    session.add(existing)
    await session.flush()
    return existing


async def get_program(session: AsyncSession, slug: str) -> Program | None:
    result = await session.execute(select(Program).where(Program.slug == slug))
    return result.scalars().first()


async def list_programs(session: AsyncSession) -> list[Program]:
    result = await session.execute(select(Program).order_by(Program.name))
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# assets
# ---------------------------------------------------------------------------


async def upsert_asset(
    session: AsyncSession,
    program_id: int,
    host: str,
    *,
    kind: AssetKind = AssetKind.DOMAIN,
    sources: Iterable[str] | None = None,
    **fields: Any,
) -> tuple[Asset, bool]:
    """Create or refresh an asset. Returns ``(asset, is_new)``.

    ``sources`` accumulates rather than overwrites: knowing that three
    independent sources saw a host is a confidence signal worth keeping.
    """
    query = select(Asset).where(Asset.program_id == program_id, Asset.host == host)
    asset = (await session.execute(query)).scalars().first()
    now = utcnow()

    if asset is None:
        candidate = Asset(
            program_id=program_id,
            host=host,
            kind=kind,
            sources=_merge_unique([], sources),
            first_seen=now,
            last_seen=now,
            **fields,
        )
        asset, created = await _insert_or_reselect(session, candidate, query)
        if created:
            return asset, True

    asset.sources = _merge_unique(asset.sources, sources)
    asset.last_seen = now
    for key, value in fields.items():
        if value is not None:
            setattr(asset, key, value)
    session.add(asset)
    await session.flush()
    return asset, False


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------


async def upsert_endpoint(
    session: AsyncSession,
    program_id: int,
    url: str,
    *,
    method: str = "GET",
    asset_id: int | None = None,
    parameters: Iterable[str] | None = None,
    **fields: Any,
) -> tuple[Endpoint, bool]:
    """Create or refresh an endpoint. Returns ``(endpoint, is_new)``."""
    query = select(Endpoint).where(
        Endpoint.program_id == program_id,
        Endpoint.url == url,
        Endpoint.method == method,
    )
    endpoint = (await session.execute(query)).scalars().first()
    now = utcnow()

    if endpoint is None:
        candidate = Endpoint(
            program_id=program_id,
            asset_id=asset_id,
            url=url,
            method=method,
            parameters=_merge_unique([], parameters),
            first_seen=now,
            last_seen=now,
            **fields,
        )
        endpoint, created = await _insert_or_reselect(session, candidate, query)
        if created:
            return endpoint, True

    endpoint.parameters = _merge_unique(endpoint.parameters, parameters)
    endpoint.last_seen = now
    if asset_id is not None:
        endpoint.asset_id = asset_id
    for key, value in fields.items():
        if value is not None:
            setattr(endpoint, key, value)
    session.add(endpoint)
    await session.flush()
    return endpoint, False


# ---------------------------------------------------------------------------
# observations
# ---------------------------------------------------------------------------


async def record_observation(
    session: AsyncSession,
    program_id: int,
    *,
    kind: str,
    key: str,
    value: str,
    asset_id: int | None = None,
    source: str = "",
) -> tuple[Observation, bool]:
    """Store an information-gathering fact, deduplicated on (kind, key, value)."""
    query = select(Observation).where(
        Observation.program_id == program_id,
        Observation.kind == kind,
        Observation.key == key,
        Observation.value == value,
    )
    observation = (await session.execute(query)).scalars().first()
    if observation is None:
        candidate = Observation(
            program_id=program_id,
            asset_id=asset_id,
            kind=kind,
            key=key,
            value=value,
            source=source,
        )
        observation, created = await _insert_or_reselect(session, candidate, query)
        if created:
            return observation, True

    observation.last_seen = utcnow()
    session.add(observation)
    await session.flush()
    return observation, False


# ---------------------------------------------------------------------------
# baselines
# ---------------------------------------------------------------------------


async def save_baseline(
    session: AsyncSession,
    program_id: int,
    host: str,
    kind: BaselineKind,
    *,
    fingerprint: Any = None,
    sample_url: str | None = None,
    path_scope: str = "/",
    **fields: Any,
) -> Baseline:
    """Record a reference response for a host.

    Pass a :class:`~reconx.net.fingerprint.ResponseFingerprint` as
    ``fingerprint`` and its fields are unpacked automatically.
    """
    payload: dict[str, Any] = dict(fields)
    if fingerprint is not None:
        payload.update(
            status=fingerprint.status,
            simhash=f"{fingerprint.simhash_value:016x}",
            sha256=fingerprint.body_sha256,
            length_band=fingerprint.length_band,
            body_length=fingerprint.body_length,
            word_count=fingerprint.word_count,
            title=fingerprint.title,
            content_type=fingerprint.content_type,
            header_names=list(fingerprint.header_names),
        )

    baseline = Baseline(
        program_id=program_id,
        host=host,
        kind=kind,
        sample_url=sample_url,
        path_scope=path_scope,
        **payload,
    )
    session.add(baseline)
    await session.flush()
    return baseline


async def get_baselines(
    session: AsyncSession,
    program_id: int,
    host: str,
    *,
    kind: BaselineKind | None = None,
    path_scope: str | None = None,
) -> list[Baseline]:
    query = select(Baseline).where(Baseline.program_id == program_id, Baseline.host == host)
    if kind is not None:
        query = query.where(Baseline.kind == kind)
    if path_scope is not None:
        query = query.where(Baseline.path_scope == path_scope)
    result = await session.execute(query.order_by(Baseline.created_at.desc()))
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


async def upsert_finding(
    session: AsyncSession,
    program_id: int,
    *,
    dedup_key: str,
    vuln_class: str,
    title: str,
    severity: Severity = Severity.INFO,
    tier: FindingTier = FindingTier.NEEDS_REVIEW,
    affected_hosts: Iterable[str] | None = None,
    signals: Iterable[str] | None = None,
    **fields: Any,
) -> tuple[Finding, bool]:
    """Create or update a finding, correlated on ``dedup_key``.

    One issue affecting fifty hosts becomes one row with fifty entries in
    ``affected_hosts``, not fifty findings. That collapse is the difference
    between a usable report and a wall of duplicates.
    """
    result = await session.execute(
        select(Finding).where(
            Finding.program_id == program_id, Finding.dedup_key == dedup_key
        )
    )
    finding = result.scalars().first()
    now = utcnow()

    if finding is None:
        finding = Finding(
            program_id=program_id,
            dedup_key=dedup_key,
            vuln_class=vuln_class,
            title=title,
            severity=severity,
            tier=tier,
            affected_hosts=_merge_unique([], affected_hosts),
            signals=_merge_unique([], signals),
            first_seen=now,
            last_seen=now,
            **fields,
        )
        session.add(finding)
        await session.flush()
        return finding, True

    finding.last_seen = now
    finding.tier = tier
    finding.severity = severity
    finding.title = title
    finding.affected_hosts = _merge_unique(finding.affected_hosts, affected_hosts)
    finding.signals = _merge_unique(finding.signals, signals)
    for key, value in fields.items():
        if value is not None:
            setattr(finding, key, value)
    session.add(finding)
    await session.flush()
    return finding, False


async def add_evidence(
    session: AsyncSession, finding_id: int, **fields: Any
) -> Evidence:
    """Attach proof to a finding."""
    evidence = Evidence(finding_id=finding_id, **fields)
    session.add(evidence)
    await session.flush()
    return evidence


# ---------------------------------------------------------------------------
# run bookkeeping
# ---------------------------------------------------------------------------


async def start_scan_run(
    session: AsyncSession,
    program_id: int,
    *,
    stages: Sequence[str],
    trigger: str = "manual",
) -> ScanRun:
    run = ScanRun(
        program_id=program_id,
        status=RunStatus.RUNNING,
        trigger=trigger,
        stages_requested=list(stages),
    )
    session.add(run)
    await session.flush()
    return run


async def finish_scan_run(
    session: AsyncSession,
    run: ScanRun,
    *,
    status: RunStatus,
    error: str | None = None,
    summary: dict[str, Any] | None = None,
    requests_made: int = 0,
    dns_queries: int = 0,
    out_of_scope_blocked: int = 0,
) -> ScanRun:
    run.status = status
    run.finished_at = utcnow()
    run.error = error
    run.summary = summary or {}
    run.requests_made = requests_made
    run.dns_queries = dns_queries
    run.out_of_scope_blocked = out_of_scope_blocked
    session.add(run)
    await session.flush()
    return run


async def start_stage_run(
    session: AsyncSession, scan_run_id: int, program_id: int, stage: str
) -> StageRun:
    """Begin a stage, reusing the row if this run is being resumed."""
    result = await session.execute(
        select(StageRun).where(
            StageRun.scan_run_id == scan_run_id, StageRun.stage == stage
        )
    )
    stage_run = result.scalars().first()
    if stage_run is None:
        stage_run = StageRun(scan_run_id=scan_run_id, program_id=program_id, stage=stage)
    stage_run.status = RunStatus.RUNNING
    stage_run.started_at = utcnow()
    stage_run.error = None
    session.add(stage_run)
    await session.flush()
    return stage_run


async def finish_stage_run(
    session: AsyncSession,
    stage_run: StageRun,
    *,
    status: RunStatus,
    items_in: int = 0,
    items_out: int = 0,
    items_filtered: int = 0,
    filter_reasons: dict[str, Any] | None = None,
    tools_used: Sequence[str] | None = None,
    error: str | None = None,
    checkpoint: dict[str, Any] | None = None,
) -> StageRun:
    stage_run.status = status
    stage_run.finished_at = utcnow()
    stage_run.items_in = items_in
    stage_run.items_out = items_out
    stage_run.items_filtered = items_filtered
    stage_run.filter_reasons = filter_reasons or {}
    stage_run.tools_used = list(tools_used or [])
    stage_run.error = error
    if checkpoint is not None:
        stage_run.checkpoint = checkpoint
    session.add(stage_run)
    await session.flush()
    return stage_run


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


async def write_audit_entries(
    session: AsyncSession,
    records: Iterable[Any],
    *,
    program_id: int | None = None,
    scan_run_id: int | None = None,
) -> int:
    """Persist :class:`~reconx.net.http.AuditRecord` objects. Returns the count."""
    count = 0
    for record in records:
        session.add(
            AuditEntry(
                program_id=program_id,
                scan_run_id=scan_run_id,
                timestamp=record.timestamp,
                method=record.method,
                url=record.url,
                host=record.host,
                status=record.status,
                duration_ms=record.duration_ms,
                response_bytes=record.response_bytes,
                error=record.error,
                matched_rule=record.matched_rule,
                blocked=record.blocked,
                block_reason=record.block_reason,
            )
        )
        count += 1
    if count:
        await session.flush()
    return count


# ---------------------------------------------------------------------------
# scheduling
# ---------------------------------------------------------------------------


async def upsert_schedule_entry(
    session: AsyncSession,
    program_id: int,
    stage: str,
    *,
    interval_seconds: int,
    enabled: bool = True,
    next_run_at: datetime | None = None,
) -> tuple[ScheduleEntry, bool]:
    result = await session.execute(
        select(ScheduleEntry).where(
            ScheduleEntry.program_id == program_id, ScheduleEntry.stage == stage
        )
    )
    entry = result.scalars().first()
    if entry is None:
        entry = ScheduleEntry(
            program_id=program_id,
            stage=stage,
            interval_seconds=interval_seconds,
            enabled=enabled,
            next_run_at=next_run_at or datetime.now(UTC),
        )
        session.add(entry)
        await session.flush()
        return entry, True

    entry.interval_seconds = interval_seconds
    entry.enabled = enabled
    if next_run_at is not None:
        entry.next_run_at = next_run_at
    session.add(entry)
    await session.flush()
    return entry, False
