"""Continuous operation.

Different stages deserve different cadences. Liveness changes hourly, subdomains
appear daily, and a full vulnerability sweep is a weekly job. Running everything
on one schedule means either hammering the target or missing the thing that
matters, so each stage carries its own interval per program.

The loop is deliberately a poll rather than one registered job per stage: a
schedule that changes while the service is running takes effect on the next tick
without anything being re-registered, and a service restart picks up exactly
where it left off because the next run time lives in the database.

Only one scan runs per program at a time. Overlapping runs on one target would
multiply the request rate that the scope's limits are supposed to cap.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlmodel import select

from reconx.config import Settings, get_settings
from reconx.db.models import Program, RunStatus, ScheduleEntry
from reconx.db.session import get_session_factory
from reconx.db.store import upsert_schedule_entry
from reconx.monitor.diff import build_notification, detect_changes
from reconx.notify.base import Notification, NotifierHub, Urgency, build_notifiers
from reconx.orchestrator import STAGE_REGISTRY, Orchestrator
from reconx.scope.model import Scope

__all__ = ["DEFAULT_CADENCES", "MonitorService", "TickReport"]

# Seconds between runs, per stage. Chosen so the cheap checks are frequent and
# the expensive ones are not.
DEFAULT_CADENCES: dict[str, int] = {
    "resolve_probe": 3_600,      # hourly: is it still up, did anything change
    "subdomains": 86_400,        # daily: new hosts are the highest-value signal
    "content": 86_400,           # daily
    "passive_recon": 604_800,    # weekly: registration data moves slowly
    "params": 604_800,           # weekly
    "vulns": 604_800,            # weekly: the most expensive, and the noisiest
}


@dataclass
class TickReport:
    """What one cycle of the loop did."""

    started: datetime
    programs_run: list[str] = field(default_factory=list)
    stages_run: dict[str, list[str]] = field(default_factory=dict)
    notifications_sent: int = 0
    changes_found: int = 0
    errors: dict[str, str] = field(default_factory=dict)
    skipped_busy: list[str] = field(default_factory=list)

    @property
    def idle(self) -> bool:
        return not self.programs_run and not self.skipped_busy

    def as_dict(self) -> dict:
        return {
            "started": self.started.isoformat(),
            "programs_run": list(self.programs_run),
            "stages_run": dict(self.stages_run),
            "notifications_sent": self.notifications_sent,
            "changes_found": self.changes_found,
            "errors": dict(self.errors),
            "skipped_busy": list(self.skipped_busy),
        }


class MonitorService:
    """Polls for due work, runs it, and reports what changed."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        tick_seconds: int = 60,
        notifiers: NotifierHub | None = None,
        use_external_tools: bool = True,
    ) -> None:
        self._settings = settings or get_settings()
        self._tick_seconds = max(10, tick_seconds)
        self._notifiers = notifiers or build_notifiers(self._settings)
        self._use_external_tools = use_external_tools
        self._scheduler: AsyncIOScheduler | None = None
        self._running: set[str] = set()
        self.ticks = 0
        self.last_report: TickReport | None = None

    @property
    def notifier_channels(self) -> list[str]:
        return self._notifiers.channels

    # -- schedule setup ----------------------------------------------------

    async def ensure_schedules(
        self, program: Program, *, cadences: dict[str, int] | None = None
    ) -> list[ScheduleEntry]:
        """Create any missing schedule rows for a program, using the defaults."""
        chosen = {**DEFAULT_CADENCES, **(cadences or {})}
        factory = get_session_factory(self._settings)
        created: list[ScheduleEntry] = []

        async with factory() as session:
            for stage, interval in chosen.items():
                if stage not in STAGE_REGISTRY:
                    continue
                entry, _ = await upsert_schedule_entry(
                    session, program.id, stage, interval_seconds=interval
                )
                created.append(entry)
            await session.commit()
        return created

    # -- the loop ----------------------------------------------------------

    async def tick(self) -> TickReport:
        """One cycle: find due work, run it, report changes."""
        self.ticks += 1
        report = TickReport(started=datetime.now(UTC))
        due = await self._due_work()

        for slug, (program_id, stages) in due.items():
            if slug in self._running:
                report.skipped_busy.append(slug)
                continue
            self._running.add(slug)
            try:
                await self._run_for_program(slug, program_id, stages, report)
            except Exception as exc:
                report.errors[slug] = f"{type(exc).__name__}: {exc}"
            finally:
                self._running.discard(slug)

        self.last_report = report
        return report

    async def _due_work(self) -> dict[str, tuple[int, list[str]]]:
        """Programs with at least one stage due, and which stages those are."""
        now = datetime.now(UTC)
        factory = get_session_factory(self._settings)
        grouped: dict[str, tuple[int, list[str]]] = {}

        async with factory() as session:
            programs = {
                program.id: program
                for program in (
                    await session.execute(
                        select(Program).where(Program.monitoring_enabled == True)  # noqa: E712
                    )
                ).scalars().all()
            }
            if not programs:
                return {}

            entries = (
                await session.execute(
                    select(ScheduleEntry).where(
                        ScheduleEntry.enabled == True,  # noqa: E712
                        ScheduleEntry.program_id.in_(list(programs)),
                    )
                )
            ).scalars().all()

            by_program: dict[int, list[str]] = defaultdict(list)
            for entry in entries:
                next_run = entry.next_run_at
                if next_run is not None and next_run.tzinfo is None:
                    next_run = next_run.replace(tzinfo=UTC)
                if next_run is None or next_run <= now:
                    by_program[entry.program_id].append(entry.stage)

            for program_id, stages in by_program.items():
                program = programs[program_id]
                grouped[program.slug] = (program_id, sorted(stages))

        return grouped

    async def _run_for_program(
        self, slug: str, program_id: int, stages: list[str], report: TickReport
    ) -> None:
        """Run the due stages for one program, then diff and notify."""
        factory = get_session_factory(self._settings)

        async with factory() as session:
            program = (
                await session.execute(select(Program).where(Program.id == program_id))
            ).scalars().first()
            if program is None:
                return
            scope_yaml = program.scope_yaml
            program_name = program.name
            # The window to diff against is the oldest due stage's last run, so a
            # weekly stage firing reports everything since that stage last ran.
            entries = (
                await session.execute(
                    select(ScheduleEntry).where(
                        ScheduleEntry.program_id == program_id,
                        ScheduleEntry.stage.in_(stages),
                    )
                )
            ).scalars().all()
            last_runs = [entry.last_run_at for entry in entries if entry.last_run_at]
            since = min(last_runs) if last_runs else datetime.now(UTC) - timedelta(
                days=1
            )
            if since.tzinfo is None:
                since = since.replace(tzinfo=UTC)

        try:
            scope = _scope_from_yaml(scope_yaml)
        except Exception as exc:
            report.errors[slug] = f"stored scope is no longer valid: {exc}"
            await self._mark_failure(program_id, stages)
            return

        orchestrator = Orchestrator(
            scope,
            scope_yaml=scope_yaml,
            settings=self._settings,
            use_external_tools=self._use_external_tools,
        )
        summary = await orchestrator.run(stages, trigger="scheduled")

        report.programs_run.append(slug)
        report.stages_run[slug] = list(stages)
        if summary.error:
            report.errors[slug] = summary.error

        # --- diff and notify ----------------------------------------------
        async with factory() as session:
            program = (
                await session.execute(select(Program).where(Program.id == program_id))
            ).scalars().first()
            changes = await detect_changes(session, program, since)

        report.changes_found += len(changes.changes)
        notification = build_notification(changes)
        if notification is not None and self._notifiers.enabled:
            results = await self._notifiers.broadcast(notification)
            report.notifications_sent += sum(1 for ok in results.values() if ok)

        if summary.error and self._notifiers.enabled:
            await self._notifiers.broadcast(
                Notification(
                    title="Scheduled scan reported an error",
                    program=program_name,
                    urgency=Urgency.NOTABLE,
                    lines=[summary.error[:500]],
                )
            )

        await self._mark_success(program_id, stages, summary.status)

    # -- schedule bookkeeping ----------------------------------------------

    async def _mark_success(
        self, program_id: int, stages: list[str], status: RunStatus
    ) -> None:
        now = datetime.now(UTC)
        factory = get_session_factory(self._settings)
        async with factory() as session:
            entries = (
                await session.execute(
                    select(ScheduleEntry).where(
                        ScheduleEntry.program_id == program_id,
                        ScheduleEntry.stage.in_(stages),
                    )
                )
            ).scalars().all()
            for entry in entries:
                entry.last_run_at = now
                entry.last_status = status
                entry.next_run_at = now + timedelta(seconds=entry.interval_seconds)
                entry.consecutive_failures = (
                    0 if status is RunStatus.COMPLETED else entry.consecutive_failures + 1
                )
                # Back off a stage that keeps failing rather than retrying on the
                # same cadence forever.
                if entry.consecutive_failures >= 3:
                    entry.next_run_at = now + timedelta(
                        seconds=min(entry.interval_seconds * 4, 86_400)
                    )
                session.add(entry)
            await session.commit()

    async def _mark_failure(self, program_id: int, stages: list[str]) -> None:
        await self._mark_success(program_id, stages, RunStatus.FAILED)

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        """Begin polling. Returns immediately; the loop runs in the background."""
        if self._scheduler is not None:
            return
        self._scheduler = AsyncIOScheduler(timezone="UTC")
        self._scheduler.add_job(
            self._safe_tick,
            "interval",
            seconds=self._tick_seconds,
            id="reconx-monitor-tick",
            max_instances=1,
            coalesce=True,
            next_run_time=datetime.now(UTC),
        )
        self._scheduler.start()

    async def _safe_tick(self) -> None:
        with contextlib.suppress(Exception):
            await self.tick()

    async def stop(self) -> None:
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None

    async def run_forever(self) -> None:
        """Start and block until cancelled."""
        await self.start()
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            await self.stop()
            raise


def _scope_from_yaml(text: str) -> Scope:
    import yaml

    payload = yaml.safe_load(text)
    if not isinstance(payload, dict):
        raise ValueError("stored scope is not a YAML mapping")
    return Scope.model_validate(payload)
