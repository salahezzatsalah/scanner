"""Pipeline orchestration.

Stages declare what they depend on; the orchestrator works out the order, runs
independent stages together, and records enough state that an interrupted run
can be resumed rather than restarted. On a long wildcard-program scan, restarting
from zero because of one network blip is the difference between a tool you leave
running and one you babysit.

Failure is contained: a stage that fails does not abort the run, but stages that
depend on it are skipped with that reason recorded, because running them on
missing input produces confident nonsense.

Stages are built from the scope's own ``scan_options`` block unless the caller
supplies instances. That is what makes a scheduled scan the same scan as a manual
one: the CLI, the REST API and the monitor all reach the orchestrator, and before
this the last two had no way to pass anything, so a program under 24/7 monitoring
ran with built-in wordlists and every default no matter what its operator wanted.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlmodel import select

from reconx.config import Settings, get_settings
from reconx.db.models import RunStatus, ScanRun, StageRun
from reconx.db.session import get_session_factory
from reconx.db.store import (
    finish_scan_run,
    finish_stage_run,
    start_scan_run,
    start_stage_run,
    upsert_program,
    write_audit_entries,
)
from reconx.net.dns import ScopedResolver
from reconx.net.http import ScopedHttpClient
from reconx.net.sources import SourceClient
from reconx.scope.guard import ScopeGuard
from reconx.scope.model import ScanOptions, Scope
from reconx.stages.base import Stage, StageContext, StageResult
from reconx.stages.content import ContentStage
from reconx.stages.params import ParamStage
from reconx.stages.passive_recon import PassiveReconStage
from reconx.stages.ports import PortStage
from reconx.stages.resolve_probe import ResolveProbeStage
from reconx.stages.subdomains import SubdomainStage
from reconx.stages.vulns import VulnStage
from reconx.verify.session import SessionMonitor

__all__ = [
    "STAGE_REGISTRY",
    "STAGE_GROUPS",
    "Orchestrator",
    "ProgressEvent",
    "build_stage",
    "RunSummary",
    "plan_stages",
    "resolve_stage_names",
    "StagePlanError",
]


@dataclass
class ProgressEvent:
    """One realtime update from a running pipeline.

    Emitted only when the orchestrator was given a ``progress`` callback;
    without one the run is silent exactly as before. ``kind`` is one of
    ``run_started``, ``stage_started``, ``stage_finished``, ``heartbeat`` or
    ``run_finished``. Counters are cumulative for the run; ``findings`` holds
    every surfaced finding label so far.
    """

    kind: str
    stage: str = ""
    status: str = ""
    detail: str = ""
    requests_made: int = 0
    tool_requests: int = 0
    dns_queries: int = 0
    findings: list[str] = field(default_factory=list)
    at: float = field(default_factory=time.monotonic)

#: A sink for :class:`ProgressEvent`. Synchronous on purpose: it is called
#: from the run loop, and anything it needs to await would serialize the scan
#: behind the display. The CLI updates a Rich live view, which is cheap.
ProgressCallback = Callable[[ProgressEvent], None]


class StagePlanError(ValueError):
    """A requested stage set cannot be ordered."""


STAGE_REGISTRY: dict[str, type[Stage]] = {
    PassiveReconStage.name: PassiveReconStage,
    SubdomainStage.name: SubdomainStage,
    ResolveProbeStage.name: ResolveProbeStage,
    ContentStage.name: ContentStage,
    PortStage.name: PortStage,
    ParamStage.name: ParamStage,
    VulnStage.name: VulnStage,
}

# Convenience names for the CLI.
STAGE_GROUPS: dict[str, tuple[str, ...]] = {
    "recon": ("passive_recon", "subdomains", "resolve_probe"),
    "passive": ("passive_recon",),
    "discover": ("passive_recon", "subdomains", "resolve_probe", "content", "ports"),
    "vulns": ("vulns",),
    "all": tuple(STAGE_REGISTRY),
    "full": tuple(STAGE_REGISTRY),
}


def build_stage(name: str, options: ScanOptions) -> Stage | None:
    """Construct one stage from a program's persisted scan options.

    Returns None for a stage that takes no options, so the caller can fall back
    to a plain constructor. Keeping this a function rather than a method means the
    API, the scheduler and the CLI all produce the same stage from the same block
    instead of three near-identical constructions that drift.
    """
    if name == PassiveReconStage.name:
        return PassiveReconStage()
    if name == SubdomainStage.name:
        return SubdomainStage(
            wordlist_path=options.subdomain_wordlist,
            brute_force=options.brute_force_subdomains,
        )
    if name == ResolveProbeStage.name:
        return (
            ResolveProbeStage(ports=tuple(options.ports))
            if options.ports
            else ResolveProbeStage()
        )
    if name == ContentStage.name:
        return ContentStage(
            wordlist_path=options.path_wordlist,
            crawl=options.crawl,
            archives=options.archives,
            brute_force=options.brute_force_paths,
        )
    if name == ParamStage.name:
        return ParamStage(
            wordlist_path=options.parameter_wordlist,
            guess_hidden=options.guess_parameters,
        )
    if name == VulnStage.name:
        skipped = set(options.skip_checks)
        return VulnStage(
            run_nuclei=options.run_nuclei,
            enable_timing=options.enable_timing,
            headless_xss=options.headless_xss,
            check_sqli="sqli" not in skipped,
            check_xss="xss" not in skipped,
            check_redirect="redirect" not in skipped,
            check_cors="cors" not in skipped,
            check_traversal="traversal" not in skipped,
            check_ssti="ssti" not in skipped,
            check_cmdi="cmdi" not in skipped,
            check_deser="deser" not in skipped,
            check_ssrf="ssrf" not in skipped,
        )
    return None


def resolve_stage_names(requested: Sequence[str] | None) -> list[str]:
    """Expand group names and validate stage names.

    Dependencies are pulled in automatically: asking for ``resolve_probe`` gets
    you ``subdomains`` too, because probing an empty host list is not a result.
    """
    if not requested:
        names = list(STAGE_GROUPS["recon"])
    else:
        names = []
        for entry in requested:
            key = entry.strip().lower()
            if key in STAGE_GROUPS:
                names.extend(STAGE_GROUPS[key])
            elif key in STAGE_REGISTRY:
                names.append(key)
            else:
                raise StagePlanError(
                    f"unknown stage {entry!r}. Stages: {', '.join(sorted(STAGE_REGISTRY))}. "
                    f"Groups: {', '.join(sorted(STAGE_GROUPS))}"
                )

    # Pull in dependencies transitively.
    needed: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        if name in seen:
            return
        seen.add(name)
        for dependency in STAGE_REGISTRY[name].requires:
            if dependency in STAGE_REGISTRY:
                add(dependency)
        needed.append(name)

    for name in names:
        add(name)
    return needed


def plan_stages(names: Sequence[str]) -> list[list[str]]:
    """Group stages into levels that can each run concurrently."""
    remaining = {
        name: {
            dependency
            for dependency in STAGE_REGISTRY[name].requires
            if dependency in names
        }
        for name in names
    }
    levels: list[list[str]] = []

    while remaining:
        ready = sorted(name for name, deps in remaining.items() if not deps)
        if not ready:
            raise StagePlanError(
                "stage dependencies form a cycle among: " + ", ".join(sorted(remaining))
            )
        levels.append(ready)
        for name in ready:
            del remaining[name]
        for deps in remaining.values():
            deps.difference_update(ready)
    return levels


@dataclass
class RunSummary:
    """The outcome of one pipeline run."""

    scan_run_id: int
    program_slug: str
    status: RunStatus
    stages: dict[str, StageResult] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)
    requests_made: int = 0
    tool_requests: int = 0
    dns_queries: int = 0
    out_of_scope_blocked: int = 0
    source_calls: int = 0
    error: str | None = None
    #: Run-level observations that belong to no single stage, such as the state of
    #: the session the scan ran under.
    notes: list[str] = field(default_factory=list)
    session: dict[str, Any] = field(default_factory=dict)

    @property
    def new_assets(self) -> list[str]:
        out: list[str] = []
        for result in self.stages.values():
            out.extend(result.new_assets)
        return sorted(set(out))

    @property
    def new_endpoints(self) -> list[str]:
        out: list[str] = []
        for result in self.stages.values():
            out.extend(result.new_endpoints)
        return sorted(set(out))

    @property
    def findings(self) -> list[str]:
        """Findings that surfaced, most severe first."""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        def rank(label: str) -> tuple[int, int, str]:
            severity = next((key for key in order if f"{key}:" in label), "INFO")
            confirmed = 0 if label.startswith("CONFIRMED") else 1
            return (order[severity], confirmed, label)

        out: list[str] = []
        for result in self.stages.values():
            out.extend(result.new_findings)
        return sorted(set(out), key=rank)

    @property
    def total_filtered(self) -> int:
        return sum(result.items_filtered for result in self.stages.values())

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_run_id": self.scan_run_id,
            "program": self.program_slug,
            "status": self.status.value,
            "requests_made": self.requests_made,
            "tool_requests": self.tool_requests,
            "dns_queries": self.dns_queries,
            "out_of_scope_blocked": self.out_of_scope_blocked,
            "source_calls": self.source_calls,
            "new_assets": self.new_assets,
            "new_endpoints": self.new_endpoints,
            "findings": self.findings,
            "total_filtered": self.total_filtered,
            "stages": {name: result.as_dict() for name, result in self.stages.items()},
            "skipped": dict(self.skipped),
            "notes": list(self.notes),
            # The session state, never the credential: SessionMonitor.summary()
            # reports whether one was configured and what the last check found.
            "session": dict(self.session),
            "error": self.error,
        }


class Orchestrator:
    """Runs a pipeline for one authorized scope."""

    def __init__(
        self,
        scope: Scope,
        *,
        scope_yaml: str = "",
        settings: Settings | None = None,
        stage_instances: dict[str, Stage] | None = None,
        use_external_tools: bool | None = None,
        progress: ProgressCallback | None = None,
        heartbeat_seconds: float = 5.0,
    ) -> None:
        self._scope = scope
        self._scope_yaml = scope_yaml or f"program: {scope.program}"
        self._settings = settings or get_settings()
        # Resolved here, before the guard, because whether a session is available
        # decides whether the guard refuses state-changing paths. Reading the
        # environment is cheap and pure, and the monitor keeps the value out of
        # its own repr.
        self._session_monitor = SessionMonitor.from_scope(scope)
        self._guard = ScopeGuard(scope, authenticated=self._session_monitor.configured)
        self._overrides = stage_instances or {}
        options = scope.scan_options
        # An explicit argument wins, then the scope's own option, then on.
        self._use_external_tools = (
            options.use_external_tools if use_external_tools is None else use_external_tools
        )
        # SQLite has a single-writer limit; see _run_level.
        self._serialize_stages = self._settings.database_url.startswith("sqlite")
        self._progress = progress
        self._heartbeat_seconds = max(1.0, heartbeat_seconds)

    @property
    def guard(self) -> ScopeGuard:
        return self._guard

    def _stage(self, name: str) -> Stage:
        """The instance to run: an explicit override, else one built from the scope."""
        if name in self._overrides:
            return self._overrides[name]
        built = build_stage(name, self._scope.scan_options)
        return built if built is not None else STAGE_REGISTRY[name]()

    async def run(
        self,
        stages: Sequence[str] | None = None,
        *,
        trigger: str = "manual",
        resume_run_id: int | None = None,
    ) -> RunSummary:
        """Execute the pipeline. Returns a summary; never raises on stage failure."""
        names = resolve_stage_names(stages)
        levels = plan_stages(names)

        factory = get_session_factory(self._settings)
        async with factory() as session:
            program = await upsert_program(session, self._scope, self._scope_yaml)
            await session.commit()

            run, completed = await self._prepare_run(
                session, program.id, names, trigger, resume_run_id
            )
            await session.commit()

            summary = RunSummary(
                scan_run_id=run.id,
                program_slug=program.slug,
                status=RunStatus.RUNNING,
            )

            # Built in __init__ so the guard could be told. An unauthenticated scan
            # still gets a monitor, in NOT_CONFIGURED state, so every stage can ask
            # the same question without a special case.
            session_monitor = self._session_monitor
            http = ScopedHttpClient(
                self._guard, settings=self._settings, session=session_monitor
            )
            dns = ScopedResolver(self._guard, settings=self._settings)
            # SourceClient is built without the monitor, and takes no argument for
            # one. crt.sh and VirusTotal are third parties outside the program, so
            # the credential must be structurally unable to reach them rather than
            # merely not passed by accident today.
            sources = SourceClient(settings=self._settings)
            shared: dict[str, Any] = {}

            if session_monitor.configured:
                verdict = await session_monitor.check(http)
                summary.notes.append(
                    f"authenticated scan: {verdict.explain()}"
                )
                if not verdict.active:
                    # Starting a scan with a session that is already dead produces
                    # a run full of logged-out results that read as clean. Say so
                    # loudly at the top rather than letting it be discovered later.
                    summary.notes.append(
                        "the session was not valid before the scan began, so these "
                        "results describe the unauthenticated surface only"
                    )

            self._emit(
                ProgressEvent(
                    kind="run_started",
                    detail=",".join(names),
                    requests_made=http.requests_made,
                )
            )
            heartbeat: asyncio.Task | None = None
            if self._progress is not None:
                heartbeat = asyncio.create_task(
                    self._heartbeat_loop(summary, http, dns, sources)
                )

            try:
                for level in levels:
                    # Between levels, not inside them: a session does not expire
                    # per-parameter, and a check per verifier would cost more
                    # requests than the verifiers do.
                    if (
                        session_monitor.configured
                        and session_monitor.auth is not None
                        and session_monitor.auth.recheck_between_stages
                        and session_monitor.checks
                    ):
                        recheck = await session_monitor.check(http)
                        if not recheck.active:
                            note = f"session check before {', '.join(level)}: {recheck.explain()}"
                            if note not in summary.notes:
                                summary.notes.append(note)

                    await self._run_level(
                        level=level,
                        completed=completed,
                        summary=summary,
                        factory=factory,
                        program_id=program.id,
                        run_id=run.id,
                        http=http,
                        dns=dns,
                        sources=sources,
                        shared=shared,
                        session_monitor=session_monitor,
                    )

                summary.status = RunStatus.FAILED if summary.error else RunStatus.COMPLETED
            except Exception as exc:  # pragma: no cover - defensive
                summary.status = RunStatus.FAILED
                summary.error = f"{type(exc).__name__}: {exc}"
            finally:
                if heartbeat is not None:
                    heartbeat.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await heartbeat
                summary.requests_made = http.requests_made
                summary.tool_requests = http.external_requests
                summary.dns_queries = dns.queries
                summary.out_of_scope_blocked = self._guard.stats.blocked
                summary.source_calls = sources.calls
                # Recorded on the run so a report can say which surface these
                # results describe. A scan whose session died is not a clean scan.
                summary.session = session_monitor.summary()

                await write_audit_entries(
                    session,
                    http.audit_records(),
                    program_id=program.id,
                    scan_run_id=run.id,
                )
                await finish_scan_run(
                    session,
                    run,
                    status=summary.status,
                    error=summary.error,
                    summary=summary.as_dict(),
                    requests_made=summary.requests_made + summary.tool_requests,
                    dns_queries=summary.dns_queries,
                    out_of_scope_blocked=summary.out_of_scope_blocked,
                )
                await session.commit()
                await http.aclose()
                await sources.aclose()

            self._emit(
                ProgressEvent(
                    kind="run_finished",
                    status=summary.status.value,
                    detail=summary.error or "",
                    requests_made=summary.requests_made,
                    tool_requests=summary.tool_requests,
                    dns_queries=summary.dns_queries,
                    findings=list(summary.findings),
                )
            )
            return summary

    # -- realtime progress --------------------------------------------------

    def _emit(self, event: ProgressEvent) -> None:
        """Deliver one progress event, never letting the display break a scan."""
        if self._progress is None:
            return
        # A display bug must not fail a scan. Cancellation is a BaseException,
        # so it still propagates.
        with contextlib.suppress(Exception):
            self._progress(event)

    def _counters(self, summary: RunSummary, http, dns, sources) -> dict[str, Any]:
        return {
            "requests_made": http.requests_made,
            "tool_requests": http.external_requests,
            "dns_queries": dns.queries,
            "findings": list(summary.findings),
        }

    async def _heartbeat_loop(self, summary, http, dns, sources) -> None:
        """Periodic totals while stages run. Cancelled when the run ends."""
        try:
            while True:
                await asyncio.sleep(self._heartbeat_seconds)
                self._emit(
                    ProgressEvent(kind="heartbeat", **self._counters(summary, http, dns, sources))
                )
        except asyncio.CancelledError:
            raise

    # -- internals --------------------------------------------------------

    async def _prepare_run(
        self,
        session,
        program_id: int,
        names: Sequence[str],
        trigger: str,
        resume_run_id: int | None,
    ) -> tuple[ScanRun, set[str]]:
        """Start a run, or pick up an existing one and report what is already done."""
        if resume_run_id is None:
            run = await start_scan_run(
                session, program_id, stages=list(names), trigger=trigger
            )
            return run, set()

        found = (
            await session.execute(select(ScanRun).where(ScanRun.id == resume_run_id))
        ).scalars().first()
        if found is None:
            raise StagePlanError(f"no scan run with id {resume_run_id} to resume")

        done = (
            await session.execute(
                select(StageRun).where(
                    StageRun.scan_run_id == resume_run_id,
                    StageRun.status == RunStatus.COMPLETED,
                )
            )
        ).scalars().all()
        found.status = RunStatus.RUNNING
        session.add(found)
        return found, {stage.stage for stage in done}

    async def _run_level(
        self,
        *,
        level: list[str],
        completed: set[str],
        summary: RunSummary,
        factory,
        program_id: int,
        run_id: int,
        http: ScopedHttpClient,
        dns: ScopedResolver,
        sources: SourceClient,
        shared: dict[str, Any],
        session_monitor: Any = None,
    ) -> None:
        """Run one dependency level, skipping stages whose inputs are missing."""
        runnable: list[str] = []
        for name in level:
            if name in completed:
                summary.skipped[name] = "already completed in this run"
                self._emit(ProgressEvent(kind="stage_finished", stage=name, status="skipped"))
                continue
            blocked = [
                dependency
                for dependency in STAGE_REGISTRY[name].requires
                if dependency in summary.skipped
                and "failed" in summary.skipped[dependency]
            ]
            if blocked:
                summary.skipped[name] = (
                    f"skipped because {', '.join(blocked)} failed"
                )
                self._emit(ProgressEvent(kind="stage_finished", stage=name, status="skipped"))
                async with factory() as bookkeeping:
                    stage_run = await start_stage_run(
                        bookkeeping, run_id, program_id, name
                    )
                    await finish_stage_run(
                        bookkeeping, stage_run, status=RunStatus.SKIPPED,
                        error=summary.skipped[name],
                    )
                    await bookkeeping.commit()
                continue
            runnable.append(name)

        if not runnable:
            return

        # Stages in one level are independent by construction, so they *can*
        # run together. Whether they should depends on the database.
        #
        # SQLite permits exactly one writer at a time, whatever the journal
        # mode, and a stage holds its write transaction for its whole duration.
        # Two stages writing in parallel therefore means one of them waits for
        # the other to finish and then fails on the busy timeout, which is
        # exactly how the port stage died alongside content discovery. WAL and a
        # generous timeout reduce the window but cannot remove it.
        #
        # So under SQLite the level runs sequentially. The work is network-bound
        # and this costs wall-clock time, but a stage that silently fails is
        # worse than one that takes longer. Postgres has real concurrency, so
        # there the level runs in parallel as intended.
        coroutines = [
            self._run_one(
                name=name,
                factory=factory,
                program_id=program_id,
                run_id=run_id,
                http=http,
                dns=dns,
                sources=sources,
                shared=shared,
                session_monitor=session_monitor,
            )
            for name in runnable
        ]

        if len(coroutines) > 1 and self._serialize_stages:
            results: list = []
            for coroutine in coroutines:
                try:
                    results.append(await coroutine)
                except Exception as exc:  # noqa: BLE001 - recorded per stage below
                    results.append(exc)
        else:
            results = await asyncio.gather(*coroutines, return_exceptions=True)

        for name, outcome in zip(runnable, results, strict=True):
            if isinstance(outcome, BaseException):
                summary.skipped[name] = f"failed: {type(outcome).__name__}: {outcome}"
            else:
                summary.stages[name] = outcome

    async def _run_one(
        self,
        *,
        name: str,
        factory,
        program_id: int,
        run_id: int,
        http: ScopedHttpClient,
        dns: ScopedResolver,
        sources: SourceClient,
        shared: dict[str, Any],
        session_monitor: Any = None,
    ) -> StageResult:
        """Run one stage in its own database session.

        Stages at the same dependency level run concurrently, and a SQLAlchemy
        session is not safe for concurrent use: sharing one produces "session is
        already flushing" the moment two stages write at once. A session per
        stage also means a stage that fails rolls back only its own work.
        """
        stage = self._stage(name)
        self._emit(ProgressEvent(kind="stage_started", stage=name, status="running"))

        async with factory() as session:
            stage_run = await start_stage_run(session, run_id, program_id, name)
            await session.commit()

            ctx = StageContext(
                program_id=program_id,
                scan_run_id=run_id,
                scope=self._scope,
                guard=self._guard,
                http=http,
                dns=dns,
                sources=sources,
                session=session,
                settings=self._settings,
                checkpoint=dict(stage_run.checkpoint or {}),
                shared=shared,
                use_external_tools=self._use_external_tools,
                session_monitor=session_monitor,
            )

            try:
                result = await stage.run(ctx)
                await session.commit()
            except Exception as exc:
                await session.rollback()
                await finish_stage_run(
                    session,
                    stage_run,
                    status=RunStatus.FAILED,
                    error=f"{type(exc).__name__}: {exc}",
                )
                await session.commit()
                self._emit(
                    ProgressEvent(
                        kind="stage_finished", stage=name, status="failed",
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                )
                raise

            await finish_stage_run(
                session,
                stage_run,
                status=RunStatus.COMPLETED,
                items_in=result.items_in,
                items_out=result.items_out,
                items_filtered=result.items_filtered,
                filter_reasons=dict(result.filter_reasons),
                tools_used=result.tools_used,
                checkpoint=result.checkpoint,
            )
            await session.commit()
            self._emit(
                ProgressEvent(
                    kind="stage_finished",
                    stage=name,
                    status="completed",
                    detail=(
                        f"in={result.items_in} out={result.items_out} "
                        f"filtered={result.items_filtered}"
                    ),
                )
            )
            return result
