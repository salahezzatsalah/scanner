"""Tests for pipeline planning and execution."""

from __future__ import annotations

import asyncio

import pytest
from sqlmodel import select

from reconx.db.models import Asset, RunStatus, StageRun
from reconx.db.session import get_session_factory
from reconx.db.store import upsert_asset
from reconx.live import LiveProgress
from reconx.orchestrator import (
    STAGE_GROUPS,
    STAGE_REGISTRY,
    Orchestrator,
    ProgressEvent,
    StagePlanError,
    plan_stages,
    resolve_stage_names,
)
from reconx.stages.base import Stage, StageContext, StageResult
from tests.conftest import make_scope

# ---------------------------------------------------------------------------
# planning
# ---------------------------------------------------------------------------


def test_dependencies_are_pulled_in_automatically() -> None:
    """Probing an empty host list is not a result, so dependencies come along."""
    assert resolve_stage_names(["resolve_probe"]) == ["subdomains", "resolve_probe"]


def test_groups_expand_to_stages() -> None:
    assert resolve_stage_names(["passive"]) == ["passive_recon"]
    assert set(resolve_stage_names(["all"])) == set(STAGE_REGISTRY)


def test_default_is_the_recon_group() -> None:
    assert resolve_stage_names(None) == list(STAGE_GROUPS["recon"])


def test_unknown_stage_names_list_the_valid_ones() -> None:
    with pytest.raises(StagePlanError) as excinfo:
        resolve_stage_names(["nonsense"])
    message = str(excinfo.value)
    assert "subdomains" in message and "recon" in message


def test_independent_stages_share_a_level() -> None:
    levels = plan_stages(resolve_stage_names(["recon"]))
    assert {"passive_recon", "subdomains"} == set(levels[0])
    assert levels[1] == ["resolve_probe"]


def test_duplicate_requests_do_not_duplicate_stages() -> None:
    names = resolve_stage_names(["subdomains", "subdomains", "recon"])
    assert len(names) == len(set(names))


def test_cycles_are_reported_rather_than_hanging(monkeypatch) -> None:
    class A(Stage):
        name = "cycle_a"
        requires = ("cycle_b",)

        async def run(self, ctx):  # pragma: no cover
            return StageResult(stage=self.name)

    class B(Stage):
        name = "cycle_b"
        requires = ("cycle_a",)

        async def run(self, ctx):  # pragma: no cover
            return StageResult(stage=self.name)

    monkeypatch.setitem(STAGE_REGISTRY, "cycle_a", A)
    monkeypatch.setitem(STAGE_REGISTRY, "cycle_b", B)
    with pytest.raises(StagePlanError, match="cycle"):
        plan_stages(["cycle_a", "cycle_b"])


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------


class _WritingStage(Stage):
    """A stub that writes assets, to exercise concurrent database access."""

    def __init__(self, name: str, hosts: list[str], *, delay: float = 0.0) -> None:
        self._name = name
        self._hosts = hosts
        self._delay = delay

    @property
    def name(self) -> str:  # type: ignore[override]
        return self._name

    async def run(self, ctx: StageContext) -> StageResult:
        result = StageResult(stage=self._name)
        if self._delay:
            await asyncio.sleep(self._delay)
        for host in self._hosts:
            _, is_new = await upsert_asset(
                ctx.session, ctx.program_id, host, sources=[self._name]
            )
            if is_new:
                result.new_assets.append(host)
        result.items_in = len(self._hosts)
        result.items_out = len(self._hosts)
        return result


class _FailingStage(Stage):
    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:  # type: ignore[override]
        return self._name

    async def run(self, ctx: StageContext) -> StageResult:
        raise RuntimeError("this stage was always going to fail")


async def test_stages_at_one_level_all_complete_without_conflict(file_db) -> None:
    """Regression: two stages at one level used to collide and one would die.

    Two separate failures produced the same symptom. First, parallel stages
    shared a single SQLAlchemy session, which is not safe for concurrent use and
    raised "Session is already flushing". Then, with a session each, SQLite's
    single-writer limit meant the second writer waited on the first for the whole
    stage and failed on the busy timeout.

    Both are fixed: a session per stage, and sequential execution under SQLite.
    What matters either way is that every stage in the level completes.
    """
    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    orchestrator = Orchestrator(
        scope,
        use_external_tools=False,
        stage_instances={
            "passive_recon": _WritingStage(
                "passive_recon", [f"a{i}.example.com" for i in range(25)], delay=0.01
            ),
            "subdomains": _WritingStage(
                "subdomains", [f"b{i}.example.com" for i in range(25)], delay=0.01
            ),
            "resolve_probe": _WritingStage("resolve_probe", ["c.example.com"]),
        },
    )
    summary = await orchestrator.run(["recon"])

    assert summary.status == RunStatus.COMPLETED, summary.error
    assert summary.skipped == {}
    assert len(summary.stages) == 3
    assert len(summary.new_assets) == 51


async def test_concurrent_stages_proposing_the_same_host_do_not_collide(
    file_db,
) -> None:
    """Two stages can legitimately find the same subdomain at the same moment."""
    shared_hosts = [f"shared{i}.example.com" for i in range(20)]
    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    orchestrator = Orchestrator(
        scope,
        use_external_tools=False,
        stage_instances={
            "passive_recon": _WritingStage("passive_recon", shared_hosts),
            "subdomains": _WritingStage("subdomains", shared_hosts),
            "resolve_probe": _WritingStage("resolve_probe", []),
        },
    )
    summary = await orchestrator.run(["recon"])
    assert summary.status == RunStatus.COMPLETED, summary.error

    factory = get_session_factory()
    async with factory() as session:
        rows = (await session.execute(select(Asset))).scalars().all()
    # One row per host, no duplicates, despite both stages inserting each.
    assert len(rows) == len(shared_hosts)


async def test_a_failing_stage_does_not_abort_the_run(file_db) -> None:
    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    orchestrator = Orchestrator(
        scope,
        use_external_tools=False,
        stage_instances={
            "passive_recon": _WritingStage("passive_recon", ["ok.example.com"]),
            "subdomains": _FailingStage("subdomains"),
            "resolve_probe": _WritingStage("resolve_probe", ["never.example.com"]),
        },
    )
    summary = await orchestrator.run(["recon"])

    # The independent stage still did its work.
    assert "passive_recon" in summary.stages
    assert "ok.example.com" in summary.new_assets
    # The failure is reported, not swallowed.
    assert "failed" in summary.skipped["subdomains"]
    # And its dependent is skipped rather than run on missing input.
    assert "skipped because subdomains failed" in summary.skipped["resolve_probe"]
    assert "never.example.com" not in summary.new_assets


async def test_failed_and_skipped_stages_are_recorded_for_inspection(file_db) -> None:
    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    orchestrator = Orchestrator(
        scope,
        use_external_tools=False,
        stage_instances={
            "passive_recon": _WritingStage("passive_recon", []),
            "subdomains": _FailingStage("subdomains"),
            "resolve_probe": _WritingStage("resolve_probe", []),
        },
    )
    summary = await orchestrator.run(["recon"])

    factory = get_session_factory()
    async with factory() as session:
        rows = (
            await session.execute(
                select(StageRun).where(StageRun.scan_run_id == summary.scan_run_id)
            )
        ).scalars().all()
    statuses = {row.stage: row.status for row in rows}
    assert statuses["passive_recon"] == RunStatus.COMPLETED
    assert statuses["subdomains"] == RunStatus.FAILED
    assert statuses["resolve_probe"] == RunStatus.SKIPPED
    failed_row = next(row for row in rows if row.stage == "subdomains")
    assert "always going to fail" in (failed_row.error or "")


async def test_resume_skips_stages_already_completed(file_db) -> None:
    """A network blip must not mean starting a long enumeration from zero."""
    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])

    first = Orchestrator(
        scope,
        use_external_tools=False,
        stage_instances={
            "passive_recon": _WritingStage("passive_recon", ["one.example.com"]),
            "subdomains": _FailingStage("subdomains"),
            "resolve_probe": _WritingStage("resolve_probe", []),
        },
    )
    summary = await first.run(["recon"])
    assert "subdomains" in summary.skipped

    # Fix the broken stage and resume the same run.
    second = Orchestrator(
        scope,
        use_external_tools=False,
        stage_instances={
            "passive_recon": _WritingStage("passive_recon", ["should-not-run.example.com"]),
            "subdomains": _WritingStage("subdomains", ["two.example.com"]),
            "resolve_probe": _WritingStage("resolve_probe", ["three.example.com"]),
        },
    )
    resumed = await second.run(["recon"], resume_run_id=summary.scan_run_id)

    assert resumed.skipped.get("passive_recon") == "already completed in this run"
    assert "should-not-run.example.com" not in resumed.new_assets
    assert set(resumed.new_assets) == {"two.example.com", "three.example.com"}


async def test_resuming_an_unknown_run_is_an_error(file_db) -> None:
    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    orchestrator = Orchestrator(scope, use_external_tools=False)
    with pytest.raises(StagePlanError, match="no scan run"):
        await orchestrator.run(["passive"], resume_run_id=98765)


async def test_run_records_traffic_and_refusals(file_db) -> None:
    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])

    class _ProbingStage(Stage):
        name = "passive_recon"

        async def run(self, ctx: StageContext) -> StageResult:
            # Try one in-scope and one out-of-scope lookup.
            await ctx.dns.resolve("www.example.com")
            await ctx.dns.resolve("unrelated.invalid")
            return StageResult(stage=self.name)

    orchestrator = Orchestrator(
        scope, use_external_tools=False,
        stage_instances={"passive_recon": _ProbingStage()},
    )
    summary = await orchestrator.run(["passive"])
    assert summary.out_of_scope_blocked >= 1


# ---------------------------------------------------------------------------
# database concurrency policy
# ---------------------------------------------------------------------------


def test_sqlite_serializes_a_level_and_postgres_does_not() -> None:
    """SQLite allows one writer, so a level must not run in parallel on it.

    A stage holds its write transaction for its whole duration, so two of them
    at once means one waits and then fails on the busy timeout. Journal mode does
    not change that. Postgres has real concurrency and keeps the parallelism.
    """
    from reconx.config import Settings

    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    sqlite = Orchestrator(
        scope, settings=Settings(database_url="sqlite+aiosqlite:///./data/x.db")
    )
    postgres = Orchestrator(
        scope, settings=Settings(database_url="postgresql+asyncpg://u@h/db")
    )
    assert sqlite._serialize_stages is True
    assert postgres._serialize_stages is False


async def test_a_failure_in_a_serialized_level_does_not_stop_its_siblings(
    file_db,
) -> None:
    """Sequential execution must still isolate failures, as gather did."""
    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    orchestrator = Orchestrator(
        scope,
        use_external_tools=False,
        stage_instances={
            # These two share a level. The first fails; the second must still run.
            "passive_recon": _FailingStage("passive_recon"),
            "subdomains": _WritingStage("subdomains", ["survived.example.com"]),
            "resolve_probe": _WritingStage("resolve_probe", []),
        },
    )
    summary = await orchestrator.run(["recon"])

    assert "failed" in summary.skipped["passive_recon"]
    assert "subdomains" in summary.stages
    assert "survived.example.com" in summary.new_assets


# ---------------------------------------------------------------------------
# realtime progress
# ---------------------------------------------------------------------------


async def test_progress_events_follow_a_run_start_to_finish(file_db) -> None:
    """The display must see every stage open and close, in order."""
    events: list[ProgressEvent] = []
    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    orchestrator = Orchestrator(
        scope,
        use_external_tools=False,
        progress=events.append,
        stage_instances={
            "passive_recon": _WritingStage("passive_recon", []),
            "subdomains": _WritingStage("subdomains", ["a.example.com"]),
            "resolve_probe": _WritingStage("resolve_probe", []),
        },
    )
    summary = await orchestrator.run(["recon"])

    kinds = [(event.kind, event.stage) for event in events]
    assert kinds[0] == ("run_started", "")
    assert ("stage_started", "subdomains") in kinds
    assert ("stage_finished", "subdomains") in kinds
    assert kinds[-1][0] == "run_finished"
    # Every started stage finishes, even the failing-free fast ones.
    started = {stage for kind, stage in kinds if kind == "stage_started"}
    finished = {stage for kind, stage in kinds if kind == "stage_finished"}
    assert started <= finished
    assert summary.status.value == "completed"


async def test_a_broken_display_callback_cannot_fail_a_run(file_db) -> None:
    """The progress sink is display-only: raising inside it changes nothing."""

    def broken(event: ProgressEvent) -> None:
        raise AssertionError("the display is on fire")

    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    orchestrator = Orchestrator(
        scope,
        use_external_tools=False,
        progress=broken,
        stage_instances={
            "passive_recon": _WritingStage("passive_recon", []),
            "subdomains": _WritingStage("subdomains", ["a.example.com"]),
            "resolve_probe": _WritingStage("resolve_probe", []),
        },
    )
    summary = await orchestrator.run(["recon"])

    assert summary.status.value == "completed"
    assert "subdomains" in summary.stages


def test_live_progress_accumulates_counts_and_findings() -> None:
    """The table state advances on events without a terminal attached."""
    view = LiveProgress()
    view(ProgressEvent(kind="run_started", detail="subdomains,resolve_probe"))
    view(ProgressEvent(kind="stage_started", stage="subdomains", status="running"))
    view(
        ProgressEvent(
            kind="heartbeat", requests_made=41, dns_queries=7,
            findings=["CONFIRMED | HIGH: Something in 'q' at /x"],
        )
    )
    view(
        ProgressEvent(
            kind="stage_finished", stage="subdomains", status="completed",
            detail="in=3 out=2 filtered=0", requests_made=41, dns_queries=7,
        )
    )

    assert view._status["subdomains"] == "completed"
    assert view._requests == 41
    assert view._dns == 7
    assert view._findings == ["CONFIRMED | HIGH: Something in 'q' at /x"]
    # Rendering must not raise with or without stages.
    view.render()
    LiveProgress().render()
