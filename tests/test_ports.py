"""Tests for port and service discovery."""

from __future__ import annotations

import asyncio
import contextlib

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx.config import Settings
from reconx.db.models import Finding, FindingTier, Observation, Program, Severity
from reconx.db.store import upsert_asset
from reconx.net.dns import ScopedResolver
from reconx.net.http import ScopedHttpClient
from reconx.net.sources import SourceClient
from reconx.scope.guard import ScopeGuard
from reconx.stages.base import StageContext
from reconx.stages.ports import (
    EXPOSURE_CONCERNS,
    SERVICE_NAMES,
    TOP_PORTS,
    PortStage,
)
from tests.conftest import make_scope


@contextlib.asynccontextmanager
async def listener(port: int = 0):
    """A TCP listener on loopback, so the scan has something real to find."""

    async def handle(_reader, writer):
        with contextlib.suppress(Exception):
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    bound = server.sockets[0].getsockname()[1]
    try:
        yield bound
    finally:
        server.close()
        await server.wait_closed()


async def make_context(
    session: AsyncSession, program: Program, scope=None
) -> StageContext:
    resolved = scope or make_scope(in_scope=["127.0.0.1"], out_of_scope=[])
    guard = ScopeGuard(resolved)
    settings = Settings(requests_per_second_per_host=500.0, max_retries=0)
    return StageContext(
        program_id=program.id,
        scan_run_id=1,
        scope=resolved,
        guard=guard,
        http=ScopedHttpClient(guard, settings=settings),
        dns=ScopedResolver(guard, settings=settings),
        sources=SourceClient(settings=settings),
        session=session,
        settings=settings,
        use_external_tools=False,
    )


# ---------------------------------------------------------------------------
# the catalogue
# ---------------------------------------------------------------------------


def test_every_scanned_port_has_a_service_name() -> None:
    """An unnamed open port is a finding a researcher has to look up."""
    unnamed = [port for port in TOP_PORTS if port not in SERVICE_NAMES]
    assert unnamed == [], f"ports without a service name: {unnamed}"


def test_exposure_concerns_are_all_in_the_scanned_set() -> None:
    """A concern for a port that is never scanned can never fire."""
    missing = [port for port in EXPOSURE_CONCERNS if port not in TOP_PORTS]
    assert missing == []


def test_exposure_concerns_carry_a_reason_and_a_sane_severity() -> None:
    for port, (severity, why) in EXPOSURE_CONCERNS.items():
        assert why.strip(), f"port {port} has no rationale"
        assert severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}


def test_the_worst_exposures_are_rated_critical() -> None:
    """Redis and an unencrypted Docker API are remote code execution."""
    assert EXPOSURE_CONCERNS[6379][0] is Severity.CRITICAL
    assert EXPOSURE_CONCERNS[2375][0] is Severity.CRITICAL
    assert EXPOSURE_CONCERNS[10250][0] is Severity.CRITICAL


def test_the_port_list_stays_small_enough_to_be_polite() -> None:
    assert 40 <= len(TOP_PORTS) <= 200
    assert 80 in TOP_PORTS and 443 in TOP_PORTS


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------


async def test_an_open_port_is_found_and_a_closed_one_is_not(
    db_session: AsyncSession, program: Program
) -> None:
    async with listener() as open_port:
        # A port we know nothing is on. Picking a high one keeps the odds good.
        closed_port = 65_301
        ctx = await make_context(db_session, program)
        await upsert_asset(db_session, program.id, "127.0.0.1")
        await db_session.commit()

        stage = PortStage(
            ports=(open_port, closed_port), connect_timeout=1.0, grab_banners=False
        )
        result = await stage.run(ctx)
        await db_session.commit()

        found = {entry["port"] for entry in ctx.shared["open_ports"]}
        assert open_port in found
        assert closed_port not in found
        assert result.items_out == 1
        await ctx.http.aclose()
        await ctx.sources.aclose()


async def test_open_ports_are_recorded_as_observations(
    db_session: AsyncSession, program: Program
) -> None:
    async with listener() as open_port:
        ctx = await make_context(db_session, program)
        await upsert_asset(db_session, program.id, "127.0.0.1")
        await db_session.commit()

        await PortStage(
            ports=(open_port,), connect_timeout=1.0, grab_banners=False
        ).run(ctx)
        await db_session.commit()

        rows = (
            await db_session.execute(
                select(Observation).where(Observation.kind == "open_port")
            )
        ).scalars().all()
        assert [row.key for row in rows] == [f"127.0.0.1:{open_port}"]
        await ctx.http.aclose()
        await ctx.sources.aclose()


async def test_an_exposed_database_port_becomes_a_finding(
    db_session: AsyncSession, program: Program
) -> None:
    """Reachability is a fact, so this is Confirmed rather than a guess."""
    async with listener(port=0) as bound:
        # Pretend the bound port is Redis by scanning it under that number's
        # rules: the stage keys concerns off the port, so this exercises the
        # finding path without needing to bind a privileged port.
        ctx = await make_context(db_session, program)
        await upsert_asset(db_session, program.id, "127.0.0.1")
        await db_session.commit()

        stage = PortStage(ports=(bound,), connect_timeout=1.0, grab_banners=False)
        # Temporarily treat the bound port as one that matters.
        from reconx.stages import ports as ports_module

        original = dict(ports_module.EXPOSURE_CONCERNS)
        ports_module.EXPOSURE_CONCERNS[bound] = (
            Severity.CRITICAL,
            "Redis usually has no authentication at all",
        )
        ports_module.SERVICE_NAMES[bound] = "redis"
        try:
            result = await stage.run(ctx)
            await db_session.commit()
        finally:
            ports_module.EXPOSURE_CONCERNS.clear()
            ports_module.EXPOSURE_CONCERNS.update(original)
            ports_module.SERVICE_NAMES.pop(bound, None)

        findings = (
            await db_session.execute(
                select(Finding).where(Finding.vuln_class == "exposed_service")
            )
        ).scalars().all()
        assert len(findings) == 1
        finding = findings[0]
        assert finding.tier is FindingTier.CONFIRMED
        assert finding.severity is Severity.CRITICAL
        assert "no authentication" in finding.description
        assert finding.recommendation
        assert result.new_findings
        await ctx.http.aclose()
        await ctx.sources.aclose()


async def test_an_ordinary_open_port_is_not_a_finding(
    db_session: AsyncSession, program: Program
) -> None:
    """Port 80 being open is not news."""
    async with listener() as open_port:
        ctx = await make_context(db_session, program)
        await upsert_asset(db_session, program.id, "127.0.0.1")
        await db_session.commit()

        await PortStage(
            ports=(open_port,), connect_timeout=1.0, grab_banners=False
        ).run(ctx)
        await db_session.commit()

        findings = (
            await db_session.execute(
                select(Finding).where(Finding.vuln_class == "exposed_service")
            )
        ).scalars().all()
        assert findings == []
        await ctx.http.aclose()
        await ctx.sources.aclose()


async def test_out_of_scope_hosts_are_never_scanned(
    db_session: AsyncSession, program: Program
) -> None:
    scope = make_scope(in_scope=["api.example.io"], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope)
    await upsert_asset(db_session, program.id, "127.0.0.1")
    await db_session.commit()

    result = await PortStage(ports=(65_302,), connect_timeout=0.5).run(ctx)
    assert result.items_in == 0
    assert any("no in-scope hosts" in note for note in result.notes)
    await ctx.http.aclose()
    await ctx.sources.aclose()


async def test_nothing_to_scan_is_reported_clearly(
    db_session: AsyncSession, program: Program
) -> None:
    ctx = await make_context(db_session, program)
    result = await PortStage(ports=(65_303,)).run(ctx)
    assert result.items_in == 0
    assert result.notes
    await ctx.http.aclose()
    await ctx.sources.aclose()


@pytest.mark.parametrize(
    ("port", "expected"),
    [(22, "ssh"), (443, "https"), (6379, "redis"), (27017, "mongodb"), (9200, "elasticsearch")],
)
def test_common_services_are_named_correctly(port: int, expected: str) -> None:
    assert SERVICE_NAMES[port] == expected
