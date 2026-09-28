"""Tests for continuous monitoring: change detection, alerts, scheduling."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import httpx
import pytest
import respx
from sqlalchemy.ext.asyncio import AsyncSession

from reconx.config import Settings
from reconx.db.models import FindingTier, Program, Severity
from reconx.db.store import upsert_asset, upsert_endpoint, upsert_finding
from reconx.monitor.diff import ChangeSet, build_notification, detect_changes
from reconx.monitor.scheduler import DEFAULT_CADENCES, MonitorService
from reconx.notify.base import (
    Notification,
    NotifierHub,
    Urgency,
    build_notifiers,
)
from reconx.notify.discord import DiscordNotifier
from reconx.notify.slack import SlackNotifier
from reconx.notify.telegram import TelegramNotifier
from reconx.notify.webhook import WebhookNotifier


def now() -> datetime:
    return datetime.now(UTC)


def a_program() -> Program:
    return Program(
        slug="acme",
        name="Acme VDP",
        scope_yaml="program: Acme VDP",
        authorized_by="me@example.com",
        authorization_date=date(2026, 9, 28),
        attestation="authorized",
    )


# ---------------------------------------------------------------------------
# change detection
# ---------------------------------------------------------------------------


async def test_a_new_asset_is_reported_as_notable(
    db_session: AsyncSession, program: Program
) -> None:
    """On a wildcard program this is the highest-value signal there is."""
    await upsert_asset(
        db_session, program.id, "admin-dev.example.com",
        is_live=True, http_status=200, title="Administrator sign in",
    )
    await db_session.commit()

    changes = await detect_changes(db_session, program, now() - timedelta(hours=1))
    assert [c.subject for c in changes.of_kind("new_asset")] == ["admin-dev.example.com"]
    assert changes.urgency is Urgency.NOTABLE
    assert "Administrator sign in" in changes.of_kind("new_asset")[0].detail


async def test_an_asset_seen_before_the_window_is_not_new(
    db_session: AsyncSession, program: Program
) -> None:
    asset, _ = await upsert_asset(db_session, program.id, "old.example.com")
    asset.first_seen = now() - timedelta(days=30)
    asset.last_seen = now() - timedelta(minutes=5)
    db_session.add(asset)
    await db_session.commit()

    changes = await detect_changes(db_session, program, now() - timedelta(hours=1))
    assert changes.of_kind("new_asset") == []


async def test_a_confirmed_high_finding_is_urgent(
    db_session: AsyncSession, program: Program
) -> None:
    await upsert_finding(
        db_session, program.id,
        dedup_key="sqli::/item::id", vuln_class="sqli",
        title="SQL injection in 'id' at /item",
        severity=Severity.CRITICAL, tier=FindingTier.CONFIRMED, confidence=95,
    )
    await db_session.commit()

    changes = await detect_changes(db_session, program, now() - timedelta(hours=1))
    finding_changes = changes.of_kind("new_finding")
    assert len(finding_changes) == 1
    assert finding_changes[0].urgency is Urgency.URGENT
    assert changes.urgency is Urgency.URGENT


async def test_a_probable_finding_is_notable_not_urgent(
    db_session: AsyncSession, program: Program
) -> None:
    """Urgency should mean something, so unverified findings do not claim it."""
    await upsert_finding(
        db_session, program.id,
        dedup_key="xss::/s::q", vuln_class="xss", title="Reflected XSS in 'q'",
        severity=Severity.HIGH, tier=FindingTier.PROBABLE, confidence=70,
    )
    await db_session.commit()

    changes = await detect_changes(db_session, program, now() - timedelta(hours=1))
    assert changes.of_kind("new_finding")[0].urgency is Urgency.NOTABLE


async def test_discarded_findings_never_reach_an_alert(
    db_session: AsyncSession, program: Program
) -> None:
    """The whole point of filtering is not being messaged about the noise."""
    await upsert_finding(
        db_session, program.id,
        dedup_key="sqli::/x::id", vuln_class="sqli", title="Discarded candidate",
        severity=Severity.HIGH, tier=FindingTier.DISCARDED,
        discard_reason="the error string was already on the page",
    )
    await db_session.commit()

    changes = await detect_changes(db_session, program, now() - timedelta(hours=1))
    assert changes.of_kind("new_finding") == []


async def test_only_interesting_endpoints_are_worth_a_message(
    db_session: AsyncSession, program: Program
) -> None:
    await upsert_endpoint(
        db_session, program.id, "https://www.example.com/.git/config",
        status=200, interesting_score=4.0,
    )
    await upsert_endpoint(
        db_session, program.id, "https://www.example.com/about-us",
        status=200, interesting_score=0.0,
    )
    await db_session.commit()

    changes = await detect_changes(db_session, program, now() - timedelta(hours=1))
    subjects = [c.subject for c in changes.of_kind("new_endpoint")]
    assert any(".git/config" in subject for subject in subjects)
    assert not any("about-us" in subject for subject in subjects)


async def test_a_live_asset_that_goes_quiet_is_reported(
    db_session: AsyncSession, program: Program
) -> None:
    asset, _ = await upsert_asset(
        db_session, program.id, "gone.example.com", is_live=True
    )
    asset.first_seen = now() - timedelta(days=30)
    asset.last_seen = now() - timedelta(days=10)
    db_session.add(asset)
    await db_session.commit()

    changes = await detect_changes(
        db_session, program, now() - timedelta(hours=1), stale_after=timedelta(days=3)
    )
    assert [c.subject for c in changes.of_kind("asset_stopped_answering")] == [
        "gone.example.com"
    ]


# ---------------------------------------------------------------------------
# notification shaping
# ---------------------------------------------------------------------------


def test_nothing_changed_produces_no_message() -> None:
    """A monitor that messages you hourly regardless gets muted, then is useless."""
    empty = ChangeSet(program=a_program(), since=now(), changes=[])
    assert build_notification(empty) is None


def test_findings_lead_the_message() -> None:
    from reconx.monitor.diff import Change

    changes = ChangeSet(
        program=a_program(),
        since=now() - timedelta(hours=1),
        changes=[
            Change("new_asset", "a.example.com", "200", Urgency.NOTABLE),
            Change("new_finding", "CRITICAL SQLi in id", "confirmed", Urgency.URGENT),
            Change("new_endpoint", "https://a.example.com/.git/", "score 4", Urgency.INFO),
        ],
    )
    notification = build_notification(changes)
    assert notification is not None
    assert notification.urgency is Urgency.URGENT
    body = notification.as_text()
    assert body.index("New Finding") < body.index("New Asset")
    assert "1 finding" in notification.title
    assert a_program().name in body
    assert "reconx report acme" in body


# ---------------------------------------------------------------------------
# delivery channels
# ---------------------------------------------------------------------------


def test_unconfigured_channels_are_skipped() -> None:
    hub = build_notifiers(Settings())
    assert hub.enabled is False
    assert hub.channels == []


def test_channels_are_enabled_by_configuration() -> None:
    hub = build_notifiers(
        Settings(
            discord_webhook="https://discord.com/api/webhooks/1/abc",
            slack_webhook="https://hooks.slack.com/services/a/b/c",
            telegram_bot_token="123:abc",
            telegram_chat_id="456",
            generic_webhook="https://example.com/hook",
        )
    )
    assert set(hub.channels) == {"discord", "slack", "telegram", "webhook"}


@pytest.mark.parametrize(
    ("notifier", "expected"),
    [
        (DiscordNotifier("not-a-url"), False),
        (DiscordNotifier("https://discord.com/api/webhooks/1/a"), True),
        (SlackNotifier(""), False),
        (TelegramNotifier("token", ""), False),
        (TelegramNotifier("token", "chat"), True),
        (WebhookNotifier("ftp://example.com"), False),
        (WebhookNotifier("http://localhost:8000/hook"), True),
    ],
)
def test_channels_report_whether_they_can_send(notifier, expected: bool) -> None:
    assert notifier.configured is expected


@respx.mock
async def test_a_failing_channel_does_not_break_the_others() -> None:
    """A scan must not die because a webhook is down."""
    respx.post("https://discord.com/api/webhooks/1/a").mock(
        return_value=httpx.Response(500, text="server error")
    )
    respx.post("https://example.com/hook").mock(return_value=httpx.Response(200))

    hub = NotifierHub(
        [
            DiscordNotifier("https://discord.com/api/webhooks/1/a"),
            WebhookNotifier("https://example.com/hook"),
        ]
    )
    results = await hub.broadcast(Notification(title="test", lines=["x"]))

    assert results == {"discord": False, "webhook": True}
    assert hub.sent == 1
    assert "discord" in hub.failures


@respx.mock
async def test_the_generic_webhook_sends_structured_data() -> None:
    """So it can feed a dashboard rather than only a chat window."""
    captured: dict = {}

    def record(request: httpx.Request) -> httpx.Response:
        import json

        captured.update(json.loads(request.content))
        return httpx.Response(200)

    respx.post("https://example.com/hook").mock(side_effect=record)

    await WebhookNotifier("https://example.com/hook").send(
        Notification(
            title="1 finding",
            program="Acme VDP",
            urgency=Urgency.URGENT,
            lines=["! CRITICAL SQLi"],
            footer="reconx report acme",
        )
    )
    assert captured["source"] == "reconx"
    assert captured["urgency"] == "urgent"
    assert captured["program"] == "Acme VDP"
    assert captured["lines"] == ["! CRITICAL SQLi"]
    assert "CRITICAL" in captured["text"]


# ---------------------------------------------------------------------------
# scheduling
# ---------------------------------------------------------------------------


def test_cadences_match_how_fast_each_thing_changes() -> None:
    """Liveness moves hourly; a full vulnerability sweep does not."""
    assert DEFAULT_CADENCES["resolve_probe"] < DEFAULT_CADENCES["subdomains"]
    assert DEFAULT_CADENCES["subdomains"] < DEFAULT_CADENCES["vulns"]
    assert all(interval >= 3600 for interval in DEFAULT_CADENCES.values())


async def test_enabling_monitoring_creates_a_schedule_for_every_stage(file_db) -> None:
    from sqlmodel import select

    from reconx.db.models import ScheduleEntry
    from reconx.db.session import get_session_factory
    from reconx.db.store import upsert_program
    from tests.conftest import make_scope

    factory = get_session_factory()
    async with factory() as session:
        created = await upsert_program(session, make_scope(), scope_yaml="program: x")
        await session.commit()
        program_id = created.id

    service = MonitorService(tick_seconds=60)
    async with factory() as session:
        found = (
            await session.execute(select(Program).where(Program.id == program_id))
        ).scalars().first()
    entries = await service.ensure_schedules(found)
    assert {entry.stage for entry in entries} == set(DEFAULT_CADENCES)

    async with factory() as session:
        stored = (
            await session.execute(
                select(ScheduleEntry).where(ScheduleEntry.program_id == program_id)
            )
        ).scalars().all()
    assert len(stored) == len(DEFAULT_CADENCES)


async def test_a_tick_with_nothing_due_is_idle_and_silent(file_db) -> None:
    service = MonitorService(tick_seconds=60, use_external_tools=False)
    report = await service.tick()
    assert report.idle is True
    assert report.programs_run == []
    assert report.notifications_sent == 0


async def test_monitoring_disabled_programs_are_not_scanned(file_db) -> None:
    from sqlmodel import select

    from reconx.db.session import get_session_factory
    from reconx.db.store import upsert_program
    from tests.conftest import make_scope

    factory = get_session_factory()
    async with factory() as session:
        created = await upsert_program(session, make_scope(), scope_yaml="program: x")
        created.monitoring_enabled = False
        session.add(created)
        await session.commit()
        program_id = created.id

    service = MonitorService(tick_seconds=60, use_external_tools=False)
    async with factory() as session:
        found = (
            await session.execute(select(Program).where(Program.id == program_id))
        ).scalars().first()
    await service.ensure_schedules(found)

    report = await service.tick()
    assert report.programs_run == []


async def test_repeated_failures_back_the_stage_off(file_db) -> None:
    """Retrying a broken stage on its normal cadence forever is not useful."""
    from sqlmodel import select

    from reconx.db.models import RunStatus, ScheduleEntry
    from reconx.db.session import get_session_factory
    from reconx.db.store import upsert_program, upsert_schedule_entry
    from tests.conftest import make_scope

    factory = get_session_factory()
    async with factory() as session:
        created = await upsert_program(session, make_scope(), scope_yaml="program: x")
        await session.commit()
        program_id = created.id
        await upsert_schedule_entry(
            session, program_id, "passive_recon", interval_seconds=3600
        )
        await session.commit()

    service = MonitorService(tick_seconds=60, use_external_tools=False)
    for _ in range(3):
        await service._mark_failure(program_id, ["passive_recon"])

    async with factory() as session:
        entry = (
            await session.execute(
                select(ScheduleEntry).where(ScheduleEntry.program_id == program_id)
            )
        ).scalars().first()

    assert entry.consecutive_failures >= 3
    assert entry.last_status is RunStatus.FAILED
    next_run = entry.next_run_at
    if next_run.tzinfo is None:
        next_run = next_run.replace(tzinfo=UTC)
    # Backed off well beyond the one-hour cadence.
    assert (next_run - now()) > timedelta(hours=2)


# ---------------------------------------------------------------------------
# the notification channel's constraint
# ---------------------------------------------------------------------------


def test_notifier_destinations_come_only_from_configuration() -> None:
    """Alert endpoints must never be derived from scan data.

    The notification channel is the one outbound path not gated by the program
    scope, which is correct: it goes to the operator, not to a target. What keeps
    that safe is that every destination is read from settings at construction
    time, and nothing a scan discovers can influence it.
    """
    import inspect

    from reconx.notify import base as notify_base

    source = inspect.getsource(notify_base.build_notifiers)
    # Every channel is constructed from a settings attribute.
    assert "resolved.discord_webhook" in source
    assert "resolved.slack_webhook" in source
    assert "resolved.telegram_bot_token" in source
    assert "resolved.generic_webhook" in source

    # The notifiers expose no way to retarget after construction.
    for cls in (DiscordNotifier, SlackNotifier, TelegramNotifier, WebhookNotifier):
        setters = [
            name
            for name in dir(cls)
            if name.startswith("set_") or name in {"url", "webhook_url"}
        ]
        assert setters == [], f"{cls.__name__} exposes a way to change its destination"


def test_a_notification_carries_no_capability_to_reach_a_target() -> None:
    """Notification content is text; it cannot cause a request anywhere."""
    notification = Notification(
        title="findings",
        program="Acme",
        lines=["https://target.example.com/admin"],
    )
    # A URL inside the body is data, not a destination.
    assert "target.example.com" in notification.as_text()
    hub = NotifierHub([])
    assert hub.channels == []
    assert hub.enabled is False
