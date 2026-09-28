"""Tests for priority scoring and the recommendation engine."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from reconx.config import Settings
from reconx.db.models import Finding, FindingTier, Program, Severity
from reconx.db.store import upsert_asset, upsert_endpoint, upsert_finding
from reconx.triage.priority import asset_criticality, compute_priority, explain_priority
from reconx.triage.recommend import PLAYBOOKS, recommend


def a_finding(**overrides) -> Finding:
    payload = {
        "program_id": 1,
        "dedup_key": "k",
        "vuln_class": "sqli",
        "title": "SQL injection",
        "severity": Severity.HIGH,
        "tier": FindingTier.CONFIRMED,
        "confidence": 95,
        "affected_hosts": ["www.example.com"],
    }
    payload.update(overrides)
    return Finding(**payload)


# ---------------------------------------------------------------------------
# priority
# ---------------------------------------------------------------------------


def test_confirmed_outranks_probable_at_the_same_severity() -> None:
    """Proved beats likely. Otherwise the queue sends you to the wrong place."""
    confirmed = compute_priority(a_finding(tier=FindingTier.CONFIRMED, confidence=95))
    probable = compute_priority(a_finding(tier=FindingTier.PROBABLE, confidence=70))
    review = compute_priority(a_finding(tier=FindingTier.NEEDS_REVIEW, confidence=45))
    assert confirmed.priority > probable.priority > review.priority


def test_severity_dominates_but_does_not_decide_alone() -> None:
    critical_unverified = compute_priority(
        a_finding(severity=Severity.CRITICAL, tier=FindingTier.NEEDS_REVIEW, confidence=40)
    )
    high_confirmed = compute_priority(
        a_finding(severity=Severity.HIGH, tier=FindingTier.CONFIRMED, confidence=95)
    )
    assert high_confirmed.priority > critical_unverified.priority


def test_a_discarded_finding_scores_zero() -> None:
    assert compute_priority(a_finding(tier=FindingTier.DISCARDED)).priority == 0.0


def test_an_admin_host_outranks_a_cdn_host() -> None:
    admin = compute_priority(a_finding(affected_hosts=["admin.example.com"]))
    cdn = compute_priority(a_finding(affected_hosts=["cdn.example.com"]))
    assert admin.priority > cdn.priority
    assert "administrative interface" in admin.reasons


def test_breadth_raises_priority() -> None:
    one = compute_priority(a_finding(affected_hosts=["a.example.com"]))
    many = compute_priority(
        a_finding(affected_hosts=[f"h{index}.example.com" for index in range(50)])
    )
    assert many.priority > one.priority
    assert any("affects 50 hosts" in reason for reason in many.reasons)


def test_a_throttled_host_lowers_confidence_in_the_result() -> None:
    clean = compute_priority(a_finding())
    throttled = compute_priority(a_finding(tested_while_throttled=True))
    assert throttled.priority < clean.priority
    assert any("rate-limiting" in reason for reason in throttled.reasons)


def test_keyword_stuffing_cannot_dominate_the_ordering() -> None:
    stuffed, _ = asset_criticality("admin-api-payments-internal-sso-console.example.com")
    assert stuffed <= 2.5


def test_an_unremarkable_host_is_neutral() -> None:
    multiplier, reasons = asset_criticality("www.example.com", title="Welcome")
    assert multiplier == 1.0
    assert reasons == []


def test_priority_is_explainable() -> None:
    """A score you cannot argue with is a score you cannot trust."""
    text = explain_priority(compute_priority(a_finding(affected_hosts=["admin.example.com"])))
    assert "severity" in text and "confidence" in text and "tier" in text
    assert "administrative interface" in text


# ---------------------------------------------------------------------------
# recommendations
# ---------------------------------------------------------------------------


async def test_every_finding_class_we_report_has_guidance(
    db_session: AsyncSession, program: Program
) -> None:
    """A finding with no next step is a finding a researcher stalls on."""
    for vuln_class in ("sqli", "xss", "subdomain_takeover", "exposed_secret", "nuclei"):
        assert vuln_class in PLAYBOOKS
        action, why = PLAYBOOKS[vuln_class]
        assert action.strip() and why.strip()


async def test_confirmed_findings_come_first(
    db_session: AsyncSession, program: Program
) -> None:
    await upsert_finding(
        db_session, program.id, dedup_key="a", vuln_class="sqli",
        title="SQL injection in 'id'", severity=Severity.CRITICAL,
        tier=FindingTier.CONFIRMED, confidence=95, affected_hosts=["admin.example.com"],
    )
    await upsert_asset(db_session, program.id, "admin.example.com", is_live=True)
    await db_session.commit()

    actions = await recommend(db_session, program, settings=Settings())
    assert actions
    assert actions[0].kind == "finding"
    assert "SQL injection" in actions[0].subject
    assert "parameterised queries" in actions[0].action or "database version" in actions[0].action


async def test_an_untested_parameterised_endpoint_is_a_coverage_gap(
    db_session: AsyncSession, program: Program
) -> None:
    """The gap between what was found and what was tested is where bugs hide."""
    await upsert_asset(db_session, program.id, "www.example.com", is_live=True)
    await upsert_endpoint(
        db_session, program.id, "https://www.example.com/search?q=1",
        parameters=["q"], status=200,
    )
    await db_session.commit()

    actions = await recommend(db_session, program, settings=Settings())
    coverage = [item for item in actions if item.kind == "coverage"]
    assert any("never tested" in item.subject for item in coverage)
    assert any("--stage vulns" in (item.command or "") for item in coverage)


async def test_an_interesting_host_with_no_findings_is_suggested(
    db_session: AsyncSession, program: Program
) -> None:
    await upsert_asset(
        db_session, program.id, "admin.example.com",
        is_live=True, http_status=200, title="Administrator sign in",
    )
    await upsert_endpoint(
        db_session, program.id, "https://admin.example.com/", status=200
    )
    await db_session.commit()

    actions = await recommend(db_session, program, settings=Settings())
    asset_actions = [item for item in actions if item.kind == "asset"]
    assert any("admin.example.com" in item.subject for item in asset_actions)
    suggestion = next(item for item in asset_actions if "admin" in item.subject)
    assert "authentication bypass" in suggestion.action


async def test_an_empty_program_is_told_to_scan(
    db_session: AsyncSession, program: Program
) -> None:
    actions = await recommend(db_session, program, settings=Settings())
    assert any("nothing has been discovered yet" in item.subject for item in actions)
    assert actions[0].priority >= 9


async def test_a_missing_alert_channel_is_flagged(
    db_session: AsyncSession, program: Program
) -> None:
    """Recording findings nobody reads is the worst outcome."""
    actions = await recommend(db_session, program, settings=Settings())
    assert any("no alert channel" in item.subject for item in actions)


async def test_a_configured_alert_channel_is_not_flagged(
    db_session: AsyncSession, program: Program
) -> None:
    configured = Settings(generic_webhook="https://example.com/hook")
    actions = await recommend(db_session, program, settings=configured)
    assert not any("no alert channel" in item.subject for item in actions)


async def test_missing_nuclei_is_called_the_biggest_gap(
    db_session: AsyncSession, program: Program
) -> None:
    from reconx.tools.base import ToolStatus
    from reconx.tools.registry import TOOL_SPECS

    statuses = {
        name: ToolStatus(spec=spec, available=False)
        for name, spec in TOOL_SPECS.items()
    }
    actions = await recommend(
        db_session, program, settings=Settings(), tool_statuses=statuses
    )
    setup = [item for item in actions if item.kind == "setup"]
    assert any("nuclei is not installed" in item.subject for item in setup)
    nuclei = next(item for item in setup if "nuclei" in item.subject)
    assert "largest coverage gap" in nuclei.why


async def test_probable_findings_are_flagged_as_unfinished(
    db_session: AsyncSession, program: Program
) -> None:
    await upsert_finding(
        db_session, program.id, dedup_key="p", vuln_class="xss",
        title="Reflected XSS in 'q'", severity=Severity.HIGH,
        tier=FindingTier.PROBABLE, confidence=70, affected_hosts=["www.example.com"],
    )
    await db_session.commit()

    actions = await recommend(db_session, program, settings=Settings())
    assert any("awaiting confirmation" in item.subject for item in actions)


async def test_every_recommendation_says_what_and_why(
    db_session: AsyncSession, program: Program
) -> None:
    await upsert_asset(db_session, program.id, "admin.example.com", is_live=True)
    await upsert_finding(
        db_session, program.id, dedup_key="a", vuln_class="sqli", title="SQLi",
        severity=Severity.HIGH, tier=FindingTier.CONFIRMED, confidence=90,
        affected_hosts=["admin.example.com"],
    )
    await db_session.commit()

    actions = await recommend(db_session, program, settings=Settings())
    assert actions
    for item in actions:
        assert item.subject.strip(), f"{item.kind} has no subject"
        assert item.action.strip(), f"{item.subject} has no action"
        assert item.why.strip(), f"{item.subject} has no rationale"
        assert item.priority > 0


@pytest.mark.parametrize(
    ("kind", "expected_present"),
    [("finding", True), ("coverage", True), ("setup", True), ("nonsense", False)],
)
async def test_recommendations_carry_their_kind(
    db_session: AsyncSession, program: Program, kind: str, expected_present: bool
) -> None:
    await upsert_asset(db_session, program.id, "www.example.com", is_live=True)
    await upsert_endpoint(
        db_session, program.id, "https://www.example.com/s?q=1", parameters=["q"]
    )
    await upsert_finding(
        db_session, program.id, dedup_key="a", vuln_class="sqli", title="SQLi",
        severity=Severity.HIGH, tier=FindingTier.CONFIRMED, confidence=90,
        affected_hosts=["www.example.com"],
    )
    await db_session.commit()

    actions = await recommend(db_session, program, settings=Settings(), limit=50)
    kinds = {item.kind for item in actions}
    assert (kind in kinds) is expected_present
