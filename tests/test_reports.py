"""Tests for report generation."""

from __future__ import annotations

import json

from sqlalchemy.ext.asyncio import AsyncSession

from reconx.db.models import FindingTier, Program, Severity
from reconx.db.store import add_evidence, upsert_asset, upsert_endpoint, upsert_finding
from reconx.report.html import build_html_report
from reconx.report.json_export import build_json_report, dump_json_report
from reconx.report.markdown import build_markdown_report
from reconx.report.repro import curl_command, http_request_text


async def seed(session: AsyncSession, program: Program) -> None:
    await upsert_asset(
        session, program.id, "www.example.com",
        is_live=True, http_status=200, title="Home", server="nginx",
        technologies=["nginx", "React"],
    )
    await upsert_asset(
        session, program.id, "rescued.example.com",
        is_live=True, http_status=200,
        wildcard_cleared_by="HTTP fingerprint diverged from the wildcard baseline",
    )
    await upsert_endpoint(
        session, program.id, "https://www.example.com/.git/config",
        status=200, interesting_score=4.0, source="wordlist",
    )
    confirmed, _ = await upsert_finding(
        session, program.id,
        dedup_key="sqli::/search::q", vuln_class="sqli",
        title="SQL injection in 'q' at /search",
        severity=Severity.CRITICAL, tier=FindingTier.CONFIRMED, confidence=95,
        priority=9.7, affected_hosts=["www.example.com"],
        signals=["boolean_differential", "error_signature"],
        description="Two independent oracles agree, each reproduced.",
        recommendation="Establish impact without touching data.",
        reproduced_count=3, attempt_count=3,
    )
    await add_evidence(
        session, confirmed.id, label="boolean differential",
        request_url="https://www.example.com/search?q=1",
        curl_command="curl -sS -i -k 'https://www.example.com/search?q=1'",
        note="true/false similarity 0.41",
    )
    await upsert_finding(
        session, program.id,
        dedup_key="sqli::/static::id", vuln_class="sqli",
        title="SQL injection in 'id' at /static",
        severity=Severity.HIGH, tier=FindingTier.DISCARDED,
        discard_reason=(
            "a MySQL error string is already present in the unmodified page, so its "
            "appearance under a payload says nothing"
        ),
    )
    await upsert_finding(
        session, program.id,
        dedup_key="xss::/echo::q", vuln_class="xss",
        title="Reflected XSS in 'q' at /echo",
        severity=Severity.HIGH, tier=FindingTier.NEEDS_REVIEW, confidence=45,
        description="escape characters survive but the payload did not execute",
    )
    await session.commit()


# ---------------------------------------------------------------------------
# reproduction commands
# ---------------------------------------------------------------------------


def test_curl_quotes_a_payload_containing_quotes() -> None:
    """A reproduction that does not paste cleanly is not a reproduction."""
    command = curl_command("GET", "https://x.example.com/s?q=' OR 1=1--")
    assert command.startswith("curl -sS -i -k ")
    assert "OR 1=1--" in command


def test_curl_skips_noisy_headers_but_keeps_the_useful_ones() -> None:
    command = curl_command(
        "GET",
        "https://x.example.com/",
        headers={
            "User-Agent": "ReconX",
            "Host": "x.example.com",
            "Content-Length": "0",
            "Cookie": "session=abc",
        },
    )
    assert "User-Agent: ReconX" in command
    assert "Host:" not in command
    assert "Content-Length" not in command
    assert "session=abc" not in command


def test_curl_can_include_cookies_when_asked() -> None:
    command = curl_command(
        "GET", "https://x.example.com/", headers={"Cookie": "session=abc"},
        include_cookies=True,
    )
    assert "session=abc" in command


def test_curl_carries_a_method_and_body() -> None:
    command = curl_command(
        "POST", "https://x.example.com/api",
        headers={"Content-Type": "application/json"}, body='{"a":1}',
    )
    assert "-X POST" in command
    assert "--data-raw" in command


def test_raw_request_text_is_pasteable_into_a_proxy() -> None:
    text = http_request_text(
        "GET", "https://x.example.com/s?q=1", headers={"User-Agent": "ReconX"}
    )
    assert text.splitlines()[0] == "GET /s?q=1 HTTP/1.1"
    assert "Host: x.example.com" in text


# ---------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------


async def test_markdown_leads_with_authorization_and_findings(
    db_session: AsyncSession, program: Program
) -> None:
    await seed(db_session, program)
    text = await build_markdown_report(db_session, program)

    assert text.startswith("# Example Corp VDP")
    assert "Authorized by **researcher@example.com**" in text
    # Findings before hosts: the findings are why anyone reads this.
    assert text.index("## Findings") < text.index("## Hosts answering over HTTP")
    assert "SQL injection in 'q' at /search" in text
    assert "boolean_differential" in text
    assert "Reproduced 3 of 3 attempts" in text
    assert "What to do next:" in text


async def test_markdown_counts_discards_but_hides_them_by_default(
    db_session: AsyncSession, program: Program
) -> None:
    await seed(db_session, program)
    brief = await build_markdown_report(db_session, program)
    assert "Findings discarded by verification | 1" in brief
    assert "already present in the unmodified page" not in brief

    full = await build_markdown_report(db_session, program, include_discarded=True)
    assert "already present in the unmodified page" in full


async def test_markdown_explains_hosts_rescued_from_a_wildcard(
    db_session: AsyncSession, program: Program
) -> None:
    await seed(db_session, program)
    text = await build_markdown_report(db_session, program)
    assert "recovered from a wildcard zone" in text
    assert "rescued.example.com" in text


async def test_markdown_survives_an_empty_program(
    db_session: AsyncSession, program: Program
) -> None:
    text = await build_markdown_report(db_session, program)
    assert "# Example Corp VDP" in text
    assert "Nothing surfaced yet" in text


# ---------------------------------------------------------------------------
# html
# ---------------------------------------------------------------------------


async def test_html_is_self_contained(
    db_session: AsyncSession, program: Program
) -> None:
    """A report that needs the network to render is useless in an air-gapped review."""
    await seed(db_session, program)
    html = await build_html_report(db_session, program)

    assert html.lower().startswith("<!doctype html>")
    assert "<style>" in html
    assert "<link" not in html
    assert "<script" not in html
    assert "src=\"http" not in html


async def test_html_supports_both_colour_schemes(
    db_session: AsyncSession, program: Program
) -> None:
    await seed(db_session, program)
    html = await build_html_report(db_session, program)
    assert "prefers-color-scheme: dark" in html
    assert '[data-theme="light"]' in html
    assert '[data-theme="dark"]' in html


async def test_html_is_usable_at_phone_width(
    db_session: AsyncSession, program: Program
) -> None:
    await seed(db_session, program)
    html = await build_html_report(db_session, program)
    assert 'name="viewport"' in html
    assert "max-width: 600px" in html
    assert 'class="scroll"' in html  # wide tables scroll rather than overflow


async def test_html_shows_findings_evidence_and_discards(
    db_session: AsyncSession, program: Program
) -> None:
    await seed(db_session, program)
    html = await build_html_report(db_session, program)
    assert "SQL injection in &#x27;q&#x27; at /search" in html or "SQL injection" in html
    assert "curl -sS" in html
    assert "Discarded by verification" in html
    assert "already present in the unmodified page" in html
    assert "Needs a human look" in html


async def test_html_escapes_content(db_session: AsyncSession, program: Program) -> None:
    """Findings contain attacker-shaped strings by definition."""
    await upsert_finding(
        db_session, program.id,
        dedup_key="xss::/x::q", vuln_class="xss",
        title="XSS with <script>alert(1)</script> in the title",
        severity=Severity.HIGH, tier=FindingTier.CONFIRMED, confidence=95,
        description="payload was <img src=x onerror=alert(1)>",
    )
    await db_session.commit()
    html = await build_html_report(db_session, program)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "onerror=alert(1)>" not in html


# ---------------------------------------------------------------------------
# json
# ---------------------------------------------------------------------------


async def test_json_export_includes_discards_by_default(
    db_session: AsyncSession, program: Program
) -> None:
    """An archive that drops the discards loses the record of what was rejected."""
    await seed(db_session, program)
    payload = await build_json_report(db_session, program)

    assert payload["totals"]["findings_confirmed"] == 1
    assert payload["totals"]["findings_discarded"] == 1
    tiers = {finding["tier"] for finding in payload["findings"]}
    assert "discarded" in tiers
    assert "confirmed" in tiers


async def test_json_export_can_omit_discards(
    db_session: AsyncSession, program: Program
) -> None:
    await seed(db_session, program)
    payload = await build_json_report(db_session, program, include_discarded=False)
    assert all(finding["tier"] != "discarded" for finding in payload["findings"])


async def test_json_export_carries_provenance_and_evidence(
    db_session: AsyncSession, program: Program
) -> None:
    await seed(db_session, program)
    payload = await build_json_report(db_session, program)

    assert payload["program"]["authorized_by"] == "researcher@example.com"
    assert payload["program"]["scope_yaml"]
    assert payload["reconx_version"]
    confirmed = next(f for f in payload["findings"] if f["tier"] == "confirmed")
    assert confirmed["signals"] == ["boolean_differential", "error_signature"]
    assert confirmed["evidence"][0]["curl_command"].startswith("curl ")


async def test_json_export_is_valid_json(
    db_session: AsyncSession, program: Program
) -> None:
    await seed(db_session, program)
    text = await dump_json_report(db_session, program)
    parsed = json.loads(text)
    assert parsed["program"]["slug"] == "example-corp-vdp"
