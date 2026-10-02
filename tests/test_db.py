"""Tests for the persistence layer."""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx.db.models import (
    Asset,
    AssetKind,
    BaselineKind,
    Finding,
    FindingTier,
    Program,
    RunStatus,
    Severity,
)
from reconx.db.store import (
    add_evidence,
    finish_stage_run,
    get_baselines,
    get_program,
    record_observation,
    save_baseline,
    start_scan_run,
    start_stage_run,
    upsert_asset,
    upsert_endpoint,
    upsert_finding,
    upsert_program,
    upsert_schedule_entry,
    write_audit_entries,
)
from reconx.net.fingerprint import fingerprint_response
from tests.conftest import make_scope

# ---------------------------------------------------------------------------
# programs
# ---------------------------------------------------------------------------


async def test_program_stores_the_authorizing_scope_verbatim(db_session: AsyncSession) -> None:
    """Provenance: what authorized a scan must be recoverable from the row."""
    yaml_text = "program: Example Corp VDP\nin_scope:\n  - '*.example.com'\n"
    created = await upsert_program(db_session, make_scope(), scope_yaml=yaml_text)
    assert created.scope_yaml == yaml_text
    assert created.authorized_by == "researcher@example.com"
    assert created.attestation.startswith("I am authorized")


async def test_program_upsert_updates_rather_than_duplicates(db_session: AsyncSession) -> None:
    await upsert_program(db_session, make_scope(), scope_yaml="v1")
    await upsert_program(db_session, make_scope(program_url="https://new"), scope_yaml="v2")
    rows = (await db_session.execute(select(Program))).scalars().all()
    assert len(rows) == 1
    assert rows[0].scope_yaml == "v2"
    assert rows[0].program_url == "https://new"


async def test_get_program_by_slug(db_session: AsyncSession, program: Program) -> None:
    assert (await get_program(db_session, "example-corp-vdp")).id == program.id
    assert await get_program(db_session, "nonexistent") is None


# ---------------------------------------------------------------------------
# assets
# ---------------------------------------------------------------------------


async def test_new_asset_reports_itself_as_new(db_session: AsyncSession, program: Program) -> None:
    """The is_new flag is what the diff engine turns into an alert."""
    _, created_first = await upsert_asset(db_session, program.id, "www.example.com")
    _, created_again = await upsert_asset(db_session, program.id, "www.example.com")
    assert created_first is True
    assert created_again is False


async def test_asset_sources_accumulate_instead_of_overwriting(
    db_session: AsyncSession, program: Program
) -> None:
    """Three sources agreeing is a confidence signal worth keeping."""
    await upsert_asset(db_session, program.id, "www.example.com", sources=["crt.sh"])
    await upsert_asset(db_session, program.id, "www.example.com", sources=["subfinder"])
    asset, _ = await upsert_asset(db_session, program.id, "www.example.com", sources=["crt.sh"])
    assert asset.sources == ["crt.sh", "subfinder"]


async def test_asset_last_seen_advances_but_first_seen_does_not(
    db_session: AsyncSession, program: Program
) -> None:
    first, _ = await upsert_asset(db_session, program.id, "www.example.com")
    original_first_seen = first.first_seen
    again, _ = await upsert_asset(db_session, program.id, "www.example.com")
    assert again.first_seen == original_first_seen
    assert again.last_seen >= original_first_seen


async def test_asset_upsert_does_not_clobber_with_none(
    db_session: AsyncSession, program: Program
) -> None:
    """A later stage that knows nothing about the title must not erase it."""
    await upsert_asset(db_session, program.id, "www.example.com", title="Home", http_status=200)
    asset, _ = await upsert_asset(db_session, program.id, "www.example.com", title=None)
    assert asset.title == "Home"
    assert asset.http_status == 200


async def test_wildcard_suspect_flag_round_trips(
    db_session: AsyncSession, program: Program
) -> None:
    asset, _ = await upsert_asset(
        db_session, program.id, "random.example.com", wildcard_suspect=True
    )
    assert asset.wildcard_suspect is True
    cleared, _ = await upsert_asset(
        db_session,
        program.id,
        "random.example.com",
        wildcard_suspect=False,
        wildcard_cleared_by="fingerprint diverged from wildcard baseline",
    )
    assert cleared.wildcard_cleared_by is not None


async def test_ip_assets_are_distinguished_from_domains(
    db_session: AsyncSession, program: Program
) -> None:
    asset, _ = await upsert_asset(db_session, program.id, "203.0.113.5", kind=AssetKind.IP)
    assert asset.kind == AssetKind.IP


# ---------------------------------------------------------------------------
# endpoints and observations
# ---------------------------------------------------------------------------


async def test_endpoint_is_keyed_on_url_and_method(
    db_session: AsyncSession, program: Program
) -> None:
    url = "https://www.example.com/api/users"
    _, get_new = await upsert_endpoint(db_session, program.id, url, method="GET")
    _, post_new = await upsert_endpoint(db_session, program.id, url, method="POST")
    _, get_again = await upsert_endpoint(db_session, program.id, url, method="GET")
    assert (get_new, post_new, get_again) == (True, True, False)


async def test_endpoint_parameters_accumulate(
    db_session: AsyncSession, program: Program
) -> None:
    url = "https://www.example.com/search"
    await upsert_endpoint(db_session, program.id, url, parameters=["q"])
    endpoint, _ = await upsert_endpoint(db_session, program.id, url, parameters=["page", "q"])
    assert endpoint.parameters == ["q", "page"]


async def test_observations_deduplicate_on_value(
    db_session: AsyncSession, program: Program
) -> None:
    for _ in range(3):
        _, is_new = await record_observation(
            db_session, program.id, kind="dns", key="A", value="203.0.113.5", source="dnspython"
        )
    assert is_new is False
    _, changed = await record_observation(
        db_session, program.id, kind="dns", key="A", value="203.0.113.6"
    )
    assert changed is True


# ---------------------------------------------------------------------------
# baselines
# ---------------------------------------------------------------------------


async def test_baseline_unpacks_a_fingerprint(
    db_session: AsyncSession, program: Program
) -> None:
    fingerprint = fingerprint_response(
        status=404,
        body=b"<html><title>Not Found</title><body>no such page</body></html>",
        headers={"Content-Type": "text/html"},
    )
    baseline = await save_baseline(
        db_session,
        program.id,
        "www.example.com",
        BaselineKind.NOT_FOUND,
        fingerprint=fingerprint,
        sample_url="https://www.example.com/reconx-probe-abc123",
    )
    assert baseline.status == 404
    assert baseline.title == "Not Found"
    assert baseline.sha256 == fingerprint.body_sha256
    assert baseline.simhash == f"{fingerprint.simhash_value:016x}"


async def test_baselines_are_retrievable_per_host_kind_and_directory(
    db_session: AsyncSession, program: Program
) -> None:
    """Soft-404 pages often differ per directory, so path_scope matters."""
    fp = fingerprint_response(status=200, body=b"not found")
    await save_baseline(
        db_session, program.id, "a.example.com", BaselineKind.NOT_FOUND,
        fingerprint=fp, path_scope="/",
    )
    await save_baseline(
        db_session, program.id, "a.example.com", BaselineKind.NOT_FOUND,
        fingerprint=fp, path_scope="/admin/",
    )
    await save_baseline(
        db_session, program.id, "a.example.com", BaselineKind.WAF_BLOCK, fingerprint=fp
    )
    assert len(await get_baselines(db_session, program.id, "a.example.com")) == 3
    root_only = await get_baselines(
        db_session, program.id, "a.example.com",
        kind=BaselineKind.NOT_FOUND, path_scope="/",
    )
    assert len(root_only) == 1


# ---------------------------------------------------------------------------
# findings: correlation and discard retention
# ---------------------------------------------------------------------------


async def test_one_issue_across_fifty_hosts_collapses_to_one_finding(
    db_session: AsyncSession, program: Program
) -> None:
    """The difference between a usable report and a wall of duplicates."""
    hosts = [f"host{index}.example.com" for index in range(50)]
    for host in hosts:
        finding, _ = await upsert_finding(
            db_session,
            program.id,
            dedup_key="missing-security-headers::default",
            vuln_class="misconfiguration",
            title="Security headers missing",
            severity=Severity.LOW,
            affected_hosts=[host],
        )
    rows = (await db_session.execute(select(Finding))).scalars().all()
    assert len(rows) == 1
    assert len(rows[0].affected_hosts) == 50


async def test_discarded_findings_are_kept_with_their_reason(
    db_session: AsyncSession, program: Program
) -> None:
    """The filter must be auditable, not a black box."""
    finding, _ = await upsert_finding(
        db_session,
        program.id,
        dedup_key="sqli::/search::q",
        vuln_class="sqli",
        title="Possible SQL injection in q",
        severity=Severity.HIGH,
        tier=FindingTier.DISCARDED,
        discard_reason=(
            "error signature also present in the benign control response, so the "
            "string was already on the page"
        ),
        signals=["error_signature"],
        attempt_count=3,
        reproduced_count=3,
    )
    assert finding.tier == FindingTier.DISCARDED
    assert "benign control" in finding.discard_reason


async def test_finding_signals_accumulate_across_verification_passes(
    db_session: AsyncSession, program: Program
) -> None:
    key = "sqli::/item::id"
    await upsert_finding(
        db_session, program.id, dedup_key=key, vuln_class="sqli",
        title="SQLi in id", signals=["boolean_differential"],
    )
    finding, _ = await upsert_finding(
        db_session, program.id, dedup_key=key, vuln_class="sqli",
        title="SQLi in id", tier=FindingTier.CONFIRMED, confidence=95,
        signals=["time_differential"],
    )
    assert finding.signals == ["boolean_differential", "time_differential"]
    assert finding.tier == FindingTier.CONFIRMED


def test_a_weaker_duplicate_verdict_does_not_overwrite_a_stronger_one() -> None:
    """The same endpoint reached through a link and through a form yields two
    verdicts. Last-wins turned a Confirmed finding into a Probable one, so
    within one run the stronger stored verdict survives."""
    from reconx.stages.vulns import keep_existing_verdict

    assert keep_existing_verdict(
        FindingTier.CONFIRMED, 7, FindingTier.PROBABLE, 7
    ) is True
    assert keep_existing_verdict(
        FindingTier.PROBABLE, 7, FindingTier.CONFIRMED, 7
    ) is False
    assert keep_existing_verdict(
        FindingTier.DISCARDED, 7, FindingTier.DISCARDED, 7
    ) is True
    # Across runs the newest verdict still wins, so a fixed bug clears.
    assert keep_existing_verdict(
        FindingTier.CONFIRMED, 7, FindingTier.DISCARDED, 8
    ) is False


async def test_evidence_attaches_a_runnable_reproduction(
    db_session: AsyncSession, program: Program
) -> None:
    finding, _ = await upsert_finding(
        db_session, program.id, dedup_key="xss::/s::q", vuln_class="xss", title="XSS in q"
    )
    evidence = await add_evidence(
        db_session,
        finding.id,
        label="payload",
        request_method="GET",
        request_url="https://www.example.com/s?q=PAYLOAD",
        response_status=200,
        curl_command="curl -sS 'https://www.example.com/s?q=PAYLOAD'",
    )
    assert evidence.curl_command.startswith("curl ")


# ---------------------------------------------------------------------------
# run bookkeeping
# ---------------------------------------------------------------------------


async def test_stage_run_is_reused_when_a_run_is_resumed(
    db_session: AsyncSession, program: Program
) -> None:
    """Resuming must not create a second row for the same stage."""
    run = await start_scan_run(db_session, program.id, stages=["passive_recon", "subdomains"])
    first = await start_stage_run(db_session, run.id, program.id, "subdomains")
    await finish_stage_run(
        db_session, first, status=RunStatus.FAILED, error="network blip",
        checkpoint={"completed_sources": ["crt.sh"]},
    )
    resumed = await start_stage_run(db_session, run.id, program.id, "subdomains")
    assert resumed.id == first.id
    assert resumed.status == RunStatus.RUNNING
    assert resumed.error is None
    assert resumed.checkpoint == {"completed_sources": ["crt.sh"]}


async def test_stage_run_records_what_was_filtered_and_why(
    db_session: AsyncSession, program: Program
) -> None:
    run = await start_scan_run(db_session, program.id, stages=["subdomains"])
    stage = await start_stage_run(db_session, run.id, program.id, "subdomains")
    await finish_stage_run(
        db_session, stage, status=RunStatus.COMPLETED,
        items_in=12000, items_out=41, items_filtered=11959,
        filter_reasons={"wildcard_dns": 11890, "out_of_scope": 69},
        tools_used=["subfinder", "crt.sh"],
    )
    assert stage.items_filtered == 11959
    assert stage.filter_reasons["wildcard_dns"] == 11890


async def test_audit_entries_persist_refusals_too(
    db_session: AsyncSession, program: Program
) -> None:
    from datetime import datetime

    from reconx.net.http import AuditRecord

    records = [
        AuditRecord(
            timestamp=datetime.now(UTC), method="GET",
            url="https://www.example.com/", host="www.example.com",
            status=200, duration_ms=12.0, response_bytes=100,
        ),
        AuditRecord(
            timestamp=datetime.now(UTC), method="GET",
            url="https://evil.com/", host="evil.com",
            status=None, duration_ms=0.0, response_bytes=0,
            blocked=True, block_reason="no in-scope rule matches this URL",
        ),
    ]
    written = await write_audit_entries(db_session, records, program_id=program.id)
    assert written == 2


async def test_schedule_entry_is_per_program_and_stage(
    db_session: AsyncSession, program: Program
) -> None:
    _, new_a = await upsert_schedule_entry(
        db_session, program.id, "subdomains", interval_seconds=86400
    )
    _, new_b = await upsert_schedule_entry(
        db_session, program.id, "resolve_probe", interval_seconds=3600
    )
    entry, new_again = await upsert_schedule_entry(
        db_session, program.id, "subdomains", interval_seconds=43200
    )
    assert (new_a, new_b, new_again) == (True, True, False)
    assert entry.interval_seconds == 43200


# ---------------------------------------------------------------------------
# migrations
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_migrations_match_the_models(tmp_path: Path) -> None:
    """A forgotten migration is a silent data-loss bug on the next upgrade.

    Applies the migration chain to an empty database and asks Alembic whether
    the result still differs from the models.
    """
    db_file = tmp_path / "migration-check.db"
    # Inherit the real environment: overriding HOME would hide user-site
    # packages and make this fail for reasons unrelated to migrations.
    env = {**os.environ, "RECONX_DATABASE_URL": f"sqlite+aiosqlite:///{db_file}"}
    upgrade = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        capture_output=True, text=True, env=env, cwd=Path.cwd(),
    )
    assert upgrade.returncode == 0, upgrade.stderr

    check = subprocess.run(
        [sys.executable, "-m", "alembic", "check"],
        capture_output=True, text=True, env=env, cwd=Path.cwd(),
    )
    combined = check.stdout + check.stderr
    assert check.returncode == 0, (
        "the models and the migrations have drifted apart; generate a new "
        f"revision with 'alembic revision --autogenerate'.\n{combined}"
    )
    assert "No new upgrade operations detected" in combined


# ---------------------------------------------------------------------------
# concurrent writers
# ---------------------------------------------------------------------------


async def test_sqlite_uses_wal_so_parallel_stages_can_write(file_db) -> None:
    """Regression: parallel stages hit "database is locked" and one of them died.

    SQLite's default journal mode refuses a concurrent write immediately rather
    than waiting, so the port stage failed whenever it ran alongside content
    discovery. WAL plus a busy timeout is the fix.
    """
    from reconx.db.session import get_engine, sqlite_journal_mode

    engine = get_engine()
    assert await sqlite_journal_mode(engine) == "wal"


async def test_two_sessions_can_write_at_once(file_db) -> None:
    """The actual failure mode, reproduced directly."""
    import asyncio

    from reconx.db.session import get_session_factory
    from reconx.db.store import record_observation, upsert_asset, upsert_program
    from tests.conftest import make_scope

    factory = get_session_factory()
    async with factory() as session:
        program = await upsert_program(session, make_scope(), scope_yaml="program: x")
        await session.commit()
        program_id = program.id

    async def writer(tag: str, count: int) -> None:
        async with factory() as session:
            for index in range(count):
                await upsert_asset(
                    session, program_id, f"{tag}{index}.example.com", sources=[tag]
                )
                await record_observation(
                    session, program_id, kind="test", key=f"{tag}:{index}", value="v"
                )
            await session.commit()

    # Two concurrent writers, which is exactly what a parallel stage level does.
    await asyncio.gather(writer("a", 30), writer("b", 30))

    async with factory() as session:
        rows = (await session.execute(select(Asset))).scalars().all()
    assert len(rows) == 60
