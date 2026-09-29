"""Markdown reporting.

Written for a researcher deciding what to look at next, so it leads with what
changed and what is worth attention, and puts the filter accounting where it can
be checked rather than hiding it.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx.db.models import (
    Asset,
    AssetKind,
    Finding,
    FindingTier,
    Observation,
    Program,
    ScanRun,
    Severity,
    StageRun,
)

__all__ = ["build_markdown_report"]

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _fmt(value: datetime | None) -> str:
    if value is None:
        return "never"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.strftime("%Y-%m-%d %H:%M UTC")


async def build_markdown_report(
    session: AsyncSession, program: Program, *, include_discarded: bool = False
) -> str:
    """Render a full Markdown report for one program."""
    assets = list(
        (
            await session.execute(
                select(Asset)
                .where(Asset.program_id == program.id)
                .order_by(Asset.host)
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
    runs = list(
        (
            await session.execute(
                select(ScanRun)
                .where(ScanRun.program_id == program.id)
                .order_by(ScanRun.started_at.desc())
                .limit(5)
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

    lines: list[str] = []
    add = lines.append

    # --- header ----------------------------------------------------------
    add(f"# {program.name}")
    add("")
    add(f"*Generated {_fmt(datetime.now(UTC))} by ReconX*")
    add("")
    if program.program_url:
        add(f"Program: {program.program_url}")
    add(f"Authorized by **{program.authorized_by}** on {program.authorization_date}")
    add("")
    add("> " + program.attestation.replace("\n", " ").strip())
    add("")

    # --- at a glance -----------------------------------------------------
    live = [asset for asset in assets if asset.is_live]
    domains = [asset for asset in assets if asset.kind == AssetKind.DOMAIN]
    ips = [asset for asset in assets if asset.kind == AssetKind.IP]
    surfaced = [
        finding
        for finding in findings
        if finding.tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE)
    ]
    discarded = [finding for finding in findings if finding.tier == FindingTier.DISCARDED]

    add("## At a glance")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Assets known | {len(assets)} |")
    add(f"| Hostnames | {len(domains)} |")
    add(f"| IP addresses | {len(ips)} |")
    add(f"| Answering over HTTP | {len(live)} |")
    add(f"| Findings surfaced | {len(surfaced)} |")
    add(f"| Findings discarded by verification | {len(discarded)} |")
    add("")

    # --- findings ---------------------------------------------------------
    if surfaced:
        add("## Findings")
        add("")
        for finding in sorted(
            surfaced, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), -f.priority)
        ):
            add(
                f"### {finding.severity.value.upper()} — {finding.title} "
                f"({finding.tier.value}, confidence {finding.confidence})"
            )
            add("")
            if finding.description:
                add(finding.description)
                add("")
            if finding.signals:
                add(f"- Agreeing signals: {', '.join(finding.signals)}")
            if finding.attempt_count:
                add(
                    f"- Reproduced {finding.reproduced_count} of "
                    f"{finding.attempt_count} attempts"
                )
            if finding.affected_hosts:
                shown = ", ".join(finding.affected_hosts[:10])
                extra = (
                    f" and {len(finding.affected_hosts) - 10} more"
                    if len(finding.affected_hosts) > 10
                    else ""
                )
                add(f"- Affects {len(finding.affected_hosts)} host(s): {shown}{extra}")
            if finding.tested_while_throttled:
                # Set for a host that was blocking or throttling *and* for a scan
                # whose session expired. Both mean the same thing to a reader --
                # this was measured in a state where results cannot be trusted --
                # and the description names which one it was.
                add(
                    "- **Note:** this was measured while the target or the scan's "
                    "session was in a state that makes the result unreliable; the "
                    "description says which"
                )
            if finding.recommendation:
                add("")
                add(f"**What to do next:** {finding.recommendation}")
            add("")
    else:
        add("## Findings")
        add("")
        add("Nothing surfaced yet. Run the vulnerability stages, or check the")
        add("discarded list below if you expected something here.")
        add("")

    # --- discarded --------------------------------------------------------
    if discarded:
        add("## Discarded by verification")
        add("")
        add(
            f"{len(discarded)} candidate(s) were filtered out. They are kept with "
            "their reason so the filter can be checked rather than trusted."
        )
        add("")
        if include_discarded:
            add("| Class | Title | Reason |")
            add("|---|---|---|")
            for finding in discarded[:100]:
                reason = (finding.discard_reason or "").replace("|", "\\|")[:160]
                add(f"| {finding.vuln_class} | {finding.title[:60]} | {reason} |")
            add("")
        else:
            add("Pass `--include-discarded` to list them.")
            add("")

    # --- assets -----------------------------------------------------------
    add("## Hosts answering over HTTP")
    add("")
    if live:
        add("| Host | Status | Title | Server | Technologies |")
        add("|---|---|---|---|---|")
        for asset in live[:300]:
            title = (asset.title or "").replace("|", "\\|")[:50]
            tech = ", ".join(asset.technologies or [])[:50]
            add(
                f"| {asset.host} | {asset.http_status or '-'} | {title} | "
                f"{asset.server or '-'} | {tech} |"
            )
        if len(live) > 300:
            add("")
            add(f"...and {len(live) - 300} more.")
        add("")
    else:
        add("No hosts have been probed yet.")
        add("")

    # --- wildcard-cleared hosts ------------------------------------------
    rescued = [asset for asset in assets if asset.wildcard_cleared_by]
    if rescued:
        add("## Hosts recovered from a wildcard zone")
        add("")
        add(
            "These names resolve through wildcard DNS, so DNS alone could not tell "
            "them apart from a catch-all. They were kept because their HTTP response "
            "differs from what the wildcard serves."
        )
        add("")
        for asset in rescued[:50]:
            add(f"- `{asset.host}` — {asset.wildcard_cleared_by}")
        add("")

    # --- information gathering -------------------------------------------
    if observations:
        grouped: dict[str, list[Observation]] = defaultdict(list)
        for observation in observations:
            grouped[observation.kind].append(observation)

        add("## Information gathered")
        add("")
        for kind in sorted(grouped):
            entries = grouped[kind]
            add(f"### {kind.replace('_', ' ').title()} ({len(entries)})")
            add("")
            for observation in sorted(entries, key=lambda o: o.key)[:40]:
                add(f"- `{observation.key}` = {observation.value[:200]}")
            if len(entries) > 40:
                add(f"- ...and {len(entries) - 40} more")
            add("")

    # --- run history and filter accounting -------------------------------
    add("## Scan history")
    add("")
    if runs:
        add("| Started | Status | Stages | Requests | DNS | Out-of-scope blocked |")
        add("|---|---|---|---|---|---|")
        for run in runs:
            add(
                f"| {_fmt(run.started_at)} | {run.status.value} | "
                f"{len(run.stages_requested)} | {run.requests_made} | "
                f"{run.dns_queries} | {run.out_of_scope_blocked} |"
            )
        add("")

        latest = runs[0]
        stage_rows = list(
            (
                await session.execute(
                    select(StageRun)
                    .where(StageRun.scan_run_id == latest.id)
                    .order_by(StageRun.started_at)
                )
            ).scalars().all()
        )
        if stage_rows:
            add("### What the last run filtered, and why")
            add("")
            add("| Stage | In | Out | Filtered | Reasons |")
            add("|---|---|---|---|---|")
            for stage in stage_rows:
                reasons = ", ".join(
                    f"{key}: {value}" for key, value in (stage.filter_reasons or {}).items()
                )
                add(
                    f"| {stage.stage} | {stage.items_in} | {stage.items_out} | "
                    f"{stage.items_filtered} | {reasons or '-'} |"
                )
            add("")
    else:
        add("No scans have run yet.")
        add("")

    return "\n".join(lines) + "\n"
