"""Self-contained HTML report.

One file, no external requests, readable in light and dark. Written for two
audiences: a researcher deciding what to work on, and a programme triager who
needs to reproduce a finding without asking questions.

Findings lead, each with the reason it was believed, the oracles that agreed, and
a copyable reproduction. The discarded list follows, because a filter you cannot
inspect is a filter you should not trust.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx.db.models import (
    Asset,
    AssetKind,
    Endpoint,
    Evidence,
    Finding,
    FindingTier,
    Observation,
    Program,
    ScanRun,
    Severity,
    StageRun,
)

__all__ = ["build_html_report"]

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_CSS = """
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #5f6b7a; --line: #e3e8ee;
  --card: #f7f9fc; --code-bg: #f0f3f7;
  --critical: #b3123b; --high: #c2410c; --medium: #a16207;
  --low: #0369a1; --info: #52606d;
  --ok: #047857; --warn: #b45309;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14181d; --fg: #e8edf2; --muted: #9aa7b4; --line: #2a323b;
    --card: #1b2127; --code-bg: #10141a;
    --critical: #ff7a94; --high: #ffa66b; --medium: #f0c36a;
    --low: #7cc4f0; --info: #a3b0bd;
    --ok: #5ddba8; --warn: #f5c164;
  }
}
:root[data-theme="dark"] {
  --bg: #14181d; --fg: #e8edf2; --muted: #9aa7b4; --line: #2a323b;
  --card: #1b2127; --code-bg: #10141a;
  --critical: #ff7a94; --high: #ffa66b; --medium: #f0c36a;
  --low: #7cc4f0; --info: #a3b0bd;
  --ok: #5ddba8; --warn: #f5c164;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 1060px; margin: 0 auto; padding: 32px 16px 96px; }
h1 { font-size: 1.9rem; margin: 0 0 4px; letter-spacing: -0.02em; }
h2 { font-size: 1.3rem; margin: 44px 0 14px; padding-bottom: 8px;
     border-bottom: 1px solid var(--line); }
h3 { font-size: 1.02rem; margin: 0 0 8px; }
p { margin: 0 0 12px; }
a { color: var(--low); }
.sub { color: var(--muted); font-size: 0.88rem; margin-bottom: 18px; }
.attest { background: var(--card); border-left: 3px solid var(--ok);
          padding: 12px 16px; border-radius: 0 6px 6px 0; color: var(--muted);
          font-size: 0.9rem; margin: 0 0 24px; }
.stats { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
         margin: 0 0 8px; }
.stat { background: var(--card); border: 1px solid var(--line); border-radius: 8px;
        padding: 14px 16px; }
.stat .n { font-size: 1.7rem; font-weight: 650; letter-spacing: -0.02em; }
.stat .l { color: var(--muted); font-size: 0.78rem; text-transform: uppercase;
           letter-spacing: 0.05em; }
.finding { background: var(--card); border: 1px solid var(--line);
           border-left: 4px solid var(--info); border-radius: 0 8px 8px 0;
           padding: 16px 18px; margin: 0 0 16px; }
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.tags { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 10px; }
.tag { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em;
       padding: 2px 8px; border-radius: 999px; border: 1px solid var(--line);
       color: var(--muted); white-space: nowrap; }
.tag.sev-critical { color: var(--critical); border-color: var(--critical); }
.tag.sev-high { color: var(--high); border-color: var(--high); }
.tag.sev-medium { color: var(--medium); border-color: var(--medium); }
.tag.sev-low { color: var(--low); border-color: var(--low); }
.tag.confirmed { color: var(--ok); border-color: var(--ok); }
.tag.probable { color: var(--warn); border-color: var(--warn); }
.why { color: var(--muted); font-size: 0.92rem; }
.next { background: var(--bg); border: 1px dashed var(--line); border-radius: 6px;
        padding: 10px 12px; margin: 12px 0 0; font-size: 0.92rem; }
.next b { color: var(--fg); }
pre, code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
pre { background: var(--code-bg); border: 1px solid var(--line); border-radius: 6px;
      padding: 10px 12px; overflow-x: auto; font-size: 0.82rem; margin: 10px 0 0; }
code { background: var(--code-bg); padding: 1px 5px; border-radius: 4px;
       font-size: 0.86em; }
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { color: var(--muted); font-size: 0.76rem; text-transform: uppercase;
     letter-spacing: 0.05em; font-weight: 600; }
td.wrap-any { word-break: break-all; }
.scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
.empty { color: var(--muted); font-style: italic; }
details { margin: 10px 0 0; }
summary { cursor: pointer; color: var(--muted); font-size: 0.88rem; }
@media (max-width: 600px) {
  .wrap { padding: 20px 16px 72px; }
  h1 { font-size: 1.5rem; }
}
"""


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _fmt(value: datetime | None) -> str:
    if value is None:
        return "never"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.strftime("%Y-%m-%d %H:%M UTC")


async def build_html_report(
    session: AsyncSession, program: Program, *, include_discarded: bool = True
) -> str:
    """Render a standalone HTML report for one program."""
    assets = list(
        (
            await session.execute(
                select(Asset).where(Asset.program_id == program.id).order_by(Asset.host)
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
    endpoints = list(
        (
            await session.execute(
                select(Endpoint)
                .where(Endpoint.program_id == program.id)
                .order_by(Endpoint.interesting_score.desc())
                .limit(200)
            )
        ).scalars().all()
    )
    runs = list(
        (
            await session.execute(
                select(ScanRun)
                .where(ScanRun.program_id == program.id)
                .order_by(ScanRun.started_at.desc())
                .limit(10)
            )
        ).scalars().all()
    )
    observations = list(
        (
            await session.execute(
                select(Observation).where(Observation.program_id == program.id).limit(2000)
            )
        ).scalars().all()
    )

    surfaced = [
        f for f in findings if f.tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE)
    ]
    review = [f for f in findings if f.tier is FindingTier.NEEDS_REVIEW]
    discarded = [f for f in findings if f.tier is FindingTier.DISCARDED]
    live = [a for a in assets if a.is_live]

    parts: list[str] = []
    add = parts.append

    add("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add(f"<title>{_esc(program.name)} — ReconX</title>")
    add(f"<style>{_CSS}</style></head><body><div class=\"wrap\">")

    # --- header ----------------------------------------------------------
    add(f"<h1>{_esc(program.name)}</h1>")
    add(
        f'<div class="sub">ReconX report · generated {_fmt(datetime.now(UTC))}'
        + (
            f' · <a href="{_esc(program.program_url)}">programme page</a>'
            if program.program_url
            else ""
        )
        + "</div>"
    )
    add(
        f'<div class="attest">Authorised by <b>{_esc(program.authorized_by)}</b> on '
        f"{_esc(program.authorization_date)}<br>{_esc(program.attestation)}</div>"
    )

    # --- at a glance ------------------------------------------------------
    add("<h2>At a glance</h2><div class=\"stats\">")
    for number, label in (
        (len(surfaced), "findings surfaced"),
        (len([f for f in surfaced if f.tier is FindingTier.CONFIRMED]), "confirmed"),
        (len(review), "need review"),
        (len(discarded), "discarded by verification"),
        (len(assets), "assets known"),
        (len(live), "answering over HTTP"),
        (len(endpoints), "endpoints recorded"),
    ):
        add(f'<div class="stat"><div class="n">{number}</div><div class="l">{label}</div></div>')
    add("</div>")

    # --- findings ---------------------------------------------------------
    add("<h2>Findings</h2>")
    if not surfaced:
        add(
            '<p class="empty">Nothing surfaced. If you expected something, check the '
            "discarded list below: it records why each candidate was rejected.</p>"
        )
    for finding in sorted(
        surfaced, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), -f.priority)
    ):
        evidence = list(
            (
                await session.execute(
                    select(Evidence).where(Evidence.finding_id == finding.id)
                )
            ).scalars().all()
        )
        severity = finding.severity.value
        add(f'<div class="finding {severity}">')
        add('<div class="tags">')
        add(f'<span class="tag sev-{severity}">{severity}</span>')
        add(f'<span class="tag {finding.tier.value}">{finding.tier.value}</span>')
        add(f'<span class="tag">confidence {finding.confidence}</span>')
        add(f'<span class="tag">priority {finding.priority:.1f}</span>')
        for signal in finding.signals or []:
            add(f'<span class="tag">{_esc(signal)}</span>')
        if finding.tested_while_throttled:
            add('<span class="tag probable">host was throttling</span>')
        add("</div>")
        add(f"<h3>{_esc(finding.title)}</h3>")
        if finding.description:
            add(f'<p class="why">{_esc(finding.description)}</p>')

        hosts = finding.affected_hosts or []
        if hosts:
            shown = ", ".join(_esc(host) for host in hosts[:12])
            more = f" and {len(hosts) - 12} more" if len(hosts) > 12 else ""
            add(f'<p class="why">Affects {len(hosts)} host(s): {shown}{more}</p>')

        if finding.recommendation:
            add(f'<div class="next"><b>What to do next:</b> {_esc(finding.recommendation)}</div>')

        runnable = [item for item in evidence if item.curl_command]
        if runnable:
            add("<details open><summary>Reproduce</summary>")
            for item in runnable[:4]:
                if item.label:
                    add(f'<p class="why" style="margin:8px 0 0">{_esc(item.label)}</p>')
                add(f"<pre>{_esc(item.curl_command)}</pre>")
            add("</details>")
        notes = [item for item in evidence if item.note and not item.curl_command]
        if notes:
            add("<details><summary>Evidence notes</summary>")
            for item in notes[:6]:
                add(f'<p class="why">{_esc(item.label)}: {_esc(item.note)}</p>')
            add("</details>")
        add("</div>")

    # --- needs review -----------------------------------------------------
    if review:
        add("<h2>Needs a human look</h2>")
        add(
            '<p class="why">The engine could not decide these, usually because the host '
            "was rate-limiting or a payload behaved unusually. An undecided candidate is "
            "where a real bug is most likely hiding.</p>"
        )
        add('<div class="scroll"><table><tr><th>Severity</th><th>Class</th>'
            "<th>Title</th><th>Why undecided</th></tr>")
        for finding in review[:60]:
            add(
                f"<tr><td>{_esc(finding.severity.value)}</td>"
                f"<td>{_esc(finding.vuln_class)}</td>"
                f"<td class='wrap-any'>{_esc(finding.title)}</td>"
                f"<td class='why'>{_esc((finding.description or '')[:300])}</td></tr>"
            )
        add("</table></div>")

    # --- discarded --------------------------------------------------------
    add("<h2>Discarded by verification</h2>")
    if not discarded:
        add('<p class="empty">Nothing was filtered out.</p>')
    else:
        add(
            f'<p class="why">{len(discarded)} candidate(s) were rejected. They are kept '
            "with the reason so the filter can be checked rather than trusted. Most "
            "scanners would have reported these.</p>"
        )
        if include_discarded:
            add('<div class="scroll"><table><tr><th>Class</th><th>Title</th>'
                "<th>Why it was rejected</th></tr>")
            for finding in discarded[:200]:
                add(
                    f"<tr><td>{_esc(finding.vuln_class)}</td>"
                    f"<td class='wrap-any'>{_esc(finding.title)}</td>"
                    f"<td class='why'>{_esc(finding.discard_reason or '')}</td></tr>"
                )
            add("</table></div>")

    # --- assets -----------------------------------------------------------
    add("<h2>Hosts answering over HTTP</h2>")
    if not live:
        add('<p class="empty">No host has been confirmed live yet.</p>')
    else:
        add('<div class="scroll"><table><tr><th>Host</th><th>Status</th><th>Title</th>'
            "<th>Server</th><th>Technologies</th><th>First seen</th></tr>")
        for asset in live[:300]:
            add(
                f"<tr><td class='wrap-any'>{_esc(asset.host)}</td>"
                f"<td>{_esc(asset.http_status or '-')}</td>"
                f"<td>{_esc((asset.title or '')[:60])}</td>"
                f"<td>{_esc(asset.server or '-')}</td>"
                f"<td>{_esc(', '.join(asset.technologies or [])[:60])}</td>"
                f"<td>{_fmt(asset.first_seen)}</td></tr>"
            )
        add("</table></div>")

    rescued = [a for a in assets if a.wildcard_cleared_by]
    if rescued:
        add("<h2>Hosts recovered from a wildcard zone</h2>")
        add(
            '<p class="why">These resolve through wildcard DNS, so DNS alone could not '
            "tell them from a catch-all. They were kept because their HTTP response "
            "differs from what the wildcard serves.</p>"
        )
        add('<div class="scroll"><table><tr><th>Host</th><th>Why it was kept</th></tr>')
        for asset in rescued[:80]:
            add(
                f"<tr><td class='wrap-any'>{_esc(asset.host)}</td>"
                f"<td class='why'>{_esc(asset.wildcard_cleared_by)}</td></tr>"
            )
        add("</table></div>")

    # --- endpoints --------------------------------------------------------
    interesting = [e for e in endpoints if e.interesting_score > 0]
    if interesting:
        add("<h2>Endpoints worth a look</h2>")
        add('<div class="scroll"><table><tr><th>URL</th><th>Status</th>'
            "<th>Parameters</th><th>Reflects</th><th>Score</th><th>Source</th></tr>")
        for endpoint in interesting[:120]:
            add(
                f"<tr><td class='wrap-any'>{_esc(endpoint.url)}</td>"
                f"<td>{_esc(endpoint.status or '-')}</td>"
                f"<td>{_esc(', '.join(endpoint.parameters or []) or '-')}</td>"
                f"<td>{_esc(', '.join(endpoint.reflected_parameters or []) or '-')}</td>"
                f"<td>{endpoint.interesting_score:.0f}</td>"
                f"<td>{_esc(endpoint.source)}</td></tr>"
            )
        add("</table></div>")

    # --- information gathered --------------------------------------------
    if observations:
        grouped: dict[str, list[Observation]] = {}
        for observation in observations:
            grouped.setdefault(observation.kind, []).append(observation)
        add("<h2>Information gathered</h2>")
        for kind in sorted(grouped):
            entries = grouped[kind]
            add(
                f"<details><summary>{_esc(kind.replace('_', ' ').title())} "
                f"({len(entries)})</summary>"
            )
            add('<div class="scroll"><table><tr><th>Key</th><th>Value</th>'
                "<th>Source</th></tr>")
            for observation in sorted(entries, key=lambda o: o.key)[:200]:
                add(
                    f"<tr><td class='wrap-any'>{_esc(observation.key)}</td>"
                    f"<td class='wrap-any'>{_esc(observation.value[:300])}</td>"
                    f"<td>{_esc(observation.source)}</td></tr>"
                )
            add("</table></div></details>")

    # --- runs and filter accounting --------------------------------------
    add("<h2>Scan history</h2>")
    if not runs:
        add('<p class="empty">No scan has run yet.</p>')
    else:
        add('<div class="scroll"><table><tr><th>Started</th><th>Status</th>'
            "<th>Trigger</th><th>Requests</th><th>DNS</th>"
            "<th>Out-of-scope blocked</th></tr>")
        for run in runs:
            add(
                f"<tr><td>{_fmt(run.started_at)}</td>"
                f"<td>{_esc(run.status.value)}</td>"
                f"<td>{_esc(run.trigger)}</td>"
                f"<td>{run.requests_made}</td><td>{run.dns_queries}</td>"
                f"<td>{run.out_of_scope_blocked}</td></tr>"
            )
        add("</table></div>")

        stage_rows = list(
            (
                await session.execute(
                    select(StageRun)
                    .where(StageRun.scan_run_id == runs[0].id)
                    .order_by(StageRun.started_at)
                )
            ).scalars().all()
        )
        if stage_rows:
            add("<h2>What the last run filtered, and why</h2>")
            add(
                '<p class="why">Every stage reports what it dropped. This is how the '
                "false-positive claim is checked rather than taken on trust.</p>"
            )
            add('<div class="scroll"><table><tr><th>Stage</th><th>In</th><th>Out</th>'
                "<th>Filtered</th><th>Reasons</th><th>Tools</th></tr>")
            for stage in stage_rows:
                reasons = ", ".join(
                    f"{key}: {value}"
                    for key, value in (stage.filter_reasons or {}).items()
                )
                add(
                    f"<tr><td>{_esc(stage.stage)}</td><td>{stage.items_in}</td>"
                    f"<td>{stage.items_out}</td><td>{stage.items_filtered}</td>"
                    f"<td class='why'>{_esc(reasons) or '-'}</td>"
                    f"<td>{_esc(', '.join(stage.tools_used or []) or 'built-in')}</td></tr>"
                )
            add("</table></div>")

    ip_count = len([a for a in assets if a.kind == AssetKind.IP])
    add(
        f'<h2>Scope</h2><p class="why">{len(assets) - ip_count} hostname(s) and '
        f"{ip_count} address(es) recorded under this scope. The authorising scope is "
        "stored with the programme and shown at the top of this report.</p>"
    )
    add("<pre>" + _esc(program.scope_yaml[:4000]) + "</pre>")

    add("</div></body></html>")
    return "".join(parts)
