"""What to do next.

A list of findings is not a plan. This turns the stored state into concrete next
actions, ordered, each saying what to do and why it is worth doing. Five kinds:

* **finding** — how to escalate or validate something already found,
* **asset** — an interesting host that has not produced a finding yet,
* **coverage** — work the pipeline has not done, which is where the unfound bugs
  are,
* **staleness** — data old enough that the target has probably moved,
* **setup** — something about the installation that is costing coverage.

Coverage gaps matter most and get looked at least. A researcher who knows that
twenty-three hosts have never been content-scanned has somewhere useful to go;
one staring at an empty findings list does not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx.config import Settings, get_settings
from reconx.db.models import (
    Asset,
    Endpoint,
    Finding,
    FindingTier,
    Program,
    ScheduleEntry,
    StageRun,
)
from reconx.triage.priority import asset_criticality, compute_priority

__all__ = ["Recommendation", "recommend", "PLAYBOOKS"]


@dataclass
class Recommendation:
    """One suggested next action."""

    kind: str
    subject: str
    action: str
    why: str
    priority: float = 1.0
    command: str | None = None
    tags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "subject": self.subject,
            "action": self.action,
            "why": self.why,
            "priority": round(self.priority, 2),
            "command": self.command,
            "tags": list(self.tags),
        }


# Per-class guidance for a finding that has already been verified. Written for a
# researcher deciding what to do with it, not as a definition of the bug class.
PLAYBOOKS: dict[str, tuple[str, str]] = {
    "sqli": (
        "Establish impact without touching data: read the database version and "
        "current user, and confirm which tables are reachable. Report with the "
        "boolean pair as proof.",
        "Do not dump or modify data unless the program explicitly permits it. "
        "Impact is demonstrated by proving the query is under your control, not "
        "by exfiltrating rows.",
    ),
    "xss": (
        "Decide whether it is reflected or stored, whether it fires without user "
        "interaction, and what a Content-Security-Policy would stop. Then check "
        "whether the same sink is reachable authenticated.",
        "Triage rates a stored, no-interaction XSS on an authenticated page far "
        "higher than a reflected one behind a click.",
    ),
    "subdomain_takeover": (
        "Document the full CNAME chain and the service's response. Claim the "
        "resource only if the program allows it, and if you do, serve a harmless "
        "proof file and nothing else.",
        "The fix is removing the dangling DNS record, so name the exact record in "
        "the report.",
    ),
    "exposed_secret": (
        "Establish whether the value is actually a credential before escalating. "
        "Many client identifiers are public by design.",
        "Reporting a publishable client ID as a leaked secret costs credibility. "
        "If it is real, report it and recommend rotation rather than testing how "
        "far it reaches.",
    ),
    "nuclei": (
        "Open the matched URL and confirm the template's claim by hand.",
        "A template says where to look, not what is true. This one reproduced, "
        "which is not the same as being exploitable.",
    ),
    "open_redirect": (
        "Establish what the redirect is worth before reporting it. On its own it "
        "is usually low: chain it with something that trusts the destination, such "
        "as an OAuth redirect_uri, a password-reset link, or a token in the "
        "fragment that survives the hop.",
        "An open redirect with no chain is routinely closed as informational. The "
        "report that lands is the one showing what leaks across the hop.",
    ),
    "cors_misconfiguration": (
        "Show what an attacking page can actually read. Name one endpoint that "
        "returns something sensitive to a cookie-authenticated request, and prove "
        "the reflected origin plus credentials makes it readable cross-origin.",
        "Reflecting an origin without credentials is usually not exploitable, and "
        "a wildcard '*' never is. The fix is an allowlist compared exactly, not a "
        "substring match.",
    ),
    "path_traversal": (
        "You have proved the boundary is crossed. Stop there and report it: name "
        "the parameter, the depth needed, and the one file record you matched. Do "
        "not walk the filesystem or read application configuration.",
        "Impact is established by the boundary crossing, not by how much you read. "
        "Reading beyond proof turns a clean report into a data-handling problem.",
    ),
    "template_injection": (
        "Report the evaluation itself, with the engine named and the computed "
        "value as proof. Whether to go further towards code execution is a "
        "decision for the program's rules, not a default.",
        "Template injection is usually rated on what the engine allows, so naming "
        "the engine is most of the triage. An unsandboxed engine is critical; a "
        "sandboxed one may be medium.",
    ),
    "command_injection": (
        "Report it on the computed value alone: the arithmetic the shell performed "
        "is complete proof that the command string is under your control. Confirm "
        "the affected parameter and the separator that worked.",
        "This is normally critical and needs nothing further to demonstrate. "
        "Running anything beyond arithmetic on someone else's host is the kind of "
        "escalation that gets a report closed and an account banned.",
    ),
    "ssrf": (
        "Establish reach, which is what decides severity: whether the request can "
        "be pointed at cloud metadata, at an internal service, or only outward. "
        "Report with the callback log and the exact parameter value.",
        "A blind SSRF that can only reach the internet is usually low. The same bug "
        "reaching a metadata endpoint or an internal admin service is critical, so "
        "say which one you established and how.",
    ),
    "misconfiguration": (
        "Work out what the misconfiguration actually enables before reporting it.",
        "Most misconfiguration reports are closed as informational because the "
        "impact was never established.",
    ),
}

_DEFAULT_PLAYBOOK = (
    "Reproduce it from the recorded request, then establish what it enables.",
    "A finding without demonstrated impact is usually closed as informational.",
)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def recommend(
    session: AsyncSession,
    program: Program,
    *,
    settings: Settings | None = None,
    limit: int = 30,
    tool_statuses: dict | None = None,
) -> list[Recommendation]:
    """Build an ordered list of next actions for one program."""
    resolved = settings or get_settings()
    out: list[Recommendation] = []

    assets = (
        await session.execute(select(Asset).where(Asset.program_id == program.id))
    ).scalars().all()
    endpoints = (
        await session.execute(select(Endpoint).where(Endpoint.program_id == program.id))
    ).scalars().all()
    findings = (
        await session.execute(select(Finding).where(Finding.program_id == program.id))
    ).scalars().all()

    out.extend(_from_findings(program, findings, assets))
    out.extend(_from_assets(program, assets, endpoints, findings))
    out.extend(_coverage_gaps(program, assets, endpoints, findings))
    out.extend(await _staleness(session, program))
    out.extend(_setup_gaps(program, resolved, tool_statuses))

    out.sort(key=lambda item: -item.priority)
    return out[:limit]


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


def _from_findings(
    program: Program, findings: list[Finding], assets: list[Asset]
) -> list[Recommendation]:
    by_host = {asset.host: asset for asset in assets}
    out: list[Recommendation] = []

    surfaced = [
        finding
        for finding in findings
        if finding.tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE)
    ]
    # Compute the score rather than trusting a stored one, which may be absent
    # on findings recorded before scoring existed.
    by_host_asset = {asset.host: asset for asset in assets}
    scores = {
        id(finding): compute_priority(
            finding,
            asset=by_host_asset.get((finding.affected_hosts or [""])[0]),
        ).priority
        for finding in surfaced
    }
    for finding in sorted(surfaced, key=lambda f: -scores[id(f)]):
        action, why = PLAYBOOKS.get(finding.vuln_class, _DEFAULT_PLAYBOOK)
        host = (finding.affected_hosts or [""])[0]
        asset = by_host.get(host)
        criticality, _ = asset_criticality(
            host, title=asset.title if asset else None
        )
        base = {
            FindingTier.CONFIRMED: 9.0,
            FindingTier.PROBABLE: 6.0,
        }[finding.tier]

        out.append(
            Recommendation(
                kind="finding",
                subject=f"{finding.severity.value.upper()} {finding.title}",
                action=action,
                why=why,
                priority=base * criticality + scores[id(finding)],
                command=f"reconx findings list {program.slug}",
                tags=[finding.vuln_class, finding.tier.value],
            )
        )

    # A probable finding is unfinished business, not a result.
    probable = [f for f in surfaced if f.tier is FindingTier.PROBABLE]
    if probable:
        out.append(
            Recommendation(
                kind="finding",
                subject=f"{len(probable)} probable finding(s) awaiting confirmation",
                action=(
                    "Verify these by hand. Each has a recorded request; the missing "
                    "piece is usually a second independent signal."
                ),
                why=(
                    "Probable means one strong signal agreed. Submitting on that alone "
                    "is how researchers accumulate closed-as-informational reports."
                ),
                priority=7.5,
                command=f"reconx findings list {program.slug} --tier probable",
                tags=["verification"],
            )
        )

    needs_review = [f for f in findings if f.tier is FindingTier.NEEDS_REVIEW]
    if needs_review:
        out.append(
            Recommendation(
                kind="finding",
                subject=f"{len(needs_review)} candidate(s) need a human look",
                action=(
                    "Read these. They are cases the engine could not decide, often "
                    "because the host was rate-limiting or a payload behaved oddly."
                ),
                why="An undecided candidate is where a real bug is most likely hiding.",
                priority=6.5,
                command=f"reconx findings list {program.slug} --tier needs_review",
                tags=["verification"],
            )
        )
    return out


# ---------------------------------------------------------------------------
# assets
# ---------------------------------------------------------------------------


def _from_assets(
    program: Program,
    assets: list[Asset],
    endpoints: list[Endpoint],
    findings: list[Finding],
) -> list[Recommendation]:
    hosts_with_findings = {
        host
        for finding in findings
        if finding.tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE)
        for host in (finding.affected_hosts or [])
    }
    out: list[Recommendation] = []

    interesting: list[tuple[float, Asset, list[str]]] = []
    for asset in assets:
        if not asset.is_live or asset.host in hosts_with_findings:
            continue
        criticality, reasons = asset_criticality(
            asset.host, title=asset.title, technologies=asset.technologies
        )
        if criticality > 1.2 and reasons:
            interesting.append((criticality, asset, reasons))

    for criticality, asset, reasons in sorted(interesting, key=lambda r: -r[0])[:10]:
        label = reasons[0]
        out.append(
            Recommendation(
                kind="asset",
                subject=f"{asset.host} looks like a {label}",
                action=_asset_action(label),
                why=(
                    f"It is live ({asset.http_status or '?'}"
                    + (f", '{asset.title}'" if asset.title else "")
                    + ") and nothing has been found on it yet, which usually means it "
                    "has not been looked at properly rather than that it is clean."
                ),
                priority=4.0 * criticality,
                command=f"reconx assets list {program.slug} --live",
                tags=["asset", label.replace(" ", "_")],
            )
        )
    return out


def _asset_action(label: str) -> str:
    if "admin" in label or "management" in label or "console" in label:
        return (
            "Look for authentication bypass, a password-reset flaw, and access "
            "control gaps after logging in. Try default credentials only if the "
            "program permits it."
        )
    if "authentication" in label or "sign-on" in label or "authorization" in label:
        return (
            "Test the flow itself: open redirects in the return parameter, token "
            "handling, account enumeration, and whether the session survives a "
            "password change."
        )
    if "API" in label or "GraphQL" in label:
        return (
            "Enumerate the schema or routes, then test object-level authorization "
            "on every identifier. Broken access control is the most common API bug "
            "and the least often automated."
        )
    if "payment" in label or "billing" in label or "checkout" in label:
        return (
            "Test for value tampering, currency and quantity handling, and race "
            "conditions in the confirmation step. Do not complete real transactions."
        )
    if "upload" in label:
        return (
            "Test the file type and content checks, where uploads are served from, "
            "and whether the stored path is guessable."
        )
    if "non-production" in label or "development" in label or "test" in label:
        return (
            "Check whether it is protected at all, whether it carries production "
            "data, and whether debug interfaces are exposed. These hosts are "
            "usually configured less carefully than production."
        )
    if "build system" in label or "source control" in label:
        return (
            "Check for unauthenticated read access to jobs, artefacts or "
            "repositories. Exposed build systems often leak credentials."
        )
    return "Explore it by hand. The pipeline found it but has not characterised it."


# ---------------------------------------------------------------------------
# coverage
# ---------------------------------------------------------------------------


def _coverage_gaps(
    program: Program,
    assets: list[Asset],
    endpoints: list[Endpoint],
    findings: list[Finding],
) -> list[Recommendation]:
    out: list[Recommendation] = []
    live = [asset for asset in assets if asset.is_live]
    hosts_with_endpoints = {
        endpoint.url.split("/")[2].split(":")[0]
        for endpoint in endpoints
        if endpoint.url.count("/") >= 2
    }

    unexplored = [asset for asset in live if asset.host not in hosts_with_endpoints]
    if unexplored:
        out.append(
            Recommendation(
                kind="coverage",
                subject=f"{len(unexplored)} live host(s) have no endpoints recorded",
                action="Run content discovery against them.",
                why=(
                    "A host with no known endpoints has not been searched for bugs, "
                    "only found. This is the largest gap between what is in scope and "
                    "what has been looked at."
                ),
                priority=8.0,
                command=f"reconx scan run {program.slug} --stage content",
                tags=["coverage", "content"],
            )
        )

    # Coverage is judged per endpoint, not per program. One tested parameter
    # somewhere does not mean the other forty have been looked at.
    from reconx.stages.vulns import normalize_path_template

    tested_templates: set[tuple[str, str]] = set()
    for finding in findings:
        if finding.vuln_class not in {"sqli", "xss"}:
            continue
        # dedup_key is "<class>::<path template>::<parameter>"
        pieces = finding.dedup_key.split("::")
        if len(pieces) >= 3:
            tested_templates.add((pieces[1], pieces[2]))

    def untested(endpoint: Endpoint, names: list[str]) -> list[str]:
        template = normalize_path_template(endpoint.url)
        return [name for name in names if (template, name) not in tested_templates]

    with_params = [
        endpoint
        for endpoint in endpoints
        if endpoint.parameters and untested(endpoint, endpoint.parameters)
    ]
    if with_params:
        out.append(
            Recommendation(
                kind="coverage",
                subject=f"{len(with_params)} endpoint(s) have parameters that were never tested",
                action="Run the vulnerability stage.",
                why=(
                    "Parameters are where injection and scripting bugs live. Finding "
                    "them and not testing them is the most expensive kind of gap."
                ),
                priority=8.5,
                command=f"reconx scan run {program.slug} --stage vulns",
                tags=["coverage", "vulns"],
            )
        )

    reflected = [
        endpoint
        for endpoint in endpoints
        if endpoint.reflected_parameters
        and untested(endpoint, endpoint.reflected_parameters)
    ]
    if reflected:
        out.append(
            Recommendation(
                kind="coverage",
                subject=f"{len(reflected)} reflecting parameter(s) still unverified",
                action="Run the vulnerability stage so each reflection is verified.",
                why=(
                    "Reflection is not a finding, but it is the shortlist. Every one "
                    "of these still has to prove it can escape its context."
                ),
                priority=8.0,
                command=f"reconx scan run {program.slug} --stage vulns",
                tags=["coverage", "xss"],
            )
        )

    if not assets:
        out.append(
            Recommendation(
                kind="coverage",
                subject="nothing has been discovered yet",
                action="Run the recon stages.",
                why="There is no data to reason about.",
                priority=10.0,
                command=f"reconx scan run {program.slug} --stage recon",
                tags=["coverage"],
            )
        )
    elif not live:
        out.append(
            Recommendation(
                kind="coverage",
                subject=f"{len(assets)} host(s) known, none confirmed live",
                action="Run the probe stage, and check the scope covers what you expect.",
                why=(
                    "Hosts that resolve but never answer are either firewalled, on a "
                    "non-standard port, or out of scope in practice."
                ),
                priority=7.0,
                command=f"reconx scan run {program.slug} --stage resolve_probe",
                tags=["coverage"],
            )
        )

    wildcard_suspects = [asset for asset in assets if asset.wildcard_suspect]
    if wildcard_suspects:
        out.append(
            Recommendation(
                kind="coverage",
                subject=f"{len(wildcard_suspects)} host(s) still flagged as wildcard suspects",
                action=(
                    "Raise the wildcard check budget so their HTTP responses get "
                    "compared against the wildcard baseline."
                ),
                why=(
                    "A real host can hide behind a wildcard zone. These were not "
                    "checked, so they are neither confirmed nor dismissed."
                ),
                priority=5.5,
                command=(
                    f"reconx scan run {program.slug} --stage subdomains "
                    "--max-wildcard-checks 1000"
                ),
                tags=["coverage", "wildcard"],
            )
        )
    return out


# ---------------------------------------------------------------------------
# staleness and setup
# ---------------------------------------------------------------------------


async def _staleness(
    session: AsyncSession, program: Program
) -> list[Recommendation]:
    out: list[Recommendation] = []
    now = datetime.now(UTC)

    entries = (
        await session.execute(
            select(ScheduleEntry).where(ScheduleEntry.program_id == program.id)
        )
    ).scalars().all()

    last_runs: dict[str, datetime] = {}
    if entries:
        for entry in entries:
            if entry.last_run_at:
                last_runs[entry.stage] = _aware(entry.last_run_at)
    else:
        stage_runs = (
            await session.execute(
                select(StageRun).where(StageRun.program_id == program.id)
            )
        ).scalars().all()
        for stage_run in stage_runs:
            when = _aware(stage_run.finished_at or stage_run.started_at)
            if when and (
                stage_run.stage not in last_runs or when > last_runs[stage_run.stage]
            ):
                last_runs[stage_run.stage] = when

    thresholds = {
        "subdomains": timedelta(days=3),
        "resolve_probe": timedelta(days=1),
        "content": timedelta(days=7),
        "vulns": timedelta(days=14),
    }
    for stage, threshold in thresholds.items():
        when = last_runs.get(stage)
        if when is None:
            continue
        age = now - when
        if age > threshold:
            days = age.days or 1
            out.append(
                Recommendation(
                    kind="staleness",
                    subject=f"{stage} last ran {days} day(s) ago",
                    action="Re-run it, or enable monitoring so it keeps itself current.",
                    why=(
                        "Estates change. Stale data means you are hunting yesterday's "
                        "attack surface, and on a wildcard program the new host is the "
                        "one nobody else has looked at."
                    ),
                    priority=4.5 + min(3.0, days / 7),
                    command=f"reconx monitor enable {program.slug}",
                    tags=["staleness", stage],
                )
            )

    if not entries:
        out.append(
            Recommendation(
                kind="staleness",
                subject="monitoring is not set up for this program",
                action="Enable it so recon keeps itself up to date.",
                why=(
                    "Running this by hand means you find a new subdomain whenever you "
                    "remember to look. Continuously means within the hour."
                ),
                priority=6.0,
                command=f"reconx monitor enable {program.slug}",
                tags=["staleness", "monitoring"],
            )
        )
    return out


def _setup_gaps(
    program: Program, settings: Settings, tool_statuses: dict | None
) -> list[Recommendation]:
    out: list[Recommendation] = []

    if tool_statuses is not None:
        missing = [
            name for name, status in tool_statuses.items() if not status.available
        ]
        if "nuclei" in missing:
            out.append(
                Recommendation(
                    kind="setup",
                    subject="nuclei is not installed",
                    action="Install it and update its templates.",
                    why=(
                        "It is the single largest coverage gap in the toolchain. "
                        "Without it, only ReconX's own checks run, which cover far "
                        "less ground."
                    ),
                    priority=7.0,
                    command="./scripts/bootstrap.sh && nuclei -update-templates",
                    tags=["setup", "nuclei"],
                )
            )
        remaining = [name for name in missing if name != "nuclei"]
        if remaining:
            out.append(
                Recommendation(
                    kind="setup",
                    subject=f"{len(remaining)} scanner(s) missing: {', '.join(remaining[:6])}",
                    action="Install them for faster and broader discovery.",
                    why=(
                        "The built-in fallbacks work but are slower and shallower. "
                        "`reconx doctor` lists exactly what each one costs you."
                    ),
                    priority=3.0,
                    command="./scripts/bootstrap.sh",
                    tags=["setup"],
                )
            )

    has_alerts = any(
        [
            settings.discord_webhook,
            settings.slack_webhook,
            settings.telegram_bot_token and settings.telegram_chat_id,
            settings.generic_webhook,
        ]
    )
    if not has_alerts:
        out.append(
            Recommendation(
                kind="setup",
                subject="no alert channel is configured",
                action="Set a webhook in .env so discoveries reach you.",
                why=(
                    "Continuous scanning that records findings nobody reads is the "
                    "worst of both worlds: it costs requests against the target and "
                    "tells you nothing."
                ),
                priority=5.0,
                command="edit .env and set RECONX_DISCORD_WEBHOOK or RECONX_GENERIC_WEBHOOK",
                tags=["setup", "alerts"],
            )
        )

    if not settings.headless_xss_confirm:
        out.append(
            Recommendation(
                kind="setup",
                subject="browser confirmation for XSS is switched off",
                action="Turn it back on so reflected XSS can reach Confirmed.",
                why=(
                    "Without it, a real XSS is reported as Probable, which means you "
                    "verify every one by hand."
                ),
                priority=3.5,
                command="set RECONX_HEADLESS_XSS_CONFIRM=true in .env",
                tags=["setup", "xss"],
            )
        )
    return out
