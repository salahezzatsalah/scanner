"""ReconX command line interface."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlmodel import select

from reconx import __version__
from reconx.config import get_settings
from reconx.db.models import Asset, Finding, FindingTier, Program, ScanRun
from reconx.db.session import get_session_factory, init_db
from reconx.db.store import get_program, list_programs, upsert_program
from reconx.orchestrator import (
    STAGE_GROUPS,
    STAGE_REGISTRY,
    Orchestrator,
    StagePlanError,
)
from reconx.report.markdown import build_markdown_report
from reconx.scope.guard import ScopeGuard
from reconx.scope.model import Scope, ScopeParseError, load_scope
from reconx.tools.registry import detect_all

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "ReconX — continuous reconnaissance and vulnerability verification "
        "for authorized security research.\n\n"
        "Every scan requires a scope file with an authorization block. "
        "Start with: reconx scope validate scopes/example.yaml"
    ),
)
scope_app = typer.Typer(no_args_is_help=True, help="Define and check program scopes.")
scan_app = typer.Typer(no_args_is_help=True, help="Run the pipeline.")
assets_app = typer.Typer(no_args_is_help=True, help="Inspect discovered assets.")
findings_app = typer.Typer(no_args_is_help=True, help="Inspect findings.")
db_app = typer.Typer(no_args_is_help=True, help="Database maintenance.")

app.add_typer(scope_app, name="scope")
app.add_typer(scan_app, name="scan")
app.add_typer(assets_app, name="assets")
app.add_typer(findings_app, name="findings")
app.add_typer(db_app, name="db")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _load(path: str) -> tuple[Scope, str]:
    """Load a scope file, exiting with a clear message if it is invalid."""
    try:
        scope = load_scope(path)
    except ScopeParseError as exc:
        err_console.print(f"[red]Invalid scope file:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    raw = Path(path).read_text(encoding="utf-8")
    return scope, raw


async def _resolve_program(slug_or_path: str) -> tuple[Scope, str, str]:
    """Accept either a stored program slug or a path to a scope file."""
    candidate = Path(slug_or_path)
    if candidate.is_file():
        scope, raw = _load(slug_or_path)
        return scope, raw, scope.slug

    factory = get_session_factory()
    async with factory() as session:
        program = await get_program(session, slug_or_path)
        if program is None:
            known = [p.slug for p in await list_programs(session)]
            err_console.print(
                f"[red]No program named[/red] {slug_or_path!r}. "
                + (f"Known: {', '.join(known)}" if known else "None added yet.")
            )
            err_console.print(
                "Add one with: [bold]reconx scope add path/to/scope.yaml[/bold]"
            )
            raise typer.Exit(code=2)
        try:
            scope = load_scope_from_text(program.scope_yaml)
        except (ScopeParseError, ValueError) as exc:
            err_console.print(
                f"[red]The stored scope for {program.slug!r} is no longer valid:[/red] {exc}"
            )
            err_console.print("Re-add it with: [bold]reconx scope add <file>[/bold]")
            raise typer.Exit(code=2) from exc
        return scope, program.scope_yaml, program.slug


def _yaml_to_dict(text: str) -> dict:
    import yaml

    loaded = yaml.safe_load(text)
    return loaded if isinstance(loaded, dict) else {}


def load_scope_from_text(text: str) -> Scope:
    """Parse a scope from YAML text rather than a file."""
    payload = _yaml_to_dict(text)
    if not payload:
        raise ScopeParseError("stored scope is not a YAML mapping")
    return Scope.model_validate(payload)


# ---------------------------------------------------------------------------
# top-level
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the ReconX version."""
    console.print(f"ReconX {__version__}")


@app.command()
def doctor() -> None:
    """Report which external tools are installed, and what is lost without each."""

    async def run() -> int:
        settings = get_settings()
        placeholder = Scope.model_validate(
            {
                "program": "doctor",
                "authorization": {
                    "authorized_by": "doctor",
                    "date": "2000-01-01",
                    "attestation": "tool detection only; no scanning is performed",
                },
                "in_scope": ["example.invalid"],
            }
        )
        statuses = await detect_all(ScopeGuard(placeholder))

        table = Table(title="External tools", show_lines=False)
        table.add_column("Tool", style="bold")
        table.add_column("Status")
        table.add_column("Version / note", overflow="fold")
        table.add_column("Purpose", overflow="fold")

        missing = []
        for name in sorted(statuses):
            status = statuses[name]
            if status.available:
                table.add_row(
                    name, "[green]installed[/green]", status.version or "", status.spec.purpose
                )
            else:
                missing.append(status)
                table.add_row(
                    name, "[yellow]missing[/yellow]", "", status.spec.purpose
                )
        console.print(table)

        if missing:
            console.print()
            console.print(
                Panel(
                    "\n".join(
                        f"[bold]{status.spec.name}[/bold]\n"
                        f"  without it: {status.spec.fallback}\n"
                        f"  install:    {status.spec.install}"
                        for status in missing
                    ),
                    title=f"{len(missing)} tool(s) missing — ReconX still runs",
                    border_style="yellow",
                )
            )
            console.print(
                "\nInstall the Go tools in one step: [bold]./scripts/bootstrap.sh[/bold]"
            )
        else:
            console.print("\n[green]All catalogued tools are installed.[/green]")

        console.print()
        console.print(f"Database: {settings.database_url}")
        console.print(
            f"Rate limit: {settings.requests_per_second_per_host} req/s per host, "
            f"{settings.max_concurrent_requests} concurrent"
        )
        console.print(
            f"Verification: a finding must reproduce "
            f"{settings.reproduce_required} of {settings.reproduce_attempts} attempts"
        )
        return len(missing)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------


@scope_app.command("validate")
def scope_validate(
    path: Annotated[str, typer.Argument(help="Path to a scope YAML file")],
) -> None:
    """Parse and check a scope file. Sends no traffic."""
    scope, _ = _load(path)

    console.print(
        Panel(
            f"[bold]{scope.program}[/bold]\n"
            f"platform: {scope.platform or '-'}\n"
            f"authorized by: {scope.authorization.authorized_by} "
            f"on {scope.authorization.date}\n"
            f"slug: {scope.slug}",
            title="Scope",
            border_style="green",
        )
    )

    table = Table(title="Rules", show_lines=False)
    table.add_column("Effect")
    table.add_column("Kind")
    table.add_column("Rule", overflow="fold")
    for rule in scope.in_scope_rules:
        table.add_row("[green]in scope[/green]", rule.kind, rule.raw)
    for rule in scope.out_of_scope_rules:
        table.add_row("[red]excluded[/red]", rule.kind, rule.raw)
    console.print(table)

    if scope.wildcard_roots:
        console.print(
            f"\nWildcard enumeration will run against: "
            f"[bold]{', '.join(scope.wildcard_roots)}[/bold]"
        )
    else:
        console.print(
            "\n[yellow]No wildcard domains.[/yellow] Only the named hosts will be "
            "enumerated. Add '*.example.com' to enumerate subdomains."
        )

    limits = scope.limits
    console.print(
        f"\nProgram limits: "
        f"{limits.requests_per_second_per_host or 'default'} req/s per host, "
        f"max {limits.max_concurrent_hosts or 'default'} hosts, "
        f"budget {limits.max_requests_per_scan or 'unlimited'} requests"
    )
    console.print(
        f"\n[green]Scope is valid.[/green] {len(scope.in_scope_rules)} in-scope "
        f"rule(s), {len(scope.out_of_scope_rules)} exclusion(s)."
    )


@scope_app.command("test")
def scope_test(
    path: Annotated[str, typer.Argument(help="Path to a scope YAML file")],
    targets: Annotated[list[str], typer.Argument(help="Hosts or URLs to check")],
) -> None:
    """Check specific targets against a scope. Sends no traffic."""
    scope, _ = _load(path)
    guard = ScopeGuard(scope)

    table = Table(title="Scope decisions")
    table.add_column("Target", overflow="fold")
    table.add_column("Decision")
    table.add_column("Why", overflow="fold")
    table.add_column("Matched rule", overflow="fold")

    any_denied = False
    for target in targets:
        decision = guard.decide(target)
        if not decision.allowed:
            any_denied = True
        table.add_row(
            target,
            "[green]ALLOW[/green]" if decision.allowed else "[red]DENY[/red]",
            decision.reason,
            decision.matched_rule or "-",
        )
    console.print(table)
    raise typer.Exit(code=1 if any_denied else 0)


@scope_app.command("add")
def scope_add(
    path: Annotated[str, typer.Argument(help="Path to a scope YAML file")],
) -> None:
    """Store a program so it can be scanned and monitored by name."""
    scope, raw = _load(path)

    async def run() -> None:
        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            program = await upsert_program(session, scope, raw)
            await session.commit()
            console.print(
                f"[green]Stored[/green] program [bold]{program.name}[/bold] "
                f"as slug [bold]{program.slug}[/bold]"
            )
            console.print(f"\nRun it with: [bold]reconx scan run {program.slug}[/bold]")

    asyncio.run(run())


@scope_app.command("list")
def scope_list() -> None:
    """List stored programs."""

    async def run() -> None:
        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            programs = await list_programs(session)
            if not programs:
                console.print(
                    "No programs stored. Add one with "
                    "[bold]reconx scope add path/to/scope.yaml[/bold]"
                )
                return
            table = Table(title="Programs")
            table.add_column("Slug", style="bold")
            table.add_column("Name", overflow="fold")
            table.add_column("Platform")
            table.add_column("Authorized")
            table.add_column("Monitoring")
            for program in programs:
                table.add_row(
                    program.slug,
                    program.name,
                    program.platform or "-",
                    str(program.authorization_date),
                    "on" if program.monitoring_enabled else "off",
                )
            console.print(table)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@scan_app.command("run")
def scan_run(
    program: Annotated[
        str, typer.Argument(help="A stored program slug, or a path to a scope file")
    ],
    stage: Annotated[
        list[str] | None,
        typer.Option(
            "--stage",
            "-s",
            help=(
                "Stage or group to run; repeatable. "
                f"Stages: {', '.join(sorted(STAGE_REGISTRY))}. "
                f"Groups: {', '.join(sorted(STAGE_GROUPS))}"
            ),
        ),
    ] = None,
    resume: Annotated[
        int | None, typer.Option("--resume", help="Resume an interrupted scan run by id")
    ] = None,
    no_brute: Annotated[
        bool, typer.Option("--no-brute", help="Skip active DNS brute forcing")
    ] = False,
    wordlist: Annotated[
        str | None, typer.Option("--wordlist", help="Path to a subdomain wordlist")
    ] = None,
    max_wildcard_checks: Annotated[
        int,
        typer.Option(
            "--max-wildcard-checks",
            help="HTTP checks budget for names that match a wildcard zone",
        ),
    ] = 300,
    no_external_tools: Annotated[
        bool,
        typer.Option(
            "--no-external-tools",
            help="Use only the built-in Python paths, ignoring installed scanners",
        ),
    ] = False,
) -> None:
    """Run the pipeline against a program."""

    async def run() -> None:
        scope, raw, slug = await _resolve_program(program)
        await init_db()

        from reconx.stages.subdomains import SubdomainStage

        overrides = {
            "subdomains": SubdomainStage(
                wordlist_path=wordlist,
                brute_force=not no_brute,
                max_wildcard_http_checks=max_wildcard_checks,
            )
        }

        console.print(
            Panel(
                f"[bold]{scope.program}[/bold]\n"
                f"authorized by {scope.authorization.authorized_by} "
                f"on {scope.authorization.date}\n"
                f"in scope: {', '.join(r.raw for r in scope.in_scope_rules)}\n"
                f"excluded: "
                f"{', '.join(r.raw for r in scope.out_of_scope_rules) or 'nothing'}",
                title="Starting scan",
                border_style="cyan",
            )
        )

        orchestrator = Orchestrator(
            scope,
            scope_yaml=raw,
            stage_instances=overrides,
            use_external_tools=not no_external_tools,
        )
        try:
            summary = await orchestrator.run(stage, resume_run_id=resume)
        except StagePlanError as exc:
            err_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=2) from exc

        _print_summary(summary, slug)

    asyncio.run(run())


def _print_summary(summary, slug: str) -> None:
    table = Table(title=f"Scan {summary.scan_run_id} — {summary.status.value}")
    table.add_column("Stage", style="bold")
    table.add_column("In", justify="right")
    table.add_column("Out", justify="right")
    table.add_column("Filtered", justify="right")
    table.add_column("New", justify="right")
    table.add_column("Tools", overflow="fold")

    for name, result in summary.stages.items():
        table.add_row(
            name,
            str(result.items_in),
            str(result.items_out),
            str(result.items_filtered),
            str(len(result.new_assets)),
            ", ".join(result.tools_used) or "built-in",
        )
    for name, reason in summary.skipped.items():
        table.add_row(name, "-", "-", "-", "-", f"[yellow]{reason}[/yellow]")
    console.print(table)

    for name, result in summary.stages.items():
        if result.filter_reasons:
            reasons = ", ".join(
                f"{key}: {value}" for key, value in result.filter_reasons.items()
            )
            console.print(f"  [dim]{name} filtered — {reasons}[/dim]")
        for note in result.notes:
            console.print(f"  [dim]{name}: {note}[/dim]")
        for fallback in result.fallbacks_used:
            console.print(f"  [yellow]{name}: {fallback}[/yellow]")

    console.print()
    tool_note = f" (+{summary.tool_requests} via tools)" if summary.tool_requests else ""
    console.print(
        f"Requests: {summary.requests_made}{tool_note}   "
        f"DNS queries: {summary.dns_queries}   "
        f"Source calls: {summary.source_calls}   "
        f"Out-of-scope blocked: {summary.out_of_scope_blocked}"
    )
    if summary.new_assets:
        console.print(f"\n[green]{len(summary.new_assets)} new asset(s):[/green]")
        for host in summary.new_assets[:25]:
            console.print(f"  + {host}")
        if len(summary.new_assets) > 25:
            console.print(f"  ...and {len(summary.new_assets) - 25} more")
    if summary.error:
        err_console.print(f"\n[red]Run error:[/red] {summary.error}")

    console.print(f"\nReport: [bold]reconx report {slug}[/bold]")


@scan_app.command("history")
def scan_history(
    program: Annotated[str, typer.Argument(help="Program slug")],
    limit: Annotated[int, typer.Option("--limit", "-n")] = 10,
) -> None:
    """Show recent scan runs."""

    async def run() -> None:
        factory = get_session_factory()
        async with factory() as session:
            found = await get_program(session, program)
            if found is None:
                err_console.print(f"[red]No program named {program!r}[/red]")
                raise typer.Exit(code=2)
            runs = (
                await session.execute(
                    select(ScanRun)
                    .where(ScanRun.program_id == found.id)
                    .order_by(ScanRun.started_at.desc())
                    .limit(limit)
                )
            ).scalars().all()

            table = Table(title=f"Scan history — {found.name}")
            table.add_column("Id", justify="right")
            table.add_column("Started")
            table.add_column("Status")
            table.add_column("Requests", justify="right")
            table.add_column("Blocked", justify="right")
            for run_row in runs:
                table.add_row(
                    str(run_row.id),
                    run_row.started_at.strftime("%Y-%m-%d %H:%M"),
                    run_row.status.value,
                    str(run_row.requests_made),
                    str(run_row.out_of_scope_blocked),
                )
            console.print(table)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# assets and findings
# ---------------------------------------------------------------------------


@assets_app.command("list")
def assets_list(
    program: Annotated[str, typer.Argument(help="Program slug")],
    live: Annotated[bool, typer.Option("--live", help="Only hosts that answered")] = False,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 100,
) -> None:
    """List discovered assets."""

    async def run() -> None:
        factory = get_session_factory()
        async with factory() as session:
            found = await get_program(session, program)
            if found is None:
                err_console.print(f"[red]No program named {program!r}[/red]")
                raise typer.Exit(code=2)
            query = select(Asset).where(Asset.program_id == found.id)
            if live:
                query = query.where(Asset.is_live == True)  # noqa: E712
            rows = (
                await session.execute(query.order_by(Asset.host).limit(limit))
            ).scalars().all()

            table = Table(title=f"Assets — {found.name}")
            table.add_column("Host", style="bold", overflow="fold")
            table.add_column("Kind")
            table.add_column("Live")
            table.add_column("Status")
            table.add_column("Title", overflow="fold")
            table.add_column("Sources", overflow="fold")
            for asset in rows:
                table.add_row(
                    asset.host,
                    asset.kind.value,
                    "yes" if asset.is_live else "-",
                    str(asset.http_status or "-"),
                    (asset.title or "")[:40],
                    ", ".join(asset.sources or [])[:40],
                )
            console.print(table)
            console.print(f"\n{len(rows)} shown.")

    asyncio.run(run())


@findings_app.command("list")
def findings_list(
    program: Annotated[str, typer.Argument(help="Program slug")],
    tier: Annotated[
        str | None,
        typer.Option(
            "--tier",
            help="confirmed, probable, needs_review or discarded",
        ),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 50,
) -> None:
    """List findings, highest priority first."""

    async def run() -> None:
        factory = get_session_factory()
        async with factory() as session:
            found = await get_program(session, program)
            if found is None:
                err_console.print(f"[red]No program named {program!r}[/red]")
                raise typer.Exit(code=2)

            query = select(Finding).where(Finding.program_id == found.id)
            if tier:
                try:
                    query = query.where(Finding.tier == FindingTier(tier))
                except ValueError as exc:
                    err_console.print(
                        f"[red]Unknown tier {tier!r}.[/red] Use one of: "
                        + ", ".join(t.value for t in FindingTier)
                    )
                    raise typer.Exit(code=2) from exc
            else:
                query = query.where(
                    Finding.tier.in_([FindingTier.CONFIRMED, FindingTier.PROBABLE])
                )

            rows = (
                await session.execute(
                    query.order_by(Finding.priority.desc()).limit(limit)
                )
            ).scalars().all()

            if not rows:
                console.print(
                    "No findings to show. "
                    "Vulnerability stages land in a later milestone; "
                    "use --tier discarded to see what verification filtered out."
                )
                return

            table = Table(title=f"Findings — {found.name}")
            table.add_column("Sev", style="bold")
            table.add_column("Tier")
            table.add_column("Conf", justify="right")
            table.add_column("Class")
            table.add_column("Title", overflow="fold")
            table.add_column("Hosts", justify="right")
            for finding in rows:
                table.add_row(
                    finding.severity.value.upper(),
                    finding.tier.value,
                    str(finding.confidence),
                    finding.vuln_class,
                    finding.title[:60],
                    str(len(finding.affected_hosts or [])),
                )
            console.print(table)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@app.command()
def report(
    program: Annotated[str, typer.Argument(help="Program slug")],
    output: Annotated[
        str | None, typer.Option("--output", "-o", help="Write to a file instead of stdout")
    ] = None,
    include_discarded: Annotated[
        bool,
        typer.Option("--include-discarded", help="List findings verification filtered out"),
    ] = False,
) -> None:
    """Generate a Markdown report."""

    async def run() -> None:
        factory = get_session_factory()
        async with factory() as session:
            found = await get_program(session, program)
            if found is None:
                err_console.print(f"[red]No program named {program!r}[/red]")
                raise typer.Exit(code=2)
            text = await build_markdown_report(
                session, found, include_discarded=include_discarded
            )

        if output:
            path = Path(output)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            console.print(f"[green]Wrote[/green] {path} ({len(text)} bytes)")
        else:
            console.print(text, markup=False, highlight=False)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# db
# ---------------------------------------------------------------------------


@db_app.command("init")
def db_init() -> None:
    """Create any missing tables."""

    async def run() -> None:
        settings = get_settings()
        settings.ensure_dirs()
        await init_db()
        console.print(f"[green]Database ready:[/green] {settings.database_url}")

    asyncio.run(run())


@db_app.command("stats")
def db_stats() -> None:
    """Row counts per table."""

    async def run() -> None:
        from sqlalchemy import func

        from reconx.db.models import AuditEntry, Endpoint, Observation

        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            table = Table(title="Database")
            table.add_column("Table", style="bold")
            table.add_column("Rows", justify="right")
            for model in (Program, Asset, Endpoint, Finding, Observation, ScanRun, AuditEntry):
                count = (
                    await session.execute(select(func.count()).select_from(model))
                ).scalar_one()
                table.add_row(model.__tablename__, str(count))
            console.print(table)

    asyncio.run(run())


if __name__ == "__main__":  # pragma: no cover
    app()
