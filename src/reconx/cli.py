"""ReconX command line interface."""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC
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
from reconx.live import LiveProgress
from reconx.orchestrator import (
    STAGE_GROUPS,
    STAGE_REGISTRY,
    Orchestrator,
    StagePlanError,
)
from reconx.report.markdown import build_markdown_report
from reconx.scope.guard import ScopeGuard
from reconx.scope.model import Scope, ScopeParseError, load_scope
from reconx.stages.wordlists import (
    COMMON_CONTENT_PATHS,
    COMMON_PARAMETER_NAMES,
    COMMON_SUBDOMAIN_LABELS,
)
from reconx.tools.registry import detect_all

console = Console()
err_console = Console(stderr=True)

# Kept as names rather than imported flags so the CLI stays importable without
# pulling in the whole verification stack at start-up.
VULN_CHECK_NAMES: tuple[str, ...] = (
    "sqli", "xss", "redirect", "cors", "traversal", "ssti", "cmdi", "deser",
    "ssrf",
)


def _validate_checks(skip: list[str] | None) -> set[str]:
    """Reject an unknown class name rather than silently running everything."""
    requested = {name.strip().lower() for name in (skip or []) if name.strip()}
    unknown = sorted(requested - set(VULN_CHECK_NAMES))
    if unknown:
        err_console.print(
            f"[red]unknown check(s): {', '.join(unknown)}[/red]\n"
            f"valid names: {', '.join(sorted(VULN_CHECK_NAMES))}"
        )
        raise typer.Exit(code=2)
    return requested

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
triage_app = typer.Typer(
    no_args_is_help=True, help="Scoring and triage maintenance."
)
monitor_app = typer.Typer(
    no_args_is_help=True, help="Continuous monitoring and alerts."
)
db_app = typer.Typer(no_args_is_help=True, help="Database maintenance.")

app.add_typer(scope_app, name="scope")
app.add_typer(scan_app, name="scan")
app.add_typer(assets_app, name="assets")
app.add_typer(findings_app, name="findings")
app.add_typer(triage_app, name="triage")
app.add_typer(monitor_app, name="monitor")
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
        console.print(
            "Out-of-band callbacks: "
            + (
                f"[green]enabled[/green] on {settings.oob_bind_host}:"
                f"{settings.oob_bind_port or 'an ephemeral port'}"
                + (
                    f", advertised as {settings.oob_public_base_url}"
                    if settings.oob_public_base_url
                    else " (loopback only, so only a target on this machine can reach it)"
                )
                if settings.enable_oob_collaborator
                else "[yellow]disabled[/yellow], so SSRF is not tested — pass --oob"
            )
        )

        # Wordlists decide how much of the application is ever seen, and the
        # built-in lists are fallbacks rather than wordlists. Saying where to get
        # a real one belongs in the same place as "which tools are missing".
        console.print()
        console.print(
            Panel(
                "The built-in lists are small on purpose: "
                f"{len(COMMON_SUBDOMAIN_LABELS)} subdomain labels, "
                f"{len(COMMON_CONTENT_PATHS)} paths, "
                f"{len(COMMON_PARAMETER_NAMES)} parameter names. They exist so a scan "
                "works with no setup, not so it finds everything.\n\n"
                "Get SecLists:\n"
                "  [bold]git clone --depth 1 https://github.com/danielmiessler/SecLists"
                "[/bold]\n\n"
                "Then point each list at it — one file cannot serve all three:\n"
                "  --wordlist        SecLists/Discovery/DNS/subdomains-top1million-110000.txt\n"
                "  --path-wordlist   SecLists/Discovery/Web-Content/raft-medium-directories.txt\n"
                "  --param-wordlist  SecLists/Discovery/Web-Content/burp-parameter-names.txt\n\n"
                "Or put them in the program's scope file under [bold]scan_options[/bold], "
                "which is the only way a scheduled scan can use them.",
                title="Wordlists",
                border_style="cyan",
            )
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
    if scope.auth is not None:
        auth = scope.auth
        # Says whether the variable is set, never what is in it.
        console.print(f"\nAuthenticated scanning: [bold]{auth.describe()}[/bold]")
        if not auth.resolve_credential():
            console.print(
                f"[yellow]${auth.credential_env} is not set, so this scan would run "
                "unauthenticated.[/yellow] Export the session before scanning."
            )
        if auth.avoid_state_changing_paths:
            console.print(
                "[dim]State-changing paths (logout, delete, password, billing) will be "
                "refused while authenticated. Set avoid_state_changing_paths: false to "
                "test them deliberately.[/dim]"
            )
        if not auth.fuzz_write_methods:
            console.print(
                "[dim]Form and JSON parameters will not be fuzzed while "
                "authenticated, because a write to an authenticated endpoint changes "
                "data. Set fuzz_write_methods: true to include them.[/dim]"
            )
    else:
        console.print(
            "\n[dim]Unauthenticated. On a mature program most of the surface is behind "
            "a login; add an 'auth' block to reach it.[/dim]"
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
        str | None,
        typer.Option(
            "--wordlist",
            help=(
                "Subdomain label wordlist. One file cannot serve all three lists, so "
                "content and parameter discovery have their own flags"
            ),
        ),
    ] = None,
    path_wordlist: Annotated[
        str | None,
        typer.Option(
            "--path-wordlist",
            help=(
                "URL path wordlist for content discovery. Point this at SecLists; the "
                "built-in list is 72 entries and is a fallback, not a wordlist"
            ),
        ),
    ] = None,
    param_wordlist: Annotated[
        str | None,
        typer.Option(
            "--param-wordlist",
            help="Parameter name wordlist for hidden-parameter discovery",
        ),
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
    no_archives: Annotated[
        bool,
        typer.Option("--no-archives", help="Skip historical URL sources (Wayback, gau)"),
    ] = False,
    no_nuclei: Annotated[
        bool, typer.Option("--no-nuclei", help="Skip nuclei template scanning")
    ] = False,
    no_timing: Annotated[
        bool,
        typer.Option(
            "--no-timing",
            help=(
                "Skip the time-based SQL injection oracle. Much faster, and it never "
                "confirms a finding on its own anyway"
            ),
        ),
    ] = False,
    no_headless: Annotated[
        bool,
        typer.Option(
            "--no-headless",
            help=(
                "Skip browser confirmation for XSS. Real findings drop to Probable "
                "rather than being lost"
            ),
        ),
    ] = False,
    skip_check: Annotated[
        list[str] | None,
        typer.Option(
            "--skip-check",
            help=(
                "Vulnerability class to skip; repeatable. One of: "
                f"{', '.join(sorted(VULN_CHECK_NAMES))}"
            ),
        ),
    ] = None,
    oob: Annotated[
        bool,
        typer.Option(
            "--oob",
            help=(
                "Enable the out-of-band callback listener, which SSRF needs. It binds "
                "loopback and contacts no third-party service; set "
                "RECONX_OOB_PUBLIC_BASE_URL to an address a remote target can reach"
            ),
        ),
    ] = False,
    progress: Annotated[
        bool,
        typer.Option(
            "--progress/--no-progress",
            help=(
                "Show a live view of stage status, request counts and findings "
                "while the scan runs. On by default when output is a terminal."
            ),
        ),
    ] = True,
) -> None:
    """Run the pipeline against a program."""
    skipped = _validate_checks(skip_check)

    async def run() -> None:
        scope, raw, slug = await _resolve_program(program)
        await init_db()

        from reconx.stages.content import ContentStage
        from reconx.stages.params import ParamStage
        from reconx.stages.subdomains import SubdomainStage
        from reconx.stages.vulns import VulnStage

        # The scope's own scan_options are the baseline, so a flag omitted here
        # keeps whatever the program's scope file says rather than silently
        # reverting to a default. Flags win where they are given.
        stored = scope.scan_options
        overrides = {
            "subdomains": SubdomainStage(
                wordlist_path=wordlist or stored.subdomain_wordlist,
                brute_force=stored.brute_force_subdomains and not no_brute,
                max_wildcard_http_checks=max_wildcard_checks,
            ),
            "content": ContentStage(
                wordlist_path=path_wordlist or stored.path_wordlist,
                crawl=stored.crawl,
                brute_force=stored.brute_force_paths and not no_brute,
                archives=stored.archives and not no_archives,
            ),
            "params": ParamStage(
                wordlist_path=param_wordlist or stored.parameter_wordlist,
                guess_hidden=stored.guess_parameters and not no_brute,
            ),
            "vulns": VulnStage(
                run_nuclei=stored.run_nuclei and not no_nuclei,
                enable_timing=stored.enable_timing and not no_timing,
                headless_xss=stored.headless_xss and not no_headless,
                **{
                    f"check_{name}": name not in (skipped | set(stored.skip_checks))
                    for name in VULN_CHECK_NAMES
                },
            ),
        }

        if oob:
            # Enabling the listener is a per-scan decision, so it is applied to
            # this run's settings rather than written anywhere.
            get_settings().enable_oob_collaborator = True
        elif "ssrf" not in skipped and not get_settings().enable_oob_collaborator:
            console.print(
                "[dim]SSRF needs the out-of-band listener; pass --oob to enable it.[/dim]"
            )

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

        # Live progress is a display concern only: same scan, more visibility.
        # Off when piped so logs stay clean; --no-progress forces it off.
        display = (
            LiveProgress()
            if progress and sys.stdout.isatty()
            else None
        )
        orchestrator = Orchestrator(
            scope,
            scope_yaml=raw,
            stage_instances=overrides,
            use_external_tools=not no_external_tools,
            progress=display,
        )
        if display is not None:
            display.start()
        try:
            summary = await orchestrator.run(stage, resume_run_id=resume)
        except StagePlanError as exc:
            err_console.print(f"[red]{exc}")
            raise typer.Exit(code=2) from exc
        finally:
            if display is not None:
                display.stop()

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
    if summary.findings:
        console.print()
        console.print(
            Panel(
                "\n".join(f"  {entry}" for entry in summary.findings[:30]),
                title=f"{len(summary.findings)} finding(s) surfaced",
                border_style="red",
            )
        )
        if len(summary.findings) > 30:
            console.print(f"  ...and {len(summary.findings) - 30} more")
        console.print(
            f"See them all: [bold]reconx findings list {slug}[/bold]   "
            f"Audit what was filtered out: "
            f"[bold]reconx findings list {slug} --tier discarded[/bold]"
        )

    if summary.new_assets:
        console.print(f"\n[green]{len(summary.new_assets)} new asset(s):[/green]")
        for host in summary.new_assets[:25]:
            console.print(f"  + {host}")
        if len(summary.new_assets) > 25:
            console.print(f"  ...and {len(summary.new_assets) - 25} more")

    if summary.new_endpoints:
        console.print(f"\n[green]{len(summary.new_endpoints)} new endpoint(s)[/green]")
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
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="markdown, html or json")
    ] = "markdown",
    include_discarded: Annotated[
        bool,
        typer.Option(
            "--include-discarded",
            help="List the candidates verification rejected, and why",
        ),
    ] = False,
) -> None:
    """Generate a report as Markdown, standalone HTML, or JSON."""

    async def run() -> None:
        chosen = fmt.strip().lower()
        if chosen not in {"markdown", "md", "html", "json"}:
            err_console.print(
                f"[red]Unknown format {fmt!r}.[/red] Use markdown, html or json."
            )
            raise typer.Exit(code=2)

        factory = get_session_factory()
        async with factory() as session:
            found = await get_program(session, program)
            if found is None:
                err_console.print(f"[red]No program named {program!r}[/red]")
                raise typer.Exit(code=2)

            if chosen == "html":
                from reconx.report.html import build_html_report

                text = await build_html_report(
                    session, found, include_discarded=True
                )
                suffix = ".html"
            elif chosen == "json":
                from reconx.report.json_export import dump_json_report

                text = await dump_json_report(session, found, include_discarded=True)
                suffix = ".json"
            else:
                text = await build_markdown_report(
                    session, found, include_discarded=include_discarded
                )
                suffix = ".md"

        if output:
            path = Path(output)
            if path.suffix == "":
                path = path.with_suffix(suffix)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            console.print(f"[green]Wrote[/green] {path} ({len(text):,} bytes)")
        else:
            console.print(text, markup=False, highlight=False)

    asyncio.run(run())


@app.command()
def api(
    host: Annotated[
        str | None, typer.Option("--host", help="Address to bind (default 127.0.0.1)")
    ] = None,
    port: Annotated[int | None, typer.Option("--port", help="Port to bind")] = None,
    reload: Annotated[bool, typer.Option("--reload", help="Reload on code changes")] = False,
) -> None:
    """Serve the HTTP API.

    Binds to loopback by default. It refuses to bind anywhere else without
    RECONX_API_TOKEN set, because it serves findings.
    """
    import uvicorn

    from reconx.api.app import ApiExposureError, assert_safe_binding, create_app

    settings = get_settings()
    bind_host = host or settings.api_host
    bind_port = port or settings.api_port

    try:
        assert_safe_binding(bind_host, settings.api_token)
    except ApiExposureError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    settings.ensure_dirs()
    console.print(
        Panel(
            f"http://{bind_host}:{bind_port}\n"
            f"docs: http://{bind_host}:{bind_port}/docs\n"
            f"auth: {'bearer token required' if settings.api_token else 'none (loopback only)'}\n"
            f"database: {settings.database_url}",
            title="ReconX API",
            border_style="cyan",
        )
    )
    uvicorn.run(
        "reconx.api.app:create_app" if reload else create_app(settings),
        host=bind_host,
        port=bind_port,
        factory=reload,
        reload=reload,
        log_level="info",
    )


# ---------------------------------------------------------------------------
# next actions
# ---------------------------------------------------------------------------


@app.command("next")
def next_actions(
    program: Annotated[str, typer.Argument(help="Program slug")],
    limit: Annotated[int, typer.Option("--limit", "-n")] = 15,
    kind: Annotated[
        str | None,
        typer.Option("--kind", help="finding, asset, coverage, staleness or setup"),
    ] = None,
) -> None:
    """What to do next, ordered, with the reasoning."""

    async def run() -> None:
        from reconx.triage.recommend import recommend

        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            found = await get_program(session, program)
            if found is None:
                err_console.print(f"[red]No program named {program!r}[/red]")
                raise typer.Exit(code=2)

            statuses = await detect_all(ScopeGuard(load_scope_from_text(found.scope_yaml)))
            actions = await recommend(
                session, found, limit=limit * 3, tool_statuses=statuses
            )

        if kind:
            actions = [item for item in actions if item.kind == kind]
        actions = actions[:limit]

        if not actions:
            console.print("Nothing to suggest. Run a scan first.")
            return

        colours = {
            "finding": "red",
            "asset": "magenta",
            "coverage": "yellow",
            "staleness": "blue",
            "setup": "cyan",
        }
        console.print(f"[bold]Next actions for {found.name}[/bold]\n")
        for index, item in enumerate(actions, 1):
            colour = colours.get(item.kind, "white")
            console.print(
                f"[bold]{index}.[/bold] [{colour}]({item.kind})[/{colour}] "
                f"{item.subject}"
            )
            console.print(f"   [bold]Do:[/bold] {item.action}")
            console.print(f"   [dim]Why: {item.why}[/dim]")
            if item.command:
                console.print(f"   [green]$ {item.command}[/green]")
            console.print()

    asyncio.run(run())


@triage_app.command("rescore")
def triage_rescore(
    program: Annotated[str, typer.Argument(help="Program slug")],
) -> None:
    """Recompute priority for every stored finding.

    Useful after upgrading, or after changing how much you care about a class of
    asset. Scoring is deterministic, so this only ever changes the ordering.
    """

    async def run() -> None:
        from reconx.db.models import Asset, Finding
        from reconx.triage.priority import compute_priority, explain_priority

        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            found = await get_program(session, program)
            if found is None:
                err_console.print(f"[red]No program named {program!r}[/red]")
                raise typer.Exit(code=2)

            assets = {
                asset.host: asset
                for asset in (
                    await session.execute(
                        select(Asset).where(Asset.program_id == found.id)
                    )
                ).scalars().all()
            }
            findings = (
                await session.execute(
                    select(Finding).where(Finding.program_id == found.id)
                )
            ).scalars().all()

            changed = 0
            top: list[tuple[float, str, str]] = []
            for finding in findings:
                host = (finding.affected_hosts or [""])[0]
                breakdown = compute_priority(finding, asset=assets.get(host))
                if abs(breakdown.priority - finding.priority) > 0.01:
                    changed += 1
                finding.priority = breakdown.priority
                session.add(finding)
                top.append((breakdown.priority, finding.title, explain_priority(breakdown)))
            await session.commit()

        console.print(
            f"Rescored {len(findings)} finding(s); {changed} changed.\n"
        )
        for priority, title, why in sorted(top, reverse=True)[:8]:
            console.print(f"  [bold]{priority:6.1f}[/bold]  {title[:60]}")
            console.print(f"          [dim]{why}[/dim]")

    asyncio.run(run())


# ---------------------------------------------------------------------------
# monitor
# ---------------------------------------------------------------------------


@monitor_app.command("status")
def monitor_status(
    program: Annotated[
        str | None, typer.Argument(help="Program slug, or omit for all programs")
    ] = None,
) -> None:
    """Show the monitoring schedule and when each stage next runs."""

    async def run() -> None:
        from datetime import datetime

        from reconx.db.models import ScheduleEntry
        from reconx.monitor.scheduler import DEFAULT_CADENCES
        from reconx.notify.base import build_notifiers

        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            programs = await list_programs(session)
            if program:
                programs = [p for p in programs if p.slug == program]
                if not programs:
                    err_console.print(f"[red]No program named {program!r}[/red]")
                    raise typer.Exit(code=2)
            if not programs:
                console.print("No programs stored yet.")
                return

            now = datetime.now(UTC)
            for found in programs:
                entries = (
                    await session.execute(
                        select(ScheduleEntry)
                        .where(ScheduleEntry.program_id == found.id)
                        .order_by(ScheduleEntry.stage)
                    )
                ).scalars().all()

                state = "[green]on[/green]" if found.monitoring_enabled else "[yellow]off[/yellow]"
                table = Table(title=f"{found.name} — monitoring {state}")
                table.add_column("Stage", style="bold")
                table.add_column("Every")
                table.add_column("Last run")
                table.add_column("Next run")
                table.add_column("Status")

                if not entries:
                    for stage, interval in DEFAULT_CADENCES.items():
                        table.add_row(
                            stage, _humanize(interval), "-",
                            "[dim]not scheduled yet[/dim]", "-",
                        )
                for entry in entries:
                    next_run = entry.next_run_at
                    if next_run is not None and next_run.tzinfo is None:
                        next_run = next_run.replace(tzinfo=UTC)
                    if next_run is None:
                        due = "as soon as the service runs"
                    elif next_run <= now:
                        due = "[green]due now[/green]"
                    else:
                        due = f"in {_humanize(int((next_run - now).total_seconds()))}"
                    table.add_row(
                        entry.stage,
                        _humanize(entry.interval_seconds),
                        entry.last_run_at.strftime("%Y-%m-%d %H:%M") if entry.last_run_at else "-",
                        due,
                        (entry.last_status.value if entry.last_status else "-")
                        + (
                            f" ({entry.consecutive_failures} fails)"
                            if entry.consecutive_failures
                            else ""
                        ),
                    )
                console.print(table)

        hub = build_notifiers()
        if hub.enabled:
            console.print(f"\nAlerts go to: [bold]{', '.join(hub.channels)}[/bold]")
        else:
            console.print(
                "\n[yellow]No alert channel configured.[/yellow] Monitoring will still "
                "run and record findings, but nothing will reach you. Set "
                "RECONX_DISCORD_WEBHOOK, RECONX_SLACK_WEBHOOK, "
                "RECONX_TELEGRAM_BOT_TOKEN or RECONX_GENERIC_WEBHOOK in .env"
            )

    asyncio.run(run())


def _humanize(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


@monitor_app.command("enable")
def monitor_enable(
    program: Annotated[str, typer.Argument(help="Program slug")],
) -> None:
    """Turn on continuous monitoring and create the default schedule."""
    _set_monitoring(program, True)


@monitor_app.command("disable")
def monitor_disable(
    program: Annotated[str, typer.Argument(help="Program slug")],
) -> None:
    """Turn off continuous monitoring. Stored data is kept."""
    _set_monitoring(program, False)


def _set_monitoring(program: str, enabled: bool) -> None:
    async def run() -> None:
        from reconx.monitor.scheduler import MonitorService

        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            found = await get_program(session, program)
            if found is None:
                err_console.print(f"[red]No program named {program!r}[/red]")
                raise typer.Exit(code=2)
            found.monitoring_enabled = enabled
            session.add(found)
            await session.commit()
            target = found

        if enabled:
            service = MonitorService()
            entries = await service.ensure_schedules(target)
            console.print(
                f"[green]Monitoring on[/green] for [bold]{target.name}[/bold] "
                f"({len(entries)} stage schedules)"
            )
            console.print(
                "Start the service with [bold]reconx serve[/bold], then check "
                f"[bold]reconx monitor status {target.slug}[/bold]"
            )
        else:
            console.print(f"[yellow]Monitoring off[/yellow] for {target.name}")

    asyncio.run(run())


@monitor_app.command("cadence")
def monitor_cadence(
    program: Annotated[str, typer.Argument(help="Program slug")],
    stage: Annotated[str, typer.Argument(help="Stage name")],
    interval: Annotated[
        str, typer.Argument(help="Interval, e.g. 30m, 6h, 2d")
    ],
) -> None:
    """Change how often one stage runs for one program."""

    async def run() -> None:
        from reconx.db.store import upsert_schedule_entry

        seconds = _parse_interval(interval)
        if stage not in STAGE_REGISTRY:
            err_console.print(
                f"[red]Unknown stage {stage!r}.[/red] Stages: "
                + ", ".join(sorted(STAGE_REGISTRY))
            )
            raise typer.Exit(code=2)

        await init_db()
        factory = get_session_factory()
        async with factory() as session:
            found = await get_program(session, program)
            if found is None:
                err_console.print(f"[red]No program named {program!r}[/red]")
                raise typer.Exit(code=2)
            await upsert_schedule_entry(
                session, found.id, stage, interval_seconds=seconds
            )
            await session.commit()
        console.print(
            f"[green]{stage}[/green] will run every [bold]{_humanize(seconds)}[/bold] "
            f"for {program}"
        )

    asyncio.run(run())


def _parse_interval(text: str) -> int:
    raw = text.strip().lower()
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if raw and raw[-1] in multipliers:
        try:
            return max(60, int(float(raw[:-1]) * multipliers[raw[-1]]))
        except ValueError:
            pass
    try:
        return max(60, int(raw))
    except ValueError as exc:
        err_console.print(
            f"[red]Could not read interval {text!r}.[/red] Use forms like 30m, 6h, 2d."
        )
        raise typer.Exit(code=2) from exc


@monitor_app.command("tick")
def monitor_tick(
    no_external_tools: Annotated[
        bool, typer.Option("--no-external-tools", help="Use only the built-in paths")
    ] = False,
) -> None:
    """Run one monitoring cycle now, then exit. Useful for checking setup."""

    async def run() -> None:
        from reconx.monitor.scheduler import MonitorService

        await init_db()
        service = MonitorService(use_external_tools=not no_external_tools)
        console.print("Running one monitoring cycle...")
        report = await service.tick()

        if report.idle:
            console.print("[dim]Nothing was due.[/dim]")
        else:
            for slug in report.programs_run:
                console.print(
                    f"[green]{slug}[/green]: ran "
                    f"{', '.join(report.stages_run.get(slug, []))}"
                )
            console.print(
                f"\nChanges detected: {report.changes_found}   "
                f"Notifications sent: {report.notifications_sent}"
            )
        for slug in report.skipped_busy:
            console.print(f"[yellow]{slug}: a scan was already running[/yellow]")
        for slug, error in report.errors.items():
            err_console.print(f"[red]{slug}: {error}[/red]")

    asyncio.run(run())


@app.command()
def serve(
    tick: Annotated[
        int, typer.Option("--tick", help="Seconds between checks for due work")
    ] = 60,
    no_external_tools: Annotated[
        bool, typer.Option("--no-external-tools", help="Use only the built-in paths")
    ] = False,
) -> None:
    """Run continuously: check for due work, scan, and alert on what changed.

    Runs in the foreground. Stop it with Ctrl-C; the schedule lives in the
    database, so restarting picks up where it left off.
    """

    async def run() -> None:
        from reconx.monitor.scheduler import MonitorService

        settings = get_settings()
        settings.ensure_dirs()
        await init_db()

        factory = get_session_factory()
        async with factory() as session:
            programs = [p for p in await list_programs(session) if p.monitoring_enabled]

        service = MonitorService(
            tick_seconds=tick, use_external_tools=not no_external_tools
        )
        for found in programs:
            await service.ensure_schedules(found)

        console.print(
            Panel(
                f"monitoring {len(programs)} program(s): "
                f"{', '.join(p.slug for p in programs) or 'none'}\n"
                f"checking for due work every {tick}s\n"
                f"alerts: {', '.join(service.notifier_channels) or 'none configured'}\n"
                f"database: {settings.database_url}",
                title="ReconX running",
                border_style="cyan",
            )
        )
        if not programs:
            console.print(
                "[yellow]No program has monitoring enabled.[/yellow] Turn one on with "
                "[bold]reconx monitor enable <slug>[/bold]"
            )
        console.print("[dim]Ctrl-C to stop.[/dim]\n")

        await service.start()
        try:
            while True:
                await asyncio.sleep(60)
                report = service.last_report
                if report is not None and not report.idle:
                    console.print(
                        f"[dim]{report.started:%H:%M:%S}[/dim] ran "
                        f"{', '.join(report.programs_run)} · "
                        f"{report.changes_found} change(s) · "
                        f"{report.notifications_sent} alert(s)"
                    )
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await service.stop()
            console.print("\n[green]Stopped.[/green] The schedule is saved.")

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print("\n[green]Stopped.[/green]")


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
