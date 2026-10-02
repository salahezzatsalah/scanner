"""Tests for authenticated scanning.

Five claims, in the order they matter:

1. **A session unlocks findings.** Asserted as a pair -- the same bug must be
   invisible without a session and confirmed with one -- so the test fails if auth
   stops working *or* if the bug turns out to be findable unauthenticated. Either
   would make the feature a lie.
2. **A session that dies mid-scan is caught.** The silent-failure case: a scan
   that loses its session returns "no signal" everywhere and reads as a clean
   scan of a well-built site. Nothing in the output would say otherwise.
3. **Credentials do not leak.** Asserted by searching the generated artefacts for
   the literal secret. Crude, and exactly right: it catches a leak through a
   report format nobody thought about.
4. **The trap is rejected.** A page that sits under /account and answers 200 is
   not a finding just because the scanner was logged in.
5. **/logout is never requested.** Asserted against what the target actually
   received, not against the deny list that is supposed to prevent it.
"""

from __future__ import annotations

import contextlib

import pytest

from reconx.config import Settings
from reconx.db.models import FindingTier
from reconx.net.http import ScopedHttpClient
from reconx.report.repro import SESSION_PLACEHOLDER, redact
from reconx.scope.guard import DESTRUCTIVE_PATH_MARKERS, OutOfScopeError, ScopeGuard
from reconx.scope.model import AuthConfig, AuthKind, Scope, ScopeParseError, load_scope
from reconx.verify.session import (
    SessionMonitor,
    SessionState,
    looks_logged_out,
)
from reconx.verify.xss import XssVerifier
from tests.conftest import make_scope
from tests.fixtures.target_app import run_target_app

SECRET_ENV = "RECONX_AUTH_TESTPROGRAM"


def fast_settings(**overrides) -> Settings:
    payload = {
        "requests_per_second_per_host": 500.0,
        "max_concurrent_requests": 20,
        "http_timeout_seconds": 10.0,
        "max_retries": 0,
    }
    payload.update(overrides)
    return Settings(**payload)


@pytest.fixture
def target():
    with run_target_app() as app:
        yield app


def auth_scope(app, **overrides) -> Scope:
    """A scope covering the fixture, with an auth block pointing at it."""
    auth = {
        "credential_env": SECRET_ENV,
        "kind": "cookie",
        "session_check_url": app.url("/account"),
        "session_check_marker": app.session_marker,
    }
    auth.update(overrides)
    return make_scope(
        program="Auth Test Target",
        in_scope=[app.host],
        out_of_scope=[],
        auth=auth,
    )


def monitor_for(app, **overrides) -> SessionMonitor:
    scope = auth_scope(app, **overrides)
    return SessionMonitor.from_scope(scope, {SECRET_ENV: app.session_cookie})


# ---------------------------------------------------------------------------
# 1. a session unlocks findings
# ---------------------------------------------------------------------------


async def test_the_gated_bug_is_invisible_without_a_session(target) -> None:
    """Half of the pair. If this ever passes *with* a finding, auth is pointless."""
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verdict = await XssVerifier(
            http, attempts=2, required=2, headless_confirm=False
        ).verify(target.url("/account/orders?ref=A-1"), "ref")

    assert verdict.vulnerable is False, (
        "the authenticated bug was found without a session, so the fixture is not "
        "actually gated and the other half of this pair proves nothing"
    )


async def test_the_gated_bug_is_found_with_a_session(target) -> None:
    """The other half: the same URL, the same verifier, plus a session."""
    monitor = monitor_for(target)
    assert monitor.configured

    scope = auth_scope(target)
    async with ScopedHttpClient(
        ScopeGuard(scope, authenticated=True), settings=fast_settings(), session=monitor
    ) as http:
        verdict = await XssVerifier(
            http,
            attempts=2,
            required=2,
            headless_confirm=False,
            session_headers=monitor.headers(),
        ).verify(target.url("/account/orders?ref=A-1"), "ref")

    assert verdict.vulnerable is True, verdict.reason
    assert verdict.site is not None
    assert verdict.site.escapable is True


def browser_available() -> bool:
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        return False
    from reconx.verify.xss import resolve_chromium_path

    return resolve_chromium_path() is not None


needs_browser = pytest.mark.skipif(
    not browser_available(),
    reason="execution confirmation needs Playwright and a Chromium build",
)


@needs_browser
async def test_an_unseeded_browser_downgrades_a_real_authenticated_finding(
    target,
) -> None:
    """Why the Playwright context has to be seeded, measured rather than argued.

    The browser gets a blank profile by default, so it loads the sign-in page
    instead of the vulnerable one, the marker never runs, and the verifier
    concludes something is "preventing it, such as a Content-Security-Policy".
    There is no CSP. The finding is real and the tooling lost it.

    Confirmed with a seeded context, Needs review without: the same bug, the same
    session on the HTTP client, differing only in what the browser was told.
    """
    monitor = monitor_for(target)
    scope = auth_scope(target)
    url = target.url("/account/orders?ref=A-1")

    async def verdict_with(seed: bool):
        async with ScopedHttpClient(
            ScopeGuard(scope, authenticated=True),
            settings=fast_settings(),
            session=monitor,
        ) as http:
            return await XssVerifier(
                http,
                attempts=2,
                required=2,
                headless_confirm=True,
                session_headers=monitor.headers() if seed else None,
            ).verify(url, "ref")

    seeded = await verdict_with(True)
    blank = await verdict_with(False)

    assert seeded.tier is FindingTier.CONFIRMED, seeded.reason
    assert seeded.dom_confirmed is True
    assert blank.tier is FindingTier.NEEDS_REVIEW, blank.reason
    assert blank.dom_confirmed is False
    assert seeded.confidence > blank.confidence


# ---------------------------------------------------------------------------
# 2. a session that dies mid-scan is caught
# ---------------------------------------------------------------------------


async def test_a_valid_session_checks_out(target) -> None:
    monitor = monitor_for(target)
    async with ScopedHttpClient(
        ScopeGuard(auth_scope(target)), settings=fast_settings(), session=monitor
    ) as http:
        verdict = await monitor.check(http)

    assert verdict.state is SessionState.AUTHENTICATED
    assert verdict.active is True
    assert verdict.obstructed is False
    assert target.session_marker in (verdict.signal or "")


async def test_an_expired_session_is_caught_rather_than_read_as_clean(target) -> None:
    """The failure this whole module exists for."""
    target.expire_session_after(1)
    monitor = monitor_for(target)

    async with ScopedHttpClient(
        ScopeGuard(auth_scope(target)), settings=fast_settings(), session=monitor
    ) as http:
        first = await monitor.check(http)
        second = await monitor.check(http)

    assert first.state is SessionState.AUTHENTICATED
    assert second.state is SessionState.EXPIRED
    assert second.obstructed is True
    assert "expired" in second.explain()
    assert "unreliable" in second.explain()
    assert monitor.expiries == 1


async def test_a_session_check_that_cannot_complete_is_unknown_not_clean(target) -> None:
    """An unverifiable session is reported, not assumed to have held.

    ``UNKNOWN`` counts as obstruction on purpose: a check that failed is exactly
    the case where a dead session goes unnoticed.
    """
    app_host = target.host
    port = target.port
    target.shutdown()  # the host is gone; the check cannot complete

    scope = make_scope(
        in_scope=[app_host],
        out_of_scope=[],
        auth={
            "credential_env": SECRET_ENV,
            "session_check_url": f"http://{app_host}:{port}/account",
            "session_check_marker": "Sign out",
        },
    )
    monitor = SessionMonitor.from_scope(scope, {SECRET_ENV: "rxsession=whatever"})
    async with ScopedHttpClient(
        ScopeGuard(scope), settings=fast_settings(), session=monitor
    ) as http:
        verdict = await monitor.check(http)

    assert verdict.state is SessionState.UNKNOWN
    assert verdict.obstructed is True
    assert "not known whether" in verdict.explain()


def test_an_unconfigured_scan_is_not_treated_as_a_broken_session() -> None:
    monitor = SessionMonitor()
    assert monitor.configured is False
    assert monitor.verdict.state is SessionState.NOT_CONFIGURED
    assert monitor.verdict.obstructed is False
    assert monitor.headers() == {}
    assert "unauthenticated" in monitor.verdict.explain()


def test_a_scope_with_auth_but_no_credential_in_the_environment(target) -> None:
    """A missing env var must read as unauthenticated, not as authenticated."""
    monitor = SessionMonitor.from_scope(auth_scope(target), {})
    assert monitor.configured is False
    assert monitor.headers() == {}


@pytest.mark.parametrize(
    ("label", "body", "status", "location", "flagged"),
    [
        ("signed in", '<a href="/logout">Sign out</a>', 200, "", False),
        ("login form", '<input type="password" name="pw">', 200, "", True),
        ("session expired text", "<p>Your session has expired</p>", 200, "", True),
        ("redirect to login", "", 302, "https://x/login?next=/a", True),
        ("401", "<p>no</p>", 401, "", True),
        # Must NOT fire: a signed-in page with a login widget in the nav, and an
        # ordinary page that simply has no reason to carry the marker.
        ("marker plus login widget", '<input type="password"> Sign out', 200, "", False),
        ("ordinary page", "<h1>Products</h1>", 200, "", False),
    ],
)
def test_the_logged_out_heuristic_is_conservative(
    label: str, body: str, status: int, location: str, flagged: bool
) -> None:
    result = looks_logged_out(body, marker="Sign out", status=status, location=location)
    assert (result is not None) is flagged, f"{label}: {result}"


# ---------------------------------------------------------------------------
# 3. credentials do not leak
# ---------------------------------------------------------------------------


def test_the_scope_file_cannot_hold_the_credential_itself() -> None:
    """The field names an environment variable, so a pasted secret is rejected."""
    with pytest.raises(ValueError) as excinfo:
        AuthConfig(
            credential_env="rxsession=abc123",
            session_check_url="https://a.example.com/x",
            session_check_marker="Sign out",
        )
    assert "must never hold the credential" in str(excinfo.value)


def test_a_session_check_url_outside_the_scope_is_refused(tmp_path) -> None:
    """Checking a session against an off-scope host would hand it to a stranger."""
    path = tmp_path / "scope.yaml"
    path.write_text(
        "program: P\n"
        "authorization:\n"
        "  authorized_by: a@b.c\n"
        "  date: '2026-09-29'\n"
        "  attestation: authorized\n"
        "in_scope: ['*.example.com']\n"
        "auth:\n"
        f"  credential_env: {SECRET_ENV}\n"
        "  session_check_url: https://evil.example.net/account\n"
        "  session_check_marker: Sign out\n"
    )
    with pytest.raises(ScopeParseError) as excinfo:
        load_scope(path)
    assert "does not cover" in str(excinfo.value)
    assert "not authorized to send it" in str(excinfo.value)


def test_the_monitor_keeps_the_credential_out_of_its_own_repr(target) -> None:
    monitor = monitor_for(target)
    assert target.session_value not in repr(monitor)
    assert target.session_value not in str(monitor)


def test_redaction_removes_the_session_and_keeps_a_cookie_payload(target) -> None:
    """A cookie-borne payload must survive redaction; the session must not."""
    monitor = monitor_for(target)
    command = (
        f"curl -sS -i -k -H 'Cookie: {target.session_cookie}; pref=PAYLOAD' "
        f"'{target.url('/account')}'"
    )
    cleaned = redact(command, monitor.redactions())

    assert target.session_value not in cleaned
    assert SESSION_PLACEHOLDER in cleaned
    assert "pref=PAYLOAD" in cleaned, "the payload is the finding and must survive"


def test_the_session_rides_in_scope_requests_and_merges_with_a_payload(target) -> None:
    monitor = monitor_for(target)
    client = ScopedHttpClient(
        ScopeGuard(auth_scope(target)), settings=fast_settings(), session=monitor
    )

    assert client._with_session(None) == {"Cookie": target.session_cookie}
    # A cookie-borne payload is appended rather than replacing the session, or the
    # scan would log itself out for exactly the requests establishing a finding.
    merged = client._with_session({"Cookie": "pref=PAYLOAD"})
    assert merged["Cookie"] == f"{target.session_cookie}; pref=PAYLOAD"


async def test_the_session_never_reaches_an_out_of_scope_host(target) -> None:
    """Containment comes from the guard, which refuses the hop before it is sent."""
    monitor = monitor_for(target)
    async with ScopedHttpClient(
        ScopeGuard(auth_scope(target)), settings=fast_settings(), session=monitor
    ) as http:
        with pytest.raises(OutOfScopeError):
            await http.get("https://evil.example.net/collect")

        blocked = [record for record in http.audit_records() if record.blocked]
        assert blocked, "the off-scope request should have been refused and audited"
        # The audit log carries no headers at all, which is why a credential cannot
        # reach it. Asserted rather than assumed.
        for record in http.audit_records():
            assert target.session_value not in str(record.as_dict())


def test_the_source_client_cannot_be_given_a_session() -> None:
    """Intelligence sources are third parties outside the program.

    Structural rather than conventional: ``SourceClient`` takes no argument for a
    session, so there is no call that could pass one by mistake.
    """
    import inspect

    from reconx.net.sources import SourceClient

    parameters = inspect.signature(SourceClient.__init__).parameters
    assert "session" not in parameters
    assert "auth" not in parameters
    assert "auth_headers" not in parameters


def test_only_the_tools_that_reach_the_target_are_given_a_session(target) -> None:
    """The same set that carries the operator's handle, for the same reason."""
    from reconx.tools.registry import get_runner

    monitor = monitor_for(target)
    guard = ScopeGuard(auth_scope(target))
    headers = monitor.headers()

    for name in ("httpx", "katana", "nuclei", "ffuf"):
        args = get_runner(name, guard, auth_headers=headers).identity_args()
        assert any(target.session_value in arg for arg in args), name

    # These ask crt.sh and VirusTotal *about* the target. Sending them a session
    # would hand the credential to parties who are not in the program.
    for name in ("subfinder", "amass", "gau", "dnsx", "naabu"):
        args = get_runner(name, guard, auth_headers=headers).identity_args()
        assert args == [], f"{name} was given a session it must never receive"


async def test_a_recorded_tool_command_carries_no_credential(target) -> None:
    """argv is visible to ps and lands in stage notes, so the copy kept is clean."""
    from reconx.tools.base import ToolRunner, ToolSpec

    monitor = monitor_for(target)
    spec = ToolSpec(
        name="probe",
        binary="echo",
        purpose="t",
        install="n/a",
        version_args=("--version",),
        identity_pattern=r"coreutils|echo",
        identity_header_args=("-H", "{header}: {value}"),
    )
    runner = ToolRunner(
        spec, ScopeGuard(auth_scope(target)), auth_headers=monitor.headers()
    )
    result = await runner.run(["-n"], targets=[target.host])

    assert target.session_value not in " ".join(result.command)
    assert SESSION_PLACEHOLDER in " ".join(result.command)
    # The process still received the real value: redaction is on the stored copy.
    assert target.session_value in result.stdout


def test_sqlmap_reports_that_it_cannot_carry_a_session(target) -> None:
    """Its flag takes a value, not a header line.

    Saying so beats silently running an unauthenticated scan whose empty result
    reads as clean.
    """
    from reconx.tools.registry import get_runner

    monitor = monitor_for(target)
    runner = get_runner(
        "sqlmap", ScopeGuard(auth_scope(target)), auth_headers=monitor.headers()
    )
    args = runner.identity_args()

    assert all(target.session_value not in arg for arg in args)
    assert runner.auth_unsupported is True


# ---------------------------------------------------------------------------
# 4 and 5. the trap, and the action never taken
# ---------------------------------------------------------------------------


async def test_a_page_that_ignores_the_session_is_not_a_finding(target) -> None:
    """/account/fake-gate answers 200 either way. Being logged in changed nothing."""
    monitor = monitor_for(target)
    async with ScopedHttpClient(
        ScopeGuard(auth_scope(target)), settings=fast_settings(), session=monitor
    ) as http:
        with_session = await http.get(target.url("/account/fake-gate"))

    async with ScopedHttpClient(
        ScopeGuard(make_scope(in_scope=[target.host], out_of_scope=[])),
        settings=fast_settings(),
    ) as anonymous:
        without = await anonymous.get(target.url("/account/fake-gate"))

    assert with_session.text == without.text, (
        "the trap must be indistinguishable with and without a session"
    )
    assert target.session_marker not in with_session.text


@pytest.mark.parametrize(
    "path",
    [
        "/logout",
        "/account/delete",
        "/settings/change-password",
        "/billing/cancel",
        "/api/keys/revoke",
        "/invite",
    ],
)
def test_state_changing_paths_are_refused_while_authenticated(target, path: str) -> None:
    guard = ScopeGuard(auth_scope(target), authenticated=True)
    decision = guard.decide_url(target.url(path))

    assert decision.allowed is False, path
    assert "changes state" in decision.reason


@pytest.mark.parametrize("path", ["/logout", "/account/delete", "/billing/cancel"])
def test_the_same_paths_are_allowed_when_not_authenticated(target, path: str) -> None:
    """Unauthenticated, a GET of /logout does nothing, and hiding it hides surface."""
    guard = ScopeGuard(auth_scope(target), authenticated=False)
    assert guard.decide_url(target.url(path)).allowed is True
    assert guard.forbidden_paths == ()


def test_a_program_can_opt_out_of_the_deny_list(target) -> None:
    """Some programs want exactly these tested, and that is their call."""
    guard = ScopeGuard(
        auth_scope(target, avoid_state_changing_paths=False), authenticated=True
    )
    assert guard.forbidden_paths == ()
    assert guard.decide_url(target.url("/logout")).allowed is True


def test_a_program_can_add_its_own_forbidden_paths(target) -> None:
    guard = ScopeGuard(
        auth_scope(target, extra_forbidden_paths=["/run-payroll"]), authenticated=True
    )
    assert "/run-payroll" in guard.forbidden_paths
    assert guard.decide_url(target.url("/admin/run-payroll")).allowed is False
    # And the built-ins are still there.
    assert "/logout" in guard.forbidden_paths


async def test_logout_is_never_requested_during_an_authenticated_crawl(target) -> None:
    """Asserted against what the target received, not against the deny list.

    The deny list is the mechanism; this is the outcome. A test of the mechanism
    would still pass if some code path bypassed the guard.
    """
    from reconx.net.http import ScopedHttpClient as Client

    monitor = monitor_for(target)
    guard = ScopeGuard(auth_scope(target), authenticated=True)

    async with Client(guard, settings=fast_settings(), session=monitor) as http:
        # Walk the account page's own links, as a crawler would.
        await http.get(target.url("/account"))
        for path in ("/account/orders?ref=A-1", "/account/fake-gate", "/logout"):
            # /logout is refused by the guard, which is the point of the test.
            with contextlib.suppress(OutOfScopeError):
                await http.get(target.url(path))

    assert not any("/logout" in entry for entry in target.requested_paths), (
        f"the scan requested /logout: {target.requested_paths}"
    )
    assert any("/account/orders" in entry for entry in target.requested_paths)


def test_the_deny_list_covers_the_actions_that_cannot_be_undone() -> None:
    """A checklist, so a future edit cannot quietly drop one."""
    for marker in ("/logout", "/delete", "/change-password", "/billing", "/invite"):
        assert marker in DESTRUCTIVE_PATH_MARKERS


# ---------------------------------------------------------------------------
# shapes of auth other than a cookie
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "credential", "expected"),
    [
        (AuthKind.COOKIE, "s=abc", {"Cookie": "s=abc"}),
        (AuthKind.BEARER, "tok123", {"Authorization": "Bearer tok123"}),
    ],
)
def test_each_auth_kind_builds_its_own_header(kind, credential, expected) -> None:
    config = AuthConfig(
        credential_env="X",
        kind=kind,
        session_check_url="https://a.example.com/x",
        session_check_marker="Sign out",
    )
    assert config.headers(credential) == expected


def test_a_named_header_is_used_for_the_header_kind() -> None:
    config = AuthConfig(
        credential_env="X",
        kind=AuthKind.HEADER,
        header_name="X-Session-Token",
        session_check_url="https://a.example.com/x",
        session_check_marker="Sign out",
    )
    assert config.headers("abc") == {"X-Session-Token": "abc"}


def test_no_credential_means_no_headers() -> None:
    config = AuthConfig(
        credential_env="X",
        session_check_url="https://a.example.com/x",
        session_check_marker="Sign out",
    )
    assert config.headers("") == {}


def test_describe_never_includes_the_credential() -> None:
    config = AuthConfig(
        credential_env="MY_VAR",
        session_check_url="https://a.example.com/x",
        session_check_marker="Sign out",
    )
    described = config.describe({"MY_VAR": "SUPERSECRETVALUE"})
    assert "SUPERSECRETVALUE" not in described
    assert "$MY_VAR" in described
    assert "(set)" in described
    assert "NOT SET" in config.describe({})


# ---------------------------------------------------------------------------
# end to end, through the orchestrator
# ---------------------------------------------------------------------------


@pytest.mark.slow
async def test_an_authenticated_pipeline_finds_the_gated_bug_and_leaks_nothing(
    file_db, target, monkeypatch
) -> None:
    """The whole claim, through the orchestrator, with nothing hinted to it.

    Three things are asserted together because they only mean something together:
    the gated bug is found, the trap under the same prefix is not reported, and the
    credential appears in none of what was stored.
    """
    from sqlalchemy import select as sa_select

    from reconx.db.models import AuditEntry, Evidence, Finding
    from reconx.db.session import get_session_factory
    from reconx.orchestrator import Orchestrator
    from reconx.stages.content import ContentStage
    from reconx.stages.params import ParamStage
    from reconx.stages.resolve_probe import ResolveProbeStage
    from reconx.stages.vulns import VulnStage

    monkeypatch.setenv(SECRET_ENV, target.session_cookie)
    scope = auth_scope(target)

    orchestrator = Orchestrator(
        scope,
        use_external_tools=False,
        stage_instances={
            "resolve_probe": ResolveProbeStage(ports=(target.port,)),
            "content": ContentStage(crawl=True, archives=False, brute_force=False),
            "params": ParamStage(guess_hidden=False),
            # Only XSS: that is what the assertions rest on, and the other seven
            # classes cost minutes here while proving nothing this test claims.
            # Browser confirmation stays on, so a real authenticated finding
            # reaches Confirmed rather than being downgraded for want of a session
            # in the browser -- the failure the seeding test isolates.
            "vulns": VulnStage(
                run_nuclei=False,
                enable_timing=False,
                headless_xss=True,
                check_takeover=False,
                check_sqli=False,
                check_redirect=False,
                check_cors=False,
                check_traversal=False,
                check_ssti=False,
                check_cmdi=False,
                check_deser=False,
                check_ssrf=False,
            ),
        },
    )
    summary = await orchestrator.run(["full"])
    assert summary.status.value == "completed", summary.error

    # The run records which surface it describes.
    assert summary.session.get("configured") is True
    assert summary.session.get("state") == "authenticated"
    assert any("authenticated scan" in note for note in summary.notes)

    factory = get_session_factory()
    async with factory() as session:
        findings = (await session.execute(sa_select(Finding))).scalars().all()
        evidence = (await session.execute(sa_select(Evidence))).scalars().all()
        audit = (await session.execute(sa_select(AuditEntry))).scalars().all()

    confirmed = {f.title for f in findings if f.tier is FindingTier.CONFIRMED}
    assert any("/account/orders" in title for title in confirmed), (
        f"the authenticated bug was not found: {sorted(confirmed)}"
    )
    # The trap sits under the same prefix and must not be reported.
    assert not any("fake-gate" in title for title in confirmed)

    # Nothing the scan stored may contain the session.
    stored = [
        str(item.request_headers) + str(item.curl_command) + str(item.request_body)
        + str(item.note) + str(item.response_excerpt)
        for item in evidence
    ]
    stored += [str(entry.url) for entry in audit]
    stored += [f.description or "" for f in findings]
    leaks = [blob for blob in stored if target.session_value in blob]
    assert not leaks, f"the credential reached storage: {leaks[:2]}"

    # And /logout was never requested, whatever the crawler found.
    assert not any("/logout" in entry for entry in target.requested_paths)


@pytest.mark.slow
async def test_a_report_of_an_authenticated_scan_carries_no_credential(
    file_db, target, monkeypatch
) -> None:
    """Every report format, because a leak through one of them is still a leak."""
    import json as jsonlib

    from reconx.db.session import get_session_factory
    from reconx.orchestrator import Orchestrator
    from reconx.report.markdown import build_markdown_report
    from reconx.stages.params import ParamStage
    from reconx.stages.resolve_probe import ResolveProbeStage
    from reconx.stages.vulns import VulnStage

    monkeypatch.setenv(SECRET_ENV, target.session_cookie)
    orchestrator = Orchestrator(
        auth_scope(target),
        use_external_tools=False,
        stage_instances={
            "resolve_probe": ResolveProbeStage(ports=(target.port,)),
            "params": ParamStage(guess_hidden=False),
            "vulns": VulnStage(
                run_nuclei=False, enable_timing=False, headless_xss=False,
                check_takeover=False, check_sqli=False, check_redirect=False,
                check_cors=False, check_traversal=False, check_ssti=False,
                check_cmdi=False, check_deser=False, check_ssrf=False,
            ),
        },
    )
    summary = await orchestrator.run(["resolve_probe", "content", "params", "vulns"])
    assert summary.status.value == "completed", summary.error

    from sqlmodel import select as sm_select

    from reconx.db.models import Program

    factory = get_session_factory()
    async with factory() as session:
        program = (
            await session.execute(
                sm_select(Program).where(Program.slug == auth_scope(target).slug)
            )
        ).scalars().first()
        markdown = await build_markdown_report(session, program, include_discarded=True)

    assert target.session_value not in markdown
    assert target.session_value not in jsonlib.dumps(summary.as_dict())


@pytest.mark.slow
async def test_a_dead_session_turns_discards_into_needs_review(
    file_db, target, monkeypatch
) -> None:
    """The outcome of the session gate, not just its mechanism.

    An expired session produces false *negatives*: the verifiers were testing a
    logged-out application, so "not vulnerable" means only "not vulnerable to an
    anonymous visitor". Leaving those as discards is precisely the silent failure
    the gate exists to prevent, so they become Needs review with the reason.
    """
    from sqlalchemy import select as sa_select

    from reconx.db.models import Finding
    from reconx.db.session import get_session_factory
    from reconx.orchestrator import Orchestrator
    from reconx.stages.params import ParamStage
    from reconx.stages.resolve_probe import ResolveProbeStage
    from reconx.stages.vulns import VulnStage

    monkeypatch.setenv(SECRET_ENV, target.session_cookie)
    # Enough authenticated requests to get through recon, then the session dies
    # part-way through the vulnerability pass.
    target.expire_session_after(12)

    orchestrator = Orchestrator(
        auth_scope(target),
        use_external_tools=False,
        stage_instances={
            "resolve_probe": ResolveProbeStage(ports=(target.port,)),
            "params": ParamStage(guess_hidden=False),
            # XSS alone still produces discards, which is what gets promoted.
            "vulns": VulnStage(
                run_nuclei=False,
                enable_timing=False,
                headless_xss=False,
                check_takeover=False,
                check_sqli=False,
                check_redirect=False,
                check_cors=False,
                check_traversal=False,
                check_ssti=False,
                check_cmdi=False,
                check_deser=False,
                check_ssrf=False,
            ),
        },
    )
    summary = await orchestrator.run(["resolve_probe", "content", "params", "vulns"])
    assert summary.status.value == "completed", summary.error

    factory = get_session_factory()
    async with factory() as session:
        findings = (await session.execute(sa_select(Finding))).scalars().all()

    needs_review = [f for f in findings if f.tier is FindingTier.NEEDS_REVIEW]
    assert needs_review, (
        "the session expired mid-scan and every discard stayed a discard, which is "
        "exactly the clean-looking empty result this gate exists to prevent"
    )
    assert any("not signed in" in (f.description or "") for f in needs_review)
    assert any("before treating it as clean" in (f.description or "") for f in needs_review)
    # A promoted finding keeps no discard reason, or a report would show both.
    for finding in needs_review:
        assert finding.discard_reason is None

    assert summary.session.get("expiries", 0) >= 1
