"""Tests for the self-registration / SSO-bypass check.

Half of these prove the finding is made. The other half prove it is *not* made
for the four things that look identical over HTTP: an ordinary consumer sign-up,
a register page that only hands off to the identity provider, registration
behind an invitation code, and an application that deliberately offers both
local accounts and SSO.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx.config import Settings
from reconx.db.models import Finding, FindingTier, Program, Severity
from reconx.db.store import upsert_asset
from reconx.net.dns import ScopedResolver
from reconx.net.http import ScopedHttpClient
from reconx.net.sources import SourceClient
from reconx.scope.guard import ScopeGuard
from reconx.scope.model import ScopeParseError, load_scope
from reconx.stages.base import StageContext
from reconx.stages.vulns import VulnStage
from reconx.verify.registration import (
    AccountCreationRefused,
    RegistrationVerifier,
    classify_registration,
    detect_identity_providers,
    parse_forms,
    redact,
    scan_sensitive_data,
)
from tests.conftest import VALID_AUTH, make_scope
from tests.fixtures.target_app import run_target_app

IDP = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"


def fast_settings(**overrides) -> Settings:
    payload = {
        "requests_per_second_per_host": 200.0,
        "http_timeout_seconds": 5.0,
        "max_retries": 0,
        "reproduce_attempts": 2,
        "reproduce_required": 2,
    }
    payload.update(overrides)
    return Settings(**payload)


@pytest.fixture
def target():
    with run_target_app() as app:
        yield app


def page(body: str) -> str:
    return f"<!doctype html><html><body>{body}</body></html>"


# ---------------------------------------------------------------------------
# form parsing and classification
# ---------------------------------------------------------------------------


def test_a_form_action_is_resolved_and_hidden_values_are_kept() -> None:
    body = page(
        '<form method="post" action="../do/register">'
        '<input type="hidden" name="_token" value="abc123">'
        '<input name="email"><input type="password" name="password">'
        '<input type="password" name="password_confirmation">'
        "<button type=\"submit\">Register</button></form>"
    )
    form = parse_forms(body, "https://app.example.com/account/register")[0]

    assert form.method == "POST"
    assert form.action == "https://app.example.com/do/register"
    assert form.same_origin is True
    assert form.submit_labels == ["Register"]

    registration, _ = classify_registration(form, body)
    assert registration is not None
    # The token has to survive into the submission or the server rejects it for
    # a reason that says nothing about whether registration is open.
    assert (registration.csrf_field, registration.csrf_value) == ("_token", "abc123")
    assert registration.confirm_field == "password_confirmation"


@pytest.mark.parametrize(
    ("label", "body"),
    [
        (
            "username and password only",
            '<form method="post" action="/login"><input name="username">'
            '<input type="password" name="password">'
            '<input type="checkbox" name="remember">'
            "<button type=\"submit\">Sign in</button></form>",
        ),
        (
            "email and password only",
            '<form method="post" action="/login"><input name="email">'
            '<input type="password" name="password"></form>',
        ),
    ],
)
def test_a_login_form_is_not_mistaken_for_registration(label: str, body: str) -> None:
    form = parse_forms(page(body), "https://app.example.com/login")[0]
    registration, reason = classify_registration(form, body)

    assert registration is None, label
    assert "login form" in reason


def test_a_handoff_to_the_identity_provider_is_not_local_registration() -> None:
    body = page(
        f'<form method="post" action="{IDP}">'
        '<input name="email"><input type="password" name="passwd"></form>'
    )
    form = parse_forms(body, "https://app.example.com/register")[0]
    registration, reason = classify_registration(form, body)

    assert registration is None
    assert "different origin" in reason
    assert "login.microsoftonline.com" in reason


def test_a_get_form_does_not_create_an_account() -> None:
    body = page(
        '<form action="/search"><input name="q">'
        '<input type="password" name="password"></form>'
    )
    form = parse_forms(body, "https://app.example.com/register")[0]
    assert classify_registration(form, body)[0] is None


def test_registration_behind_an_invitation_code_is_marked_gated() -> None:
    body = page(
        '<form method="post" action="/register"><input name="full_name">'
        '<input type="email" name="email"><input name="invitation_code">'
        '<input type="password" name="password">'
        '<input type="password" name="password_confirmation"></form>'
    )
    form = parse_forms(body, "https://app.example.com/register")[0]
    registration, _ = classify_registration(form, body)

    assert registration is not None
    assert registration.gated is True
    assert registration.invite_fields == ["invitation_code"]


def test_wording_about_approval_gates_registration_too() -> None:
    body = page(
        "<p>New accounts are subject to approval by an administrator.</p>"
        '<form method="post" action="/register"><input name="full_name">'
        '<input type="email" name="email"><input type="password" name="password">'
        '<input type="password" name="password2"></form>'
    )
    form = parse_forms(body, "https://app.example.com/register")[0]
    registration, _ = classify_registration(form, body)

    assert registration is not None
    assert registration.approval_required is True
    assert registration.gated is True


def test_a_captcha_is_noticed_without_changing_the_verdict() -> None:
    body = page(
        '<form method="post" action="/register"><input name="name">'
        '<input type="email" name="email"><input type="password" name="password">'
        '<input type="password" name="password_confirmation">'
        '<div class="g-recaptcha" data-sitekey="x"></div></form>'
    )
    form = parse_forms(body, "https://app.example.com/register")[0]
    registration, _ = classify_registration(form, body)

    assert registration is not None
    assert registration.captcha is True
    assert registration.gated is False


# ---------------------------------------------------------------------------
# identity providers
# ---------------------------------------------------------------------------


def test_an_identity_provider_is_named_with_the_marker_that_found_it() -> None:
    found = detect_identity_providers(
        f'<a href="{IDP}?client_id=abc">Sign in with Microsoft</a>'
    )
    providers = dict((provider, marker) for provider, marker in found)

    assert "Microsoft Entra ID (Azure AD)" in providers
    assert providers["Microsoft Entra ID (Azure AD)"] == "login.microsoftonline.com"


def test_ordinary_prose_does_not_name_an_identity_provider() -> None:
    assert detect_identity_providers(
        "<h1>Welcome</h1><p>Sign in below, or open a Google Doc about SAML.</p>"
    ) == []


# ---------------------------------------------------------------------------
# sensitive data, redacted
# ---------------------------------------------------------------------------


def test_customer_records_are_counted_and_never_stored_in_the_clear() -> None:
    dashboard = (
        "<table>"
        "<tr><td>Ani</td><td>6281100000101</td><td>Rp 788,421</td>"
        "<td>28-09-2026 23:49:57</td></tr>"
        "<tr><td>Budi</td><td>6281100000102</td><td>Rp 362,511</td>"
        "<td>28-09-2026 23:49:43</td></tr>"
        "<tr><td>Citra</td><td>6281100000103</td><td>Rp 2,461,157</td></tr>"
        "<tr><td>Dewi</td><td>6281100000104</td><td>Rp 1,172,324</td></tr>"
        "<tr><td>Eko</td><td>6281100000105</td><td>Rp 124,199</td></tr>"
        "</table><footer>support@example.co.id</footer>"
    )
    scan = scan_sensitive_data(
        dashboard, control_body="<footer>support@example.co.id</footer>"
    )
    labels = {category.label: category for category in scan.categories}

    assert scan.significant is True
    assert labels["telephone numbers"].count == 5
    assert labels["monetary amounts"].count == 5
    # The footer address is on the anonymous page too, so it is not exposure.
    assert "email addresses" not in labels
    # A timestamp is twelve digits with separators, like an E.164 number.
    assert all("2026" not in sample for sample in labels["telephone numbers"].samples)
    # Nothing recognisable is kept.
    for category in scan.categories:
        for sample in category.samples:
            assert "*" in sample or "<" in sample
            assert "6281100000101" not in sample


def test_a_contact_address_in_a_footer_is_not_a_data_exposure() -> None:
    scan = scan_sensitive_data(
        "<p>Call us on +62 21 555 0100 or email hello@example.com.</p>"
    )
    assert scan.significant is False


def test_redaction_keeps_the_shape_and_drops_the_value() -> None:
    assert redact("6281100000101") == "62********01"
    assert redact("ab") == "**"


# ---------------------------------------------------------------------------
# the scope contract around account creation
# ---------------------------------------------------------------------------


def test_account_creation_requires_a_mailbox_in_the_scope_file(tmp_path) -> None:
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "program: Example\n"
        "authorization:\n"
        f"  authorized_by: {VALID_AUTH['authorized_by']}\n"
        f"  date: '{VALID_AUTH['date']}'\n"
        f"  attestation: {VALID_AUTH['attestation']}\n"
        "in_scope:\n  - example.com\n"
        "permissions:\n  account_creation: true\n",
        encoding="utf-8",
    )

    with pytest.raises(ScopeParseError, match="test_account_email"):
        load_scope(scope_file)


def test_a_scope_grants_account_creation_explicitly_or_not_at_all() -> None:
    default = ScopeGuard(make_scope())
    assert default.permits("account_creation") is False

    granted = ScopeGuard(
        make_scope(
            permissions={
                "account_creation": True,
                "test_account_email": "researcher@example.com",
            }
        )
    )
    assert granted.permits("account_creation") is True


def test_the_verifier_refuses_to_register_without_a_mailbox() -> None:
    with pytest.raises(AccountCreationRefused):
        RegistrationVerifier(object(), allow_account_creation=True, probe_email=None)


# ---------------------------------------------------------------------------
# against the local target
# ---------------------------------------------------------------------------


def client_for(target, **overrides) -> ScopedHttpClient:
    scope = make_scope(in_scope=[target.host], out_of_scope=[], **overrides)
    return ScopedHttpClient(ScopeGuard(scope), settings=fast_settings())


async def test_an_sso_only_portal_with_open_signup_is_reported_probable(target) -> None:
    http = client_for(target)
    verifier = RegistrationVerifier(http, attempts=2, required=2)

    verdict = await verifier.verify(target.base_url)

    assert verdict.tier is FindingTier.PROBABLE
    assert verdict.severity is Severity.HIGH
    assert verdict.registration_url == f"{target.base_url}/register"
    assert "Microsoft Entra ID (Azure AD)" in verdict.providers
    assert verdict.protected_area is not None
    assert verdict.protected_area.url == f"{target.base_url}/dashboard"
    assert set(verdict.signals) >= {
        "local_registration_form",
        "identity_provider_present",
        "protected_area_refuses_anonymous",
        "reproduced",
    }
    # Nothing was written to the target without permission.
    assert verdict.created_account is None
    assert target.accounts == []
    assert "Registering was not attempted" in verdict.reason
    await http.aclose()


async def test_registering_confirms_the_bypass_and_names_the_account(target) -> None:
    http = client_for(target)
    verifier = RegistrationVerifier(
        http,
        attempts=2,
        required=2,
        allow_account_creation=True,
        probe_email="researcher@example.com",
    )

    verdict = await verifier.verify(target.base_url)

    assert verdict.tier is FindingTier.CONFIRMED
    assert verdict.severity is Severity.CRITICAL
    assert verdict.session_confirmed is True
    assert "session_crossed_boundary" in verdict.signals
    assert verdict.cleanup_required is True

    # Exactly one account, under the mailbox the scope named, and obviously ours.
    assert len(target.accounts) == 1
    created = target.accounts[0]
    assert verdict.created_account == created["email"]
    assert created["email"].startswith("researcher+reconx-")
    assert created["email"].endswith("@example.com")
    assert created["name"] == "ReconX Authorized Test"
    assert verdict.created_account in verdict.reason

    # And it saw what the report is actually about.
    assert verdict.data_scan is not None
    assert verdict.data_scan.significant is True
    assert "sensitive_data_exposed" in verdict.signals
    await http.aclose()


async def test_the_registered_session_does_not_leak_into_the_rest_of_the_scan(
    target,
) -> None:
    http = client_for(target)
    verifier = RegistrationVerifier(
        http,
        attempts=2,
        required=2,
        allow_account_creation=True,
        probe_email="researcher@example.com",
    )

    await verifier.verify(target.base_url)

    # The next request the scan makes must be anonymous again, or every later
    # finding would be "reachable" only because we logged in.
    assert http.cookies == {}
    after = await http.get(f"{target.base_url}/dashboard", follow_redirects=False)
    assert after.status == 302
    assert after.header("location") == "/login"
    await http.aclose()


async def test_a_consumer_signup_with_no_identity_provider_is_discarded(target) -> None:
    http = client_for(target)
    verifier = RegistrationVerifier(
        http,
        attempts=2,
        required=2,
        registration_paths=("/shop/signup",),
        login_paths=("/shop/login",),
        protected_paths=("/shop/account",),
    )

    verdict = await verifier.verify(target.base_url)

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.registration_url == f"{target.base_url}/shop/signup"
    assert "no identity provider" in verdict.reason
    await http.aclose()


async def test_a_register_page_that_only_hands_off_is_discarded(target) -> None:
    http = client_for(target)
    verifier = RegistrationVerifier(
        http,
        attempts=2,
        required=2,
        registration_paths=("/sso/register",),
        login_paths=("/sso/login",),
        protected_paths=("/sso/dashboard",),
    )

    verdict = await verifier.verify(target.base_url)

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.registration_url is None
    assert "different origin" in verdict.reason
    await http.aclose()


async def test_registration_behind_an_invitation_is_discarded(target) -> None:
    http = client_for(target)
    verifier = RegistrationVerifier(
        http,
        attempts=2,
        required=2,
        registration_paths=("/invite/register",),
        login_paths=("/invite/login",),
        protected_paths=("/invite/dashboard",),
    )

    verdict = await verifier.verify(target.base_url)

    assert verdict.tier is FindingTier.DISCARDED
    assert "invitation" in verdict.reason
    assert "invitation_code" in verdict.reason
    await http.aclose()


async def test_sso_alongside_a_local_login_needs_a_human(target) -> None:
    http = client_for(target)
    verifier = RegistrationVerifier(
        http,
        attempts=2,
        required=2,
        registration_paths=("/both/register",),
        login_paths=("/both/login",),
        protected_paths=("/both/dashboard",),
    )

    verdict = await verifier.verify(target.base_url)

    assert verdict.tier is FindingTier.NEEDS_REVIEW
    assert "local password form" in verdict.reason
    await http.aclose()


# ---------------------------------------------------------------------------
# through the pipeline
# ---------------------------------------------------------------------------


async def make_context(
    session: AsyncSession, program: Program, target, *, permissions: dict | None = None
) -> StageContext:
    scope = make_scope(
        in_scope=[target.host],
        out_of_scope=[],
        **({"permissions": permissions} if permissions else {}),
    )
    guard = ScopeGuard(scope)
    settings = fast_settings()
    await upsert_asset(
        session,
        program.id,
        target.host,
        is_live=True,
        scheme="http",
        port=target.port,
        http_status=200,
    )
    await session.flush()
    return StageContext(
        program_id=program.id,
        scan_run_id=1,
        scope=scope,
        guard=guard,
        http=ScopedHttpClient(guard, settings=settings),
        dns=ScopedResolver(guard, settings=settings),
        sources=SourceClient(settings=settings),
        session=session,
        settings=settings,
        use_external_tools=False,
    )


async def findings_for(session: AsyncSession, program: Program) -> dict[str, Finding]:
    rows = await session.execute(select(Finding).where(Finding.program_id == program.id))
    return {finding.vuln_class: finding for finding in rows.scalars().all()}


async def test_the_stage_reports_the_bypass_and_the_exposure_separately(
    db_session: AsyncSession, program: Program, target
) -> None:
    ctx = await make_context(
        db_session,
        program,
        target,
        permissions={
            "account_creation": True,
            "test_account_email": "researcher@example.com",
        },
    )
    stage = VulnStage(
        run_nuclei=False,
        check_sqli=False,
        check_xss=False,
        check_takeover=False,
        allow_account_creation=True,
    )

    result = await stage.run(ctx)
    await db_session.commit()

    found = await findings_for(db_session, program)
    bypass = found["auth_bypass"]
    assert bypass.tier is FindingTier.CONFIRMED
    assert bypass.severity is Severity.CRITICAL
    assert bypass.dedup_key == "auth_bypass::self_registration::/register"
    assert bypass.priority > 0
    assert target.host in bypass.affected_hosts
    assert bypass.recommendation and "deleted" in bypass.recommendation

    # Closing registration and stopping the page rendering records are two
    # different fixes, so they are two different findings.
    exposure = found["sensitive_data_exposure"]
    assert exposure.tier is FindingTier.CONFIRMED
    assert "telephone numbers" in (exposure.description or "")
    assert "6281100000101" not in (exposure.description or "")

    assert any("researcher+reconx-" in note for note in result.notes)
    assert result.items_out >= 2
    await ctx.http.aclose()
    await ctx.sources.aclose()


async def test_the_stage_will_not_register_without_the_scope_permission(
    db_session: AsyncSession, program: Program, target
) -> None:
    ctx = await make_context(db_session, program, target)
    stage = VulnStage(
        run_nuclei=False,
        check_sqli=False,
        check_xss=False,
        check_takeover=False,
        # Asked for on the command line, not granted in the scope file.
        allow_account_creation=True,
    )

    result = await stage.run(ctx)
    await db_session.commit()

    assert target.accounts == []
    assert any("does not grant permissions.account_creation" in n for n in result.notes)

    found = await findings_for(db_session, program)
    assert found["auth_bypass"].tier is FindingTier.PROBABLE
    assert "sensitive_data_exposure" not in found
    await ctx.http.aclose()
    await ctx.sources.aclose()
