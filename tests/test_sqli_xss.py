"""Verification tests for SQL injection and cross-site scripting.

These are the tests behind the central claim of the project. Each case is either
a real vulnerability that must be confirmed, or a deliberate trap that other
scanners report and this one must discard with a correct reason.
"""

from __future__ import annotations

import pytest

from reconx.config import Settings
from reconx.db.models import FindingTier
from reconx.net.http import ScopedHttpClient
from reconx.scope.guard import ScopeGuard
from reconx.verify.sqli import (
    SqliVerifier,
    find_error_signature,
    set_parameter,
)
from reconx.verify.xss import (
    ReflectionKind,
    XssVerifier,
    classify_reflection,
    resolve_chromium_path,
)
from tests.conftest import make_scope
from tests.fixtures.target_app import run_target_app


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


def browser_available() -> bool:
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        return False
    return resolve_chromium_path() is not None


needs_browser = pytest.mark.skipif(
    not browser_available(),
    reason="execution confirmation needs Playwright and a Chromium build",
)


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------


async def test_a_real_injection_is_confirmed_by_two_agreeing_oracles(target) -> None:
    """The bar for Confirmed is two independent oracles, each reproduced."""
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = SqliVerifier(http, attempts=3, required=3, enable_timing=False)
        verdict = await verifier.verify(target.url("/sqli?id=1"), "id")

    assert verdict.tier is FindingTier.CONFIRMED
    assert verdict.confidence >= 90
    assert set(verdict.agreeing) == {"boolean_differential", "error_signature"}
    assert verdict.dbms_hint == "MySQL"
    assert verdict.evidence, "a confirmed finding must carry evidence"


async def test_a_page_that_always_shows_a_sql_error_is_discarded(target) -> None:
    """The classic false positive: the error string was already on the page.

    /static-error carries MySQL error text in its template whatever you send. A
    scanner that matches on error strings reports it. The control request and the
    pre-existing check are what settle it.
    """
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = SqliVerifier(http, attempts=3, required=3, enable_timing=False)
        verdict = await verifier.verify(target.url("/static-error?id=1"), "id")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.agreeing == []
    assert "already present in the unmodified page" in verdict.reason


async def test_a_parameter_with_no_injectable_behaviour_is_discarded(target) -> None:
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = SqliVerifier(http, attempts=3, required=3, enable_timing=False)
        verdict = await verifier.verify(target.url("/?id=1"), "id")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.vulnerable is False


async def test_a_randomly_slow_endpoint_is_not_reported_as_time_based(target) -> None:
    """/jitter delays at random, which is what time-based detection mistakes.

    The timing oracle requires non-overlapping ranges and the magnitude the
    payload asked for, so random latency cannot satisfy it. Even if it somehow
    did, timing alone never reaches Confirmed.
    """
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = SqliVerifier(
            http, attempts=2, required=2, sleep_seconds=3, enable_timing=True
        )
        verdict = await verifier.verify(target.url("/jitter?id=1"), "id")

    assert verdict.tier is not FindingTier.CONFIRMED
    assert "time_differential" not in verdict.agreeing or verdict.tier is (
        FindingTier.NEEDS_REVIEW
    )


async def test_a_blocked_host_yields_needs_review_not_a_finding(target) -> None:
    """Results from a host that is refusing requests cannot be trusted."""
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = SqliVerifier(http, attempts=2, required=2, enable_timing=False)
        verdict = await verifier.verify(target.url("/waf?id=1"), "id")

    assert verdict.obstructed is True
    assert verdict.tier is FindingTier.NEEDS_REVIEW
    assert "trusted" in verdict.reason or "blocked" in verdict.reason


def test_set_parameter_replaces_and_adds() -> None:
    url = "https://x.example.com/i?id=1&p=2"
    assert "id=9" in set_parameter(url, "id", "9")
    assert "p=2" in set_parameter(url, "id", "9")
    assert "new=1" in set_parameter("https://x.example.com/i", "new", "1")


@pytest.mark.parametrize(
    ("label", "body", "matched"),
    [
        ("mysql", b"You have an error in your SQL syntax; check the manual", True),
        ("postgres", b"ERROR: unterminated quoted string at or near", True),
        ("oracle", b"ORA-01756: quoted string not properly terminated", True),
        ("mssql", b"Unclosed quotation mark after the character string", True),
        ("sqlite", b"no such column: username", True),
        # These must not match, or every site becomes a finding.
        ("generic error text", b"<p>An error occurred. Please try again later.</p>", False),
        ("sql tutorial page", b"<h1>Learn SQL</h1><p>A guide to databases</p>", False),
        ("the word error", b"error", False),
        ("empty", b"", False),
    ],
)
def test_error_signatures_are_specific_to_database_drivers(
    label: str, body: bytes, matched: bool
) -> None:
    assert (find_error_signature(body) is not None) is matched, label


# ---------------------------------------------------------------------------
# cross-site scripting
# ---------------------------------------------------------------------------


@needs_browser
async def test_html_body_xss_is_confirmed_by_real_execution(target) -> None:
    """Confirmed means the payload ran in a browser, not that input came back."""
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = XssVerifier(http, attempts=3, required=3, headless_confirm=True)
        verdict = await verifier.verify(target.url("/xss?q=test"), "q")

    assert verdict.tier is FindingTier.CONFIRMED
    assert verdict.confidence >= 90
    assert verdict.dom_confirmed is True
    assert verdict.site is not None
    assert verdict.site.kind is ReflectionKind.HTML_BODY
    assert "executed in a real browser" in verdict.reason


@needs_browser
async def test_attribute_xss_is_confirmed_when_the_quote_survives(target) -> None:
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = XssVerifier(http, attempts=3, required=3, headless_confirm=True)
        verdict = await verifier.verify(target.url("/attr-xss?q=test"), "q")

    assert verdict.tier is FindingTier.CONFIRMED
    assert verdict.dom_confirmed is True
    assert verdict.site.kind is ReflectionKind.ATTRIBUTE_DOUBLE


async def test_encoded_reflection_is_discarded_as_inert(target) -> None:
    """The single biggest source of XSS noise: reflected but harmless."""
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = XssVerifier(http, attempts=3, required=3, headless_confirm=False)
        verdict = await verifier.verify(target.url("/reflect?q=test"), "q")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.site.kind is ReflectionKind.HTML_BODY
    assert verdict.site.escapable is False
    assert "inert" in verdict.reason
    assert set(verdict.site.encoded_chars) == {"<", ">"}


async def test_attribute_reflection_with_an_encoded_quote_is_discarded(target) -> None:
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = XssVerifier(http, attempts=3, required=3, headless_confirm=False)
        verdict = await verifier.verify(target.url("/attr?q=test"), "q")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.site.kind is ReflectionKind.ATTRIBUTE_DOUBLE
    assert verdict.site.encoded_chars == ('"',)
    assert "inert" in verdict.reason


async def test_a_parameter_that_is_not_reflected_is_discarded(target) -> None:
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = XssVerifier(http, attempts=2, required=2, headless_confirm=False)
        verdict = await verifier.verify(target.url("/?q=test"), "q")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.site.kind is ReflectionKind.NONE
    assert "not reflected" in verdict.reason


async def test_without_a_browser_a_real_xss_is_probable_not_discarded(target) -> None:
    """A missing browser must downgrade confidence, never lose the finding."""
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = XssVerifier(http, attempts=3, required=3, headless_confirm=False)
        verdict = await verifier.verify(target.url("/xss?q=test"), "q")

    assert verdict.tier is FindingTier.PROBABLE
    assert verdict.vulnerable is True
    assert verdict.site.escapable is True
    assert "verify by hand" in verdict.reason


async def test_a_blocked_host_is_not_reported_as_xss(target) -> None:
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as http:
        verifier = XssVerifier(http, attempts=2, required=2, headless_confirm=False)
        verdict = await verifier.verify(target.url("/waf?q=test"), "q")

    assert verdict.obstructed is True
    assert verdict.tier is FindingTier.NEEDS_REVIEW


# ---------------------------------------------------------------------------
# reflection context classification
# ---------------------------------------------------------------------------

CANARY = "rxCANARYzz"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (f"<html><body><h1>Results for {CANARY}</h1></body></html>", ReflectionKind.HTML_BODY),
        (f'<input type="text" value="{CANARY}">', ReflectionKind.ATTRIBUTE_DOUBLE),
        (f"<input value='{CANARY}'>", ReflectionKind.ATTRIBUTE_SINGLE),
        (f"<input value={CANARY}>", ReflectionKind.ATTRIBUTE_UNQUOTED),
        (f'<script>var q = "{CANARY}";</script>', ReflectionKind.SCRIPT_STRING_DOUBLE),
        (f"<script>var q = '{CANARY}';</script>", ReflectionKind.SCRIPT_STRING_SINGLE),
        (f"<script>var q = {CANARY};</script>", ReflectionKind.SCRIPT_BLOCK),
        (f"<!-- search term: {CANARY} -->", ReflectionKind.HTML_COMMENT),
        (f"<style>.x{{color:{CANARY}}}</style>", ReflectionKind.STYLE_BLOCK),
        ("<html><body>nothing here</body></html>", ReflectionKind.NONE),
    ],
)
def test_reflection_context_is_classified(body: str, expected: ReflectionKind) -> None:
    """The context decides which characters matter, so it has to be right."""
    assert classify_reflection(body, CANARY).kind is expected


def test_each_context_knows_what_it_takes_to_escape() -> None:
    body_site = classify_reflection(f"<p>{CANARY}</p>", CANARY)
    assert set(body_site.required_chars) == {"<", ">"}

    attribute_site = classify_reflection(f'<input value="{CANARY}">', CANARY)
    assert set(attribute_site.required_chars) == {'"'}

    comment_site = classify_reflection(f"<!-- {CANARY} -->", CANARY)
    assert "-" in comment_site.required_chars


def test_a_site_with_no_surviving_characters_is_not_escapable() -> None:
    site = classify_reflection(f"<p>{CANARY}</p>", CANARY)
    site.surviving_chars = ()
    site.encoded_chars = ("<", ">")
    assert site.escapable is False

    site.surviving_chars = ("<",)  # only one of the two needed
    assert site.escapable is False

    site.surviving_chars = ("<", ">")
    assert site.escapable is True


def test_chromium_resolution_returns_none_rather_than_guessing(monkeypatch) -> None:
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/nonexistent-path-for-this-test")
    monkeypatch.setattr("shutil.which", lambda _name: None)
    import os

    real_isfile = os.path.isfile
    monkeypatch.setattr(
        "os.path.isfile",
        lambda path: False if "chrom" in str(path) or "pw-browsers" in str(path)
        else real_isfile(path),
    )
    assert resolve_chromium_path() is None
