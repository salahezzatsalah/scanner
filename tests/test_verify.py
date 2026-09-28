"""Tests for the verification layer."""

from __future__ import annotations

import httpx
import pytest
import respx

from reconx.config import Settings
from reconx.net.fingerprint import fingerprint_response
from reconx.net.http import ScopedHttpClient
from reconx.scope.guard import ScopeGuard
from reconx.verify.baseline import BaselineCollector, DirectoryBaseline, _normalize_directory
from reconx.verify.waf import WafState, classify_response, looks_like_challenge
from tests.conftest import make_scope

HTML = {"Content-Type": "text/html"}


def fast_settings(**overrides) -> Settings:
    payload = {
        "requests_per_second_per_host": 500.0,
        "http_timeout_seconds": 5.0,
        "max_retries": 0,
        "soft404_probe_count": 3,
    }
    payload.update(overrides)
    return Settings(**payload)


# ---------------------------------------------------------------------------
# WAF classification
# ---------------------------------------------------------------------------


def test_a_clean_response_is_left_alone() -> None:
    verdict = classify_response(
        status=200,
        headers={"Server": "nginx"},
        body=b"<html><title>Shop</title><body>Browse our catalogue</body></html>",
    )
    assert verdict.state is WafState.CLEAN
    assert verdict.obstructed is False


@pytest.mark.parametrize(
    ("label", "status", "headers", "body", "expected"),
    [
        (
            "cloudflare block",
            403,
            {"CF-Ray": "abc123", "Server": "cloudflare"},
            b"<html><title>Attention Required! | Cloudflare</title></html>",
            WafState.BLOCKED,
        ),
        (
            "cloudflare interstitial",
            503,
            {"CF-Ray": "abc123"},
            b"Checking your browser before accessing the site",
            WafState.CHALLENGED,
        ),
        (
            "imperva",
            403,
            {},
            b"<html><body>Incapsula incident ID: 0123-456</body></html>",
            WafState.BLOCKED,
        ),
        ("explicit throttle", 429, {"Retry-After": "60"}, b"slow down", WafState.RATE_LIMITED),
        ("captcha", 200, {}, b'<div class="g-recaptcha"></div>', WafState.CHALLENGED),
        ("origin down", 502, {}, b"Bad Gateway", WafState.UNAVAILABLE),
        (
            "f5",
            403,
            {},
            b"The requested URL was rejected. Please consult with your administrator.",
            WafState.BLOCKED,
        ),
    ],
)
def test_obstruction_is_classified(
    label: str, status: int, headers: dict, body: bytes, expected: WafState
) -> None:
    verdict = classify_response(status=status, headers=headers, body=body)
    assert verdict.state is expected, label
    assert verdict.obstructed is True
    assert verdict.should_back_off is True


def test_a_genuinely_protected_403_is_not_mistaken_for_a_block() -> None:
    """Misreading this loses a real finding, which is the expensive mistake.

    An access-controlled path returning 403 is something to report. A WAF block
    page returning 403 is not. Status alone cannot tell them apart, so the body
    has to.
    """
    body = (
        b"<html><title>403 Forbidden</title><body><h1>Forbidden</h1>"
        + b"<p>You do not have permission to access /admin/ on this server. "
        b"Contact the site administrator if you believe this is an error.</p>" * 20
        + b"</body></html>"
    )
    verdict = classify_response(status=403, headers={"Server": "Apache"}, body=body)
    assert verdict.state is WafState.CLEAN


def test_a_cdn_header_alone_does_not_mean_blocked() -> None:
    """Plenty of healthy sites sit behind a CDN."""
    verdict = classify_response(
        status=200,
        headers={"CF-Ray": "abc123", "Server": "cloudflare"},
        body=b"<html><title>Home</title><body>Welcome, please sign in.</body></html>",
    )
    assert verdict.state is WafState.CLEAN
    assert verdict.vendor == "cloudflare"


def test_retry_after_is_honoured_and_unparseable_values_are_generous() -> None:
    numeric = classify_response(status=429, headers={"Retry-After": "90"}, body=b"")
    assert numeric.retry_after_seconds == 90.0
    http_date = classify_response(
        status=429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, body=b""
    )
    assert http_date.retry_after_seconds == 30.0


def test_challenge_detection_on_raw_bodies() -> None:
    assert looks_like_challenge(b'<script src="/turnstile/v0/api.js"></script>') is True
    assert looks_like_challenge(b"<html><body>ordinary page</body></html>") is False


# ---------------------------------------------------------------------------
# baseline bookkeeping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/", "/"),
        ("/admin", "/"),
        ("/admin/", "/admin/"),
        ("/a/b/c.php", "/a/b/"),
        ("api/v1/users", "/api/v1/"),
    ],
)
def test_directory_normalization(raw: str, expected: str) -> None:
    assert _normalize_directory(raw) == expected


def test_an_unlearned_baseline_never_filters_anything() -> None:
    """Absence of a baseline must not be treated as a match."""
    baseline = DirectoryBaseline(host="x.example.com", directory="/")
    fingerprint = fingerprint_response(status=200, body=b"anything", headers=HTML)
    assert baseline.learned is False
    assert baseline.matches(fingerprint) is False


def test_an_inconsistent_baseline_refuses_to_filter() -> None:
    """If missing paths return unrelated pages, there is nothing to compare to."""
    baseline = DirectoryBaseline(
        host="x.example.com",
        directory="/",
        samples=[
            fingerprint_response(
                status=200, body=b"<html><title>A</title>totally different one</html>",
                headers=HTML,
            ),
            fingerprint_response(
                status=200,
                body=b"<html><title>B</title>nothing alike here at all whatsoever</html>",
                headers=HTML,
            ),
        ],
        statuses={200},
    )
    assert baseline.consistent is False
    probe = fingerprint_response(status=200, body=b"<html><title>A</title>x</html>", headers=HTML)
    assert baseline.matches(probe) is False


def test_soft_404_is_distinguished_from_a_real_404() -> None:
    soft = DirectoryBaseline(host="x", directory="/", statuses={200})
    hard = DirectoryBaseline(host="x", directory="/", statuses={404})
    mixed = DirectoryBaseline(host="x", directory="/", statuses={200, 404})
    assert soft.soft_404 is True
    assert hard.soft_404 is False
    assert mixed.soft_404 is False


# ---------------------------------------------------------------------------
# baseline learning over HTTP
# ---------------------------------------------------------------------------


@respx.mock
async def test_soft_404_host_filters_wordlist_hits() -> None:
    """The whole point: a 200 on a soft-404 host is not a discovery."""
    not_found = (
        "<html><head><title>Not found</title></head><body>"
        "<h1>We could not find that page</h1><p>Try the home page.</p>"
        "<span>ref 12345</span></body></html>"
    )
    real_page = (
        "<html><head><title>Admin</title></head><body><h1>Administrator sign in</h1>"
        "<form><input name=user><input name=pass></form></body></html>"
    )

    # Every probe path returns the not-found page with fresh noise.
    respx.get(url__regex=r"https://www\.example\.com/reconx-probe-.*").mock(
        side_effect=lambda request: httpx.Response(
            200, text=not_found.replace("12345", str(hash(str(request.url)) % 99999)),
            headers=HTML,
        )
    )
    respx.get("https://www.example.com/backup.sql").mock(
        return_value=httpx.Response(200, text=not_found.replace("12345", "77777"), headers=HTML)
    )
    respx.get("https://www.example.com/admin").mock(
        return_value=httpx.Response(200, text=real_page, headers=HTML)
    )

    guard = ScopeGuard(make_scope())
    async with ScopedHttpClient(guard, settings=fast_settings()) as client:
        collector = BaselineCollector(client, probes=3, persist=False)
        baseline = await collector.for_directory("https://www.example.com", "/")

        assert baseline.learned is True
        assert baseline.soft_404 is True
        assert baseline.consistent is True

        junk = await client.get("https://www.example.com/backup.sql")
        is_missing, reason = await collector.is_not_found(
            "https://www.example.com", "/backup.sql", junk.fingerprint
        )
        assert is_missing is True
        assert "soft-404" in (reason or "")

        real = await client.get("https://www.example.com/admin")
        is_missing_real, _ = await collector.is_not_found(
            "https://www.example.com", "/admin", real.fingerprint
        )
        assert is_missing_real is False

    assert collector.summary()["soft_404_directories"] == ["www.example.com/"]


@respx.mock
async def test_baselines_are_learned_per_directory() -> None:
    """404 handling routinely differs between / and /api/."""
    respx.get(url__regex=r"https://www\.example\.com/reconx-probe-.*").mock(
        return_value=httpx.Response(200, text="<html><title>Site 404</title></html>", headers=HTML)
    )
    respx.get(url__regex=r"https://www\.example\.com/api/reconx-probe-.*").mock(
        return_value=httpx.Response(
            404, json={"error": "not found", "code": 404},
        )
    )

    guard = ScopeGuard(make_scope())
    async with ScopedHttpClient(guard, settings=fast_settings()) as client:
        collector = BaselineCollector(client, probes=2, persist=False)
        root = await collector.for_directory("https://www.example.com", "/")
        api = await collector.for_directory("https://www.example.com", "/api/")

    assert root.soft_404 is True
    assert api.soft_404 is False
    assert api.statuses == {404}


@respx.mock
async def test_a_blocked_host_is_marked_unreliable_rather_than_baselined() -> None:
    """Learning a not-found page from WAF block pages would be worthless."""
    respx.get(url__regex=r"https://www\.example\.com/reconx-probe-.*").mock(
        return_value=httpx.Response(
            403,
            text="<html><title>Attention Required! | Cloudflare</title></html>",
            headers={"CF-Ray": "abc", **HTML},
        )
    )
    guard = ScopeGuard(make_scope())
    async with ScopedHttpClient(guard, settings=fast_settings()) as client:
        collector = BaselineCollector(client, probes=2, persist=False)
        baseline = await collector.for_directory("https://www.example.com", "/")

    assert baseline.learned is False
    assert baseline.obstructed is True
    assert "unreliable" in (baseline.note or "")
    assert collector.summary()["obstructed_directories"] == ["www.example.com/"]
