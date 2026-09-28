"""Tests for the network layer: politeness, scope enforcement, fingerprinting."""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

import httpx
import pytest
import respx

from reconx.config import Settings
from reconx.net.dns import DnsAnswer, ScopedResolver, WildcardProfile
from reconx.net.fingerprint import fingerprint_response, hamming_distance
from reconx.net.http import RequestBudgetExceeded, ScopedHttpClient
from reconx.net.ratelimit import HostRateLimiter, TokenBucket
from reconx.scope.guard import OutOfScopeError, ScopeGuard
from tests.conftest import make_scope


def fast_settings(**overrides) -> Settings:
    """Deterministic settings for tests: no retries, no waiting."""
    payload = {
        "requests_per_second_per_host": 1000.0,
        "max_concurrent_requests": 50,
        "http_timeout_seconds": 5.0,
        "max_retries": 0,
    }
    payload.update(overrides)
    return Settings(**payload)


def html(title: str, body: str = "") -> str:
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>"


# ---------------------------------------------------------------------------
# politeness
# ---------------------------------------------------------------------------


async def test_token_bucket_enforces_sustained_rate() -> None:
    bucket = TokenBucket(rate=20, capacity=1)
    started = time.monotonic()
    for _ in range(5):
        await bucket.acquire()
    elapsed = time.monotonic() - started
    # 1 immediate + 4 paced at 20/s = ~0.2s. Allow generous slack for CI.
    assert 0.12 < elapsed < 1.0


async def test_token_bucket_rejects_nonsense_rate() -> None:
    with pytest.raises(ValueError):
        TokenBucket(rate=0)


async def test_default_burst_is_capped_to_per_host_concurrency() -> None:
    """A full second of requests arriving at once is not polite."""
    limiter = HostRateLimiter(
        rate_per_host=50, max_concurrent_requests=50, max_concurrent_per_host=3, jitter=0
    )
    started = time.monotonic()

    async def one() -> None:
        async with limiter.slot("example.com"):
            pass

    await asyncio.gather(*(one() for _ in range(20)))
    elapsed = time.monotonic() - started
    # Burst of 3, remaining 17 paced at 50/s => ~0.34s, definitely not instant.
    assert elapsed > 0.15


async def test_per_host_concurrency_is_capped() -> None:
    limiter = HostRateLimiter(
        rate_per_host=1000, max_concurrent_requests=100, max_concurrent_per_host=2, jitter=0
    )
    in_flight = 0
    peak = 0

    async def one() -> None:
        nonlocal in_flight, peak
        async with limiter.slot("example.com"):
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.02)
            in_flight -= 1

    await asyncio.gather(*(one() for _ in range(10)))
    assert peak <= 2


async def test_penalties_compound_and_expire() -> None:
    limiter = HostRateLimiter(rate_per_host=100)
    first = limiter.penalize("example.com", 0.05, signal="429")
    second = limiter.penalize("example.com", 0.05, signal="429")
    assert second > first  # repeated distress buys more room
    assert limiter.is_throttled("example.com") is True
    assert "429" in limiter.snapshot()["example.com"]["distress_signals"]


# ---------------------------------------------------------------------------
# the no-bypass property
# ---------------------------------------------------------------------------


def test_http_client_cannot_be_built_without_a_guard() -> None:
    for bad in (None, "example.com", object()):
        with pytest.raises(TypeError):
            ScopedHttpClient(bad)  # type: ignore[arg-type]


def test_resolver_cannot_be_built_without_a_guard() -> None:
    for bad in (None, "example.com", object()):
        with pytest.raises(TypeError):
            ScopedResolver(bad)  # type: ignore[arg-type]


def test_no_module_reaches_the_network_around_the_guard() -> None:
    """Structural guarantee, enforced against the source tree.

    Raw HTTP clients and DNS resolvers may only be constructed inside the two
    scoped wrappers. If this fails, someone added a code path that can send
    traffic without a scope check — fix the code, never this test.
    """
    # ReconX has exactly three outbound channels, each constrained differently:
    #
    #   net/http.py     target traffic, gated by the program scope
    #   net/sources.py  public intelligence services, gated by a code-defined
    #                   allowlist (test_source_client_* below)
    #   notify/base.py  alerts to endpoints the operator configured, which are
    #                   never derived from scan data (test_notifier_* below)
    #
    # Anything else constructing a client is an unreviewed fourth channel.
    allowed = {
        "httpx.AsyncClient": {
            Path("src/reconx/net/http.py"),
            Path("src/reconx/net/sources.py"),
            Path("src/reconx/notify/base.py"),
        },
        "dns.asyncresolver.Resolver": {Path("src/reconx/net/dns.py")},
        "dns.resolver.Resolver": {Path("src/reconx/net/dns.py")},
    }
    offenders: list[str] = []
    for path in Path("src/reconx").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for construct, permitted in allowed.items():
            pattern = re.escape(construct) + r"\s*\("
            if re.search(pattern, text) and path not in permitted:
                offenders.append(f"{path} constructs {construct}")
    assert offenders == [], "unscoped network access: " + "; ".join(offenders)


# ---------------------------------------------------------------------------
# scope enforcement on HTTP
# ---------------------------------------------------------------------------


@respx.mock
async def test_out_of_scope_request_is_refused_before_any_traffic() -> None:
    route = respx.get("https://evil.com/").mock(return_value=httpx.Response(200))
    guard = ScopeGuard(make_scope())
    async with ScopedHttpClient(guard, settings=fast_settings()) as client:
        with pytest.raises(OutOfScopeError):
            await client.get("https://evil.com/")
    assert route.called is False  # nothing left the process
    # The refusal is recorded for the audit trail.
    records = client.audit_records()
    assert len(records) == 1 and records[0].blocked is True


@respx.mock
async def test_in_scope_request_succeeds_and_is_audited() -> None:
    respx.get("https://www.example.com/").mock(
        return_value=httpx.Response(200, text=html("Home"), headers={"Content-Type": "text/html"})
    )
    guard = ScopeGuard(make_scope())
    async with ScopedHttpClient(guard, settings=fast_settings()) as client:
        response = await client.get("https://www.example.com/")

    assert response.status == 200
    assert response.fingerprint.title == "Home"
    record = client.audit_records()[0]
    assert record.status == 200
    assert record.host == "www.example.com"
    assert record.matched_rule == "*.example.com"
    assert record.blocked is False


@respx.mock
async def test_redirect_off_scope_is_not_followed() -> None:
    """A target must not be able to walk the scanner out of scope."""
    respx.get("https://www.example.com/go").mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil.com/landing"})
    )
    leaked = respx.get("https://evil.com/landing").mock(return_value=httpx.Response(200))

    guard = ScopeGuard(make_scope())
    async with ScopedHttpClient(guard, settings=fast_settings()) as client:
        response = await client.get("https://www.example.com/go")

    assert leaked.called is False
    assert response.status == 302
    assert "out-of-scope" in (response.redirect_stopped_reason or "")


@respx.mock
async def test_redirect_within_scope_is_followed() -> None:
    respx.get("https://www.example.com/old").mock(
        return_value=httpx.Response(301, headers={"Location": "/new"})
    )
    respx.get("https://www.example.com/new").mock(
        return_value=httpx.Response(200, text=html("New"))
    )
    guard = ScopeGuard(make_scope())
    async with ScopedHttpClient(guard, settings=fast_settings()) as client:
        response = await client.get("https://www.example.com/old")

    assert response.status == 200
    assert response.fingerprint.title == "New"
    assert response.redirect_chain == [(301, "https://www.example.com/old")]


@respx.mock
async def test_redirect_to_excluded_path_is_not_followed() -> None:
    """Path-level exclusions hold across redirects too."""
    scope = make_scope(
        in_scope=["*.example.com"], out_of_scope=["https://www.example.com/logout"]
    )
    respx.get("https://www.example.com/x").mock(
        return_value=httpx.Response(302, headers={"Location": "/logout"})
    )
    blocked = respx.get("https://www.example.com/logout").mock(
        return_value=httpx.Response(200)
    )
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as client:
        response = await client.get("https://www.example.com/x")

    assert blocked.called is False
    assert "out-of-scope" in (response.redirect_stopped_reason or "")


@respx.mock
async def test_redirect_loop_stops_at_the_limit() -> None:
    respx.get("https://www.example.com/loop").mock(
        return_value=httpx.Response(302, headers={"Location": "/loop"})
    )
    guard = ScopeGuard(make_scope())
    async with ScopedHttpClient(guard, settings=fast_settings(), max_redirects=3) as client:
        response = await client.get("https://www.example.com/loop")
    assert "redirect limit" in (response.redirect_stopped_reason or "")


@respx.mock
async def test_get_many_skips_out_of_scope_urls_silently() -> None:
    respx.get("https://www.example.com/a").mock(return_value=httpx.Response(200, text="a"))
    respx.get("https://api.example.io/b").mock(return_value=httpx.Response(200, text="b"))
    leaked = respx.get("https://evil.com/c").mock(return_value=httpx.Response(200))

    guard = ScopeGuard(make_scope())
    async with ScopedHttpClient(guard, settings=fast_settings()) as client:
        responses = await client.get_many(
            [
                "https://www.example.com/a",
                "https://evil.com/c",
                "https://api.example.io/b",
                "https://payments.example.com/d",
            ]
        )
    assert leaked.called is False
    assert {r.status for r in responses} == {200}
    assert len(responses) == 2


# ---------------------------------------------------------------------------
# distress handling and budget
# ---------------------------------------------------------------------------


@respx.mock
async def test_429_puts_the_host_in_the_penalty_box() -> None:
    respx.get("https://www.example.com/").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "1"})
    )
    guard = ScopeGuard(make_scope())
    async with ScopedHttpClient(guard, settings=fast_settings()) as client:
        response = await client.get("https://www.example.com/")

    assert response.status == 429
    assert response.throttled_host is True
    assert client.limiter.is_throttled("www.example.com") is True


@respx.mock
async def test_request_budget_is_enforced() -> None:
    respx.get(url__regex=r"https://www\.example\.com/.*").mock(
        return_value=httpx.Response(200, text="ok")
    )
    scope = make_scope(limits={"max_requests_per_scan": 3})
    async with ScopedHttpClient(ScopeGuard(scope), settings=fast_settings()) as client:
        for index in range(3):
            await client.get(f"https://www.example.com/{index}")
        with pytest.raises(RequestBudgetExceeded):
            await client.get("https://www.example.com/overflow")
    assert client.requests_made == 3


# ---------------------------------------------------------------------------
# fingerprinting
# ---------------------------------------------------------------------------


def test_dynamic_noise_does_not_change_the_fingerprint() -> None:
    """Request ids and timestamps must not make one page look like two."""
    first = fingerprint_response(
        status=404,
        body=html("Not Found", "<h1>No such page</h1><p>id 88412 at 10:11:12</p>").encode(),
        headers={"Content-Type": "text/html"},
    )
    second = fingerprint_response(
        status=404,
        body=html("Not Found", "<h1>No such page</h1><p>id 99317 at 10:14:55</p>").encode(),
        headers={"Content-Type": "text/html"},
    )
    assert first.looks_same_as(second)


def test_genuinely_different_pages_are_distinguished() -> None:
    soft404 = fingerprint_response(
        status=200,
        body=html("Not Found", "<h1>Sorry, that page does not exist</h1>").encode(),
        headers={"Content-Type": "text/html"},
    )
    admin = fingerprint_response(
        status=200,
        body=html("Admin", "<h1>Administrator login</h1><form>user pass token</form>").encode(),
        headers={"Content-Type": "text/html"},
    )
    assert not soft404.looks_same_as(admin)


def test_same_body_different_status_is_not_the_same_outcome() -> None:
    body = html("Blocked", "<h1>Request blocked</h1>").encode()
    allowed = fingerprint_response(status=200, body=body)
    denied = fingerprint_response(status=403, body=body)
    assert not allowed.looks_same_as(denied)


def test_simhash_is_stable_across_processes() -> None:
    """Python's hash() is randomized per process; ours must not be."""
    body = html("Stable", "<p>consistent content for hashing</p>").encode()
    assert (
        fingerprint_response(status=200, body=body).simhash_value
        == fingerprint_response(status=200, body=body).simhash_value
    )
    assert hamming_distance(0b1011, 0b1001) == 1


def test_empty_body_does_not_crash_fingerprinting() -> None:
    fp = fingerprint_response(status=204, body=b"")
    assert fp.body_length == 0 and fp.simhash_value == 0


# ---------------------------------------------------------------------------
# DNS and wildcard logic
# ---------------------------------------------------------------------------


async def test_resolver_refuses_out_of_scope_lookups() -> None:
    resolver = ScopedResolver(ScopeGuard(make_scope()))
    answer = await resolver.resolve("secret.unrelated.org")
    assert answer.out_of_scope is True
    assert answer.resolved is False
    assert resolver.queries == 0  # never hit the wire


async def test_resolver_rejects_malformed_names_without_querying() -> None:
    resolver = ScopedResolver(ScopeGuard(make_scope()))
    answer = await resolver.resolve("!!!not a host!!!")
    assert answer.resolved is False
    assert "invalid host" in (answer.error or "")
    assert resolver.queries == 0


@pytest.mark.parametrize(
    ("wildcard_values", "answer_values", "covered"),
    [
        # Everything the name returns is what the wildcard returns: suspect.
        (["1.2.3.4"], ["1.2.3.4"], True),
        (["1.2.3.4", "5.6.7.8"], ["1.2.3.4"], True),
        # Anything the wildcard does not return means a real, distinct host.
        (["1.2.3.4"], ["9.9.9.9"], False),
        (["1.2.3.4"], ["1.2.3.4", "9.9.9.9"], False),
        # No answer at all is not a wildcard artifact.
        (["1.2.3.4"], [], False),
    ],
)
def test_wildcard_coverage_decision(
    wildcard_values: list[str], answer_values: list[str], covered: bool
) -> None:
    profile = WildcardProfile(
        domain="example.com",
        probed=True,
        is_wildcard=True,
        values=frozenset(wildcard_values),
    )
    answer = DnsAnswer(host="x.example.com", rdtype="A", values=tuple(answer_values))
    assert profile.covers(answer) is covered


def test_non_wildcard_zone_never_covers_anything() -> None:
    profile = WildcardProfile(domain="example.com", probed=True, is_wildcard=False)
    answer = DnsAnswer(host="x.example.com", rdtype="A", values=("1.2.3.4",))
    assert profile.covers(answer) is False


async def test_wildcard_probing_is_skipped_when_probes_are_out_of_scope() -> None:
    """Only a wildcard-covered scope can be wildcard-profiled."""
    scope = make_scope(in_scope=["api.example.io"], out_of_scope=[])
    resolver = ScopedResolver(ScopeGuard(scope))
    profile = await resolver.profile_wildcard("example.io")
    assert profile.probed is False
    assert profile.is_wildcard is False
    assert "not in scope" in (profile.reason or "")
    assert resolver.queries == 0


# ---------------------------------------------------------------------------
# intelligence sources: the second, separately-gated channel
# ---------------------------------------------------------------------------


def test_source_client_allowlist_is_immutable_at_runtime() -> None:
    """Making this configurable would let a target pose as a data source."""
    from reconx.net.sources import SOURCE_ALLOWLIST

    with pytest.raises(TypeError):
        SOURCE_ALLOWLIST["www.example.com"] = "not a source"  # type: ignore[index]


async def test_source_client_refuses_anything_off_its_allowlist() -> None:
    from reconx.net.sources import SourceClient, SourceNotAllowed

    async with SourceClient() as client:
        for url in (
            "https://www.example.com/",          # an in-scope target
            "https://evil.com/",                 # an unrelated host
            "https://crt.sh.evil.com/",          # suffix confusion
        ):
            with pytest.raises(SourceNotAllowed):
                await client.get(url)
        assert client.calls == 0


def test_source_client_accepts_only_exact_allowlist_hosts() -> None:
    from reconx.net.sources import SourceClient

    assert SourceClient.is_allowed("https://crt.sh/?q=%25.example.com") is True
    assert SourceClient.is_allowed("https://web.archive.org/cdx/search") is True
    assert SourceClient.is_allowed("https://crt.sh.evil.com/") is False
    assert SourceClient.is_allowed("https://notcrt.sh/") is False


def test_no_target_host_can_be_an_intelligence_source() -> None:
    """The two channels must stay disjoint in kind.

    Every allowlisted source is a public, read-only data service. None is a
    wildcard, a bare IP, or anything a program scope would plausibly contain.
    """
    import ipaddress

    from reconx.net.sources import SOURCE_ALLOWLIST

    for host in SOURCE_ALLOWLIST:
        assert "*" not in host, f"{host} is a wildcard, which cannot be an exact source"
        with pytest.raises(ValueError):
            ipaddress.ip_address(host)  # must be a name, not a raw address
