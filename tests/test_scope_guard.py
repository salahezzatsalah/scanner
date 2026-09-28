"""Tests for the scope chokepoint.

This is the most important test file in the project. If the guard is wrong,
ReconX sends traffic somewhere it was not authorized to. Treat a failure here
as a stop-the-line event, never as a test to relax.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from reconx.scope.guard import OutOfScopeError, ScopeGuard
from reconx.scope.model import (
    Scope,
    ScopeParseError,
    load_scope,
    normalize_host,
    parse_rule,
    split_host_port,
)
from tests.conftest import make_scope

# ---------------------------------------------------------------------------
# host normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("EXAMPLE.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  example.com  ", "example.com"),
        ("example.com:8443", "example.com"),
        ("[::1]:8080", "::1"),
        ("::1", "::1"),
        ("203.0.113.5", "203.0.113.5"),
        ("203.0.113.5:443", "203.0.113.5"),
        ("bücher.example.com", "xn--bcher-kva.example.com"),
    ],
)
def test_normalize_host(raw: str, expected: str) -> None:
    assert normalize_host(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", ".", ":443"])
def test_normalize_host_rejects_junk(raw: str) -> None:
    with pytest.raises(ScopeParseError):
        normalize_host(raw)


def test_split_host_port_handles_bare_ipv6() -> None:
    assert split_host_port("2001:db8::1") == ("2001:db8::1", None)
    assert split_host_port("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert split_host_port("example.com") == ("example.com", None)


# ---------------------------------------------------------------------------
# rule parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "kind"),
    [
        ("example.com", "exact"),
        ("*.example.com", "wildcard"),
        (".example.com", "wildcard"),
        ("203.0.113.5", "ip"),
        ("203.0.113.0/24", "cidr"),
        ("2001:db8::/32", "cidr"),
        ("https://example.com/api/*", "url"),
        (r"re:^prod-\d+\.example\.com$", "regex"),
    ],
)
def test_parse_rule_kinds(raw: str, kind: str) -> None:
    assert parse_rule(raw).kind == kind


@pytest.mark.parametrize(
    "raw",
    [
        "*.com",              # public suffix
        "*.co.uk",            # multi-label public suffix
        "*.github.io",        # private suffix: everyone's pages
        "*.s3.amazonaws.com", # private suffix: everyone's buckets
        "*.1.2.3.4",          # wildcard over an IP is meaningless
        "ex*mple.com",        # wildcard only valid as a leading label
        "re:[unclosed",       # broken regex
        "203.0.113.0/99",     # impossible prefix length
        "",
    ],
)
def test_parse_rule_rejects_dangerous_or_broken(raw: str) -> None:
    with pytest.raises(ScopeParseError):
        parse_rule(raw)


def test_url_rule_without_path_is_a_host_rule() -> None:
    assert parse_rule("https://example.com").kind == "exact"
    assert parse_rule("https://example.com/").kind == "exact"


# ---------------------------------------------------------------------------
# core decision logic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "allowed"),
    [
        # wildcard covers apex and any depth of subdomain
        ("example.com", True),
        ("www.example.com", True),
        ("a.b.c.d.example.com", True),
        # exact host
        ("api.example.io", True),
        ("other.example.io", False),
        # CIDR
        ("203.0.113.1", True),
        ("203.0.113.255", True),
        ("198.51.100.1", False),
        # out-of-scope overrides the in-scope wildcard
        ("payments.example.com", False),
        ("internal.example.com", False),
        ("db.internal.example.com", False),
        # suffix-confusion must not pass
        ("example.com.evil.com", False),
        ("notexample.com", False),
        ("evil-example.com", False),
        ("example.com.br", False),
        # nothing matches
        ("google.com", False),
    ],
)
def test_host_decisions(guard: ScopeGuard, host: str, allowed: bool) -> None:
    assert guard.decide_host(host).allowed is allowed


def test_out_of_scope_beats_in_scope_even_when_listed_first() -> None:
    """Order in the file must not change the outcome."""
    a = ScopeGuard(make_scope(in_scope=["*.example.com"], out_of_scope=["secret.example.com"]))
    b = ScopeGuard(make_scope(in_scope=["secret.example.com", "*.example.com"],
                              out_of_scope=["secret.example.com"]))
    assert a.decide_host("secret.example.com").allowed is False
    assert b.decide_host("secret.example.com").allowed is False


def test_absence_of_a_rule_is_never_permission() -> None:
    guard = ScopeGuard(make_scope(in_scope=["only.example.com"], out_of_scope=[]))
    assert guard.decide_host("anything-else.example.com").allowed is False
    assert guard.decide_host("example.com").allowed is False


def test_ip_target_does_not_match_a_domain_rule() -> None:
    guard = ScopeGuard(make_scope(in_scope=["*.example.com"], out_of_scope=[]))
    assert guard.decide_host("203.0.113.5").allowed is False


def test_unparseable_host_is_denied_not_crashed(guard: ScopeGuard) -> None:
    decision = guard.decide_host("!!! not a host !!!")
    assert decision.allowed is False
    assert "unparseable" in decision.reason


# ---------------------------------------------------------------------------
# URL-level decisions and path scoping
# ---------------------------------------------------------------------------


def test_path_scoped_in_scope_rule_restricts_paths() -> None:
    guard = ScopeGuard(
        make_scope(in_scope=["https://shop.example.net/api/*"], out_of_scope=[])
    )
    assert guard.decide_url("https://shop.example.net/api/v1/users").allowed is True
    assert guard.decide_url("https://shop.example.net/api").allowed is True
    assert guard.decide_url("https://shop.example.net/admin").allowed is False
    # The host itself stays resolvable so we can reach the in-scope path.
    assert guard.decide_host("shop.example.net").allowed is True


def test_path_scoped_exclusion_does_not_block_the_whole_host() -> None:
    """Excluding /logout must not make the host unreachable."""
    guard = ScopeGuard(
        make_scope(in_scope=["*.example.com"], out_of_scope=["https://example.com/logout"])
    )
    assert guard.decide_url("https://example.com/logout").allowed is False
    assert guard.decide_url("https://example.com/anything").allowed is True
    assert guard.decide_host("example.com").allowed is True


def test_host_level_exclusion_blocks_every_url_on_it(guard: ScopeGuard) -> None:
    assert guard.decide_url("https://payments.example.com/").allowed is False
    assert guard.decide_url("https://payments.example.com/deep/path?q=1").allowed is False


def test_path_prefix_does_not_match_a_sibling_prefix() -> None:
    guard = ScopeGuard(make_scope(in_scope=["https://example.com/api"], out_of_scope=[]))
    assert guard.decide_url("https://example.com/api").allowed is True
    assert guard.decide_url("https://example.com/api/v1").allowed is True
    # /apikeys must not be swallowed by the /api prefix
    assert guard.decide_url("https://example.com/apikeys").allowed is False


def test_decide_dispatches_between_host_and_url(guard: ScopeGuard) -> None:
    assert guard.decide("www.example.com").level == "host"
    assert guard.decide("https://www.example.com/x").level == "url"
    assert guard.decide("www.example.com/x").level == "url"


# ---------------------------------------------------------------------------
# helpers, raising, stats
# ---------------------------------------------------------------------------


def test_assert_in_scope_raises_with_context(guard: ScopeGuard) -> None:
    with pytest.raises(OutOfScopeError) as excinfo:
        guard.assert_in_scope("evil.com")
    assert excinfo.value.decision.allowed is False
    assert "evil.com" in str(excinfo.value)
    # An allowed target returns the decision rather than raising.
    assert guard.assert_in_scope("www.example.com").allowed is True


def test_filter_hosts_drops_out_of_scope_and_deduplicates(guard: ScopeGuard) -> None:
    """This is the funnel for tool output, which routinely includes strays."""
    raw = [
        "www.example.com",
        "WWW.EXAMPLE.COM.",        # same host, different spelling
        "payments.example.com",     # excluded
        "unrelated.org",            # a passive source's stray result
        "api.example.io",
    ]
    assert guard.filter_hosts(raw) == ["www.example.com", "api.example.io"]


def test_guard_records_what_it_blocked(guard: ScopeGuard) -> None:
    guard.decide_host("www.example.com")
    guard.decide_host("evil.com")
    guard.decide_host("payments.example.com")
    stats = guard.stats.as_dict()
    assert stats["allowed"] == 1
    assert stats["blocked"] == 2
    assert "evil.com" in stats["blocked_samples"]


def test_host_decisions_are_cached(guard: ScopeGuard) -> None:
    first = guard.decide_host("www.example.com")
    second = guard.decide_host("www.example.com")
    assert first == second
    assert guard.stats.allowed == 2  # counted twice, computed once


def test_program_limits_override_defaults() -> None:
    guard = ScopeGuard(make_scope(limits={"requests_per_second_per_host": 2}))
    assert guard.effective_limit("requests_per_second_per_host", 50) == 2
    assert guard.effective_limit("max_concurrent_hosts", 10) == 10


# ---------------------------------------------------------------------------
# scope document validation
# ---------------------------------------------------------------------------


def test_authorization_block_is_required() -> None:
    with pytest.raises(ValidationError):
        Scope.model_validate({"program": "x", "in_scope": ["example.com"]})


def test_blank_attestation_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_scope(authorization={
            "authorized_by": "me@example.com",
            "date": "2026-09-28",
            "attestation": "   ",
        })


def test_empty_in_scope_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_scope(in_scope=[])


def test_invalid_rules_are_reported_together() -> None:
    with pytest.raises(ValueError) as excinfo:
        make_scope(in_scope=["*.com", "ex*mple.com", "good.example.com"])
    message = str(excinfo.value)
    assert "*.com" in message and "ex*mple.com" in message


def test_scope_derived_properties() -> None:
    scope = make_scope(
        in_scope=["*.example.com", "api.example.io", "203.0.113.0/24", "198.51.100.7"]
    )
    assert scope.wildcard_roots == ["example.com"]
    assert scope.seed_hosts == ["api.example.io"]
    assert set(scope.seed_networks) == {"203.0.113.0/24", "198.51.100.7"}
    assert scope.slug == "example-corp-vdp"


def test_shipped_example_scope_is_valid() -> None:
    """The example we ship must actually load, or it teaches the wrong thing."""
    scope = load_scope("scopes/example.yaml")
    guard = ScopeGuard(scope)
    assert guard.decide_host("www.example.com").allowed is True
    assert guard.decide_host("payments.example.com").allowed is False
    assert guard.decide_host("db.staging.example.com").allowed is False
    assert guard.decide_url("https://example.com/logout").allowed is False


def test_load_scope_errors_are_actionable(tmp_path) -> None:
    missing = tmp_path / "nope.yaml"
    with pytest.raises(ScopeParseError, match="not found"):
        load_scope(missing)

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("in_scope: [oops\n")
    with pytest.raises(ScopeParseError, match="valid YAML"):
        load_scope(bad_yaml)

    not_a_mapping = tmp_path / "list.yaml"
    not_a_mapping.write_text("- just\n- a\n- list\n")
    with pytest.raises(ScopeParseError, match="mapping"):
        load_scope(not_a_mapping)
