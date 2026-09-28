"""Tests for content discovery helpers."""

from __future__ import annotations

import pytest

from reconx.stages.content import (
    _JS_CONCAT_RE,
    _JS_CONST_RE,
    _JS_FETCH_RE,
    _JS_PATH_RE,
    _JS_TEMPLATE_RE,
    _SECRET_PATTERNS,
    _interest_score,
    _normalize_url,
)

# ---------------------------------------------------------------------------
# URL handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://x.example.com/a#frag", "https://x.example.com/a"),
        ("https://x.example.com", "https://x.example.com/"),
        ("https://x.example.com/a?b=1#c", "https://x.example.com/a?b=1"),
        ("https://x.example.com/a?b=1", "https://x.example.com/a?b=1"),
    ],
)
def test_normalize_url_drops_fragments(raw: str, expected: str) -> None:
    assert _normalize_url(raw) == expected


def test_interest_score_ranks_the_paths_worth_looking_at() -> None:
    """A report should lead with an exposed .git, not a marketing page."""
    assert _interest_score("https://x.example.com/.git/config") > _interest_score(
        "https://x.example.com/about-us"
    )
    assert _interest_score("https://x.example.com/actuator/env") > _interest_score(
        "https://x.example.com/api"
    )
    assert _interest_score("https://x.example.com/products") == 0.0


# ---------------------------------------------------------------------------
# JavaScript mining
# ---------------------------------------------------------------------------

SAMPLE_JS = """
const API_BASE = "/api/v1";
let ADMIN_ROOT = "/internal/admin";
const GREETING = "hello there";
fetch(API_BASE + "/users");
fetch(`${API_BASE}/orders`);
axios.get(ADMIN_ROOT + "/audit-log");
fetch("/legacy/direct-path");
fetch(GREETING + "/not-a-path");
const LOGO = "/assets/logo.png";
fetch(LOGO);
"""


def _resolved_paths(text: str) -> set[str]:
    """Reproduce the stage's resolution logic over a sample."""
    constants = {
        name: value
        for name, value in _JS_CONST_RE.findall(text)
        if value.startswith("/") or value.startswith("http")
    }
    found: set[str] = set()
    for pattern in (_JS_CONCAT_RE, _JS_TEMPLATE_RE):
        for match in pattern.finditer(text):
            name, suffix = match.group(1), match.group(2)
            base = constants.get(name)
            if base and suffix:
                found.add(base.rstrip("/") + "/" + suffix.lstrip("/"))
    return found


def test_string_constants_are_collected_but_only_path_like_ones() -> None:
    constants = dict(_JS_CONST_RE.findall(SAMPLE_JS))
    assert constants["API_BASE"] == "/api/v1"
    assert constants["ADMIN_ROOT"] == "/internal/admin"
    # A non-path constant is parsed but must not be treated as a base.
    assert constants["GREETING"] == "hello there"
    assert "hello there/not-a-path" not in _resolved_paths(SAMPLE_JS)


def test_concatenated_paths_are_resolved() -> None:
    """Real bundles assign a base and concatenate; the literal is never complete."""
    resolved = _resolved_paths(SAMPLE_JS)
    assert "/api/v1/users" in resolved
    assert "/internal/admin/audit-log" in resolved


def test_template_literal_paths_are_resolved() -> None:
    resolved = _resolved_paths(SAMPLE_JS)
    assert "/api/v1/orders" in resolved


def test_direct_literal_paths_are_still_found() -> None:
    literals = set(_JS_PATH_RE.findall(SAMPLE_JS))
    assert "/legacy/direct-path" in literals
    calls = set(_JS_FETCH_RE.findall(SAMPLE_JS))
    assert "/legacy/direct-path" in calls


def test_minified_bundle_shape_still_yields_endpoints() -> None:
    """Minified code has no spaces around operators."""
    minified = 'var a="/api/v2";fetch(a+"/profile");t.get(`${a}/settings`)'
    resolved = _resolved_paths(minified)
    assert "/api/v2/profile" in resolved
    assert "/api/v2/settings" in resolved


# ---------------------------------------------------------------------------
# credential shapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "sample"),
    [
        ("AWS access key id", "AKIAIOSFODNN7EXAMPLE"),
        ("Google API key", "AIza" + "B" * 35),
        ("Slack token", "xoxb-" + "1234567890" * 2),
        ("GitHub token", "ghp_" + "a" * 36),
        ("Stripe secret key", "sk_live_" + "9" * 24),
        ("private key block", "-----BEGIN RSA PRIVATE KEY-----"),
    ],
)
def test_credential_formats_are_recognised(label: str, sample: str) -> None:
    import re

    pattern = next(p for name, p, _ in _SECRET_PATTERNS if name == label)
    assert re.search(pattern, f'const k = "{sample}";'), f"{label} not matched"


@pytest.mark.parametrize(
    "benign",
    [
        'const version = "1.2.3";',
        'const id = "AKIA";',                    # too short to be a key
        'const name = "aizaSomethingShort";',
        'const token = "xox";',
        'const path = "/api/v1/users";',
        'const uuid = "550e8400-e29b-41d4-a716-446655440000";',
    ],
)
def test_ordinary_javascript_does_not_look_like_a_credential(benign: str) -> None:
    """A secret scanner that fires on version strings is worse than none."""
    import re

    for _label, pattern, _severity in _SECRET_PATTERNS:
        assert not re.search(pattern, benign), f"false positive on: {benign}"
