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


# ---------------------------------------------------------------------------
# katana parity
# ---------------------------------------------------------------------------

FIXTURE_PAGE = """<!doctype html><html><head><title>Home</title></head><body>
<a href="/products">products</a>
<a href="/sqli?id=1">widget</a>
<form action="/search"><input name="q"><input name="page"><textarea name="note">
</textarea></form>
<form><input name="csrf" type="hidden"><input name="username"></form>
<script src="/static/app.js"></script>
<a href="mailto:x@example.com">mail</a>
<a href="#top">top</a>
</body></html>"""


class _StubContext:
    """Just enough of StageContext for the HTML harvesters."""

    def __init__(self) -> None:
        self.shared: dict = {}


def _collect(page: str, source: str = "crawl"):
    """Run the shared harvester and return (proposed urls, form params, followable)."""
    from reconx.stages.content import ContentStage

    ctx = _StubContext()
    proposed: list[tuple[str, str]] = []
    stage = ContentStage()
    followable = stage._harvest_html(
        ctx, "http://t.example.com/", page, lambda url, src: proposed.append((url, src)), source
    )
    return proposed, ctx.shared.get("form_params", {}), followable


def test_html_harvest_finds_links_forms_and_scripts() -> None:
    proposed, forms, _ = _collect(FIXTURE_PAGE)
    urls = {url for url, _ in proposed}

    assert "http://t.example.com/products" in urls
    assert "http://t.example.com/sqli?id=1" in urls
    assert "http://t.example.com/static/app.js" in urls
    # The form's action, which link extraction alone never yields.
    assert "http://t.example.com/search" in urls
    # Its input names, which are the parameters worth testing later.
    assert forms["http://t.example.com/search"] == ["note", "page", "q"]


def test_html_harvest_skips_non_navigable_hrefs() -> None:
    proposed, _, _ = _collect(FIXTURE_PAGE)
    urls = {url for url, _ in proposed}
    assert not any("mailto:" in url for url in urls)
    assert not any(url.endswith("#top") for url in urls)


def test_a_form_with_no_action_attributes_to_its_own_page() -> None:
    proposed, forms, _ = _collect(FIXTURE_PAGE)
    del proposed
    # The second form has no action, so its inputs belong to the page itself.
    assert forms["http://t.example.com/"] == ["csrf", "username"]


def test_katana_output_yields_the_same_things_as_the_builtin_crawler() -> None:
    """Regression: installing katana used to make the scan find *less*.

    Katana's endpoint list is link-driven, so it never reported a form's action
    or its input names. Because the katana path returned early, the built-in
    crawler that did find those never ran, and a genuinely vulnerable form
    endpoint was silently dropped. Katana's JSONL carries the response body, so
    the same parsing now runs over what it already fetched.
    """
    import json

    from reconx.stages.content import ContentStage

    # One katana JSONL row, shaped as katana v1.7 emits it.
    row = {
        "request": {"method": "GET", "endpoint": "http://t.example.com/"},
        "response": {
            "status_code": 200,
            "headers": {"Content-Type": "text/html; charset=utf-8"},
            "body": FIXTURE_PAGE,
        },
    }

    ctx = _StubContext()
    proposed: list[tuple[str, str]] = []

    class _Result:
        def __init__(self) -> None:
            self.notes: list[str] = []

        def note(self, message: str) -> None:
            self.notes.append(message)

    stage = ContentStage()
    stage._harvest_katana(
        ctx, [json.dumps(row)], lambda url, src: proposed.append((url, src)), _Result()
    )

    urls = {url for url, _ in proposed}
    builtin_urls = {url for url, _ in _collect(FIXTURE_PAGE)[0]}

    # Everything the built-in crawler finds on this page, katana's path finds too.
    missing = builtin_urls - urls
    assert missing == set(), f"the katana path lost: {missing}"
    # Including the form action and its parameters.
    assert "http://t.example.com/search" in urls
    assert ctx.shared["form_params"]["http://t.example.com/search"] == ["note", "page", "q"]


def test_katana_rows_without_a_body_are_tolerated() -> None:
    """Not every katana row carries a response, and a missing one is not an error."""
    import json

    from reconx.stages.content import ContentStage

    class _Result:
        def note(self, message: str) -> None:
            pass

    ctx = _StubContext()
    proposed: list[tuple[str, str]] = []
    rows = [
        json.dumps({"request": {"endpoint": "http://t.example.com/only-a-link"}}),
        "not json at all",
        json.dumps({"response": {"body": "<html></html>"}}),  # no endpoint
    ]
    ContentStage()._harvest_katana(
        ctx, rows, lambda url, src: proposed.append((url, src)), _Result()
    )
    assert ("http://t.example.com/only-a-link", "katana") in proposed
