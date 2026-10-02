"""Verification tests for the vulnerability classes added after SQLi and XSS.

Each class is tested the same way, because the same claim is being made about
each one:

1. the real case on the fixture reaches **Confirmed**, with both oracles named,
2. the trap is **Discarded**, and the test asserts the *reason text* rather than
   just the tier, because a class that rejects a trap for the wrong reason will
   reject a real finding for the wrong reason too,
3. a blocked host yields **Needs review** and never a finding.

The traps matter more than the real cases. A verifier that says yes is easy; the
whole value of this project is in the ones that say no, so every trap here is a
finding that other scanners report.
"""

from __future__ import annotations

import pytest

from reconx.config import Settings
from reconx.db.models import FindingTier
from reconx.net.http import ScopedHttpClient
from reconx.scope.guard import ScopeGuard
from reconx.verify.cmdi import CmdiVerifier
from reconx.verify.collaborator import LocalCollaborator
from reconx.verify.cors import CorsVerifier
from reconx.verify.deser import (
    _FORBIDDEN_TOKENS,
    CORRUPT_VALUES,
    VALID_PICKLES,
    DeserVerifier,
    find_deser_signature,
)
from reconx.verify.redirect import RedirectVerifier, redirect_target, sentinel_host
from reconx.verify.ssrf import SsrfVerifier
from reconx.verify.ssti import SstiVerifier
from reconx.verify.traversal import TraversalVerifier, find_file_signature
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


async def _client(app):
    scope = make_scope(in_scope=[app.host], out_of_scope=[])
    return ScopedHttpClient(ScopeGuard(scope), settings=fast_settings())


# ---------------------------------------------------------------------------
# open redirect
# ---------------------------------------------------------------------------


async def test_a_real_open_redirect_is_confirmed_by_two_forms(target) -> None:
    async with await _client(target) as http:
        verifier = RedirectVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/redirect?next=/"), "next")

    assert verdict.tier is FindingTier.CONFIRMED
    assert set(verdict.agreeing) == {"absolute_location", "scheme_relative_location"}
    assert verdict.confidence >= 90
    assert verdict.evidence, "a confirmed finding must carry evidence"
    # The sentinel is unresolvable and was never contacted, which the reason says.
    assert ".invalid" in verdict.reason


async def test_a_url_echoed_into_the_page_is_not_a_redirect(target) -> None:
    """The defining false positive: the sentinel is in the body, not in Location."""
    async with await _client(target) as http:
        verifier = RedirectVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/echo-url?next=/"), "next")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.agreeing == []
    assert "reflected into the response body" in verdict.reason
    assert "no Location header" in verdict.reason


async def test_a_blocked_host_is_not_reported_as_an_open_redirect(target) -> None:
    async with await _client(target) as http:
        verifier = RedirectVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/waf?next=/"), "next")

    assert verdict.obstructed is True
    assert verdict.tier is FindingTier.NEEDS_REVIEW


def test_the_redirect_sentinel_can_never_resolve() -> None:
    """A host in .invalid is guaranteed by RFC 2606 not to exist."""
    assert sentinel_host().endswith(".invalid")
    assert sentinel_host() != sentinel_host(), "each probe needs its own sentinel"


def test_only_the_location_header_counts_as_a_redirect() -> None:
    class _Response:
        status = 200
        headers: dict[str, str] = {}
        body = b'<a href="https://elsewhere.example">go</a>'

        def header(self, _name, default=""):
            return default

    from reconx.verify.base import FetchResult, PreparedRequest

    result = FetchResult(
        request=PreparedRequest(url="http://t/x"), response=_Response()  # type: ignore[arg-type]
    )
    assert redirect_target(result) is None


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


async def test_a_reflected_origin_with_credentials_is_confirmed(target) -> None:
    async with await _client(target) as http:
        verdict = await CorsVerifier(http, attempts=2, required=2).verify(
            target.url("/cors")
        )

    assert verdict.tier is FindingTier.CONFIRMED
    assert set(verdict.agreeing) == {"origin_reflected", "credentials_allowed"}
    assert verdict.allows_credentials is True
    assert verdict.reflected_origin


async def test_a_public_wildcard_cors_policy_is_not_a_finding(target) -> None:
    """``*`` with no credentials is the intended configuration for a public API."""
    async with await _client(target) as http:
        verdict = await CorsVerifier(http, attempts=2, required=2).verify(
            target.url("/cors-public")
        )

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.wildcard_only is True
    assert "intended configuration" in verdict.reason
    assert "refuse to send credentials" in verdict.reason


async def test_an_endpoint_with_no_cors_headers_is_discarded(target) -> None:
    async with await _client(target) as http:
        verdict = await CorsVerifier(http, attempts=2, required=2).verify(
            target.url("/api/v1/users")
        )

    assert verdict.tier is FindingTier.DISCARDED
    assert "not attacker-controlled" in verdict.reason


# ---------------------------------------------------------------------------
# path traversal
# ---------------------------------------------------------------------------


async def test_a_real_traversal_is_confirmed_by_two_different_files(target) -> None:
    async with await _client(target) as http:
        verifier = TraversalVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/download?file=readme.txt"), "file")

    assert verdict.tier is FindingTier.CONFIRMED
    assert set(verdict.agreeing) == {"reached_etc_passwd", "reached_etc_group"}
    assert verdict.file_label == "unix account database"
    assert verdict.matched_line, "the matched record is the proof and must be kept"


async def test_a_page_documenting_etc_passwd_is_discarded(target) -> None:
    """Mirrors the /static-error SQL trap: the signature is already on the page."""
    async with await _client(target) as http:
        verifier = TraversalVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/docs/passwd?file=overview"), "file")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.agreeing == []
    assert "already contains" in verdict.reason
    assert "says nothing" in verdict.reason


async def test_a_parameter_that_reads_no_file_is_discarded(target) -> None:
    async with await _client(target) as http:
        verifier = TraversalVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/?file=readme.txt"), "file")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.vulnerable is False


@pytest.mark.parametrize(
    ("label", "body", "matched"),
    [
        ("a real passwd file", "root:x:0:0:root:/root:/bin/bash\n", True),
        ("rendered inside pre", "<pre>root:x:0:0:root:/root:/bin/bash</pre>", True),
        ("a group file", "root:x:0:\nadm:x:4:syslog\n", True),
        ("win.ini", "[fonts]\nArial=arial.ttf", True),
        # None of these may match, or every page becomes a finding.
        ("the word root", "Only the root user may edit this file.", False),
        ("a colon after root", "root: see the administrator guide", False),
        ("sql about users", "CREATE USER root IDENTIFIED BY 'x'", False),
        ("empty", "", False),
    ],
)
def test_file_signatures_match_a_record_format_not_a_word(
    label: str, body: str, matched: bool
) -> None:
    assert (find_file_signature(body) is not None) is matched, label


# ---------------------------------------------------------------------------
# template injection
# ---------------------------------------------------------------------------


async def test_a_real_template_injection_is_confirmed_and_names_the_engine(
    target,
) -> None:
    async with await _client(target) as http:
        verifier = SstiVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/template?name=guest"), "name")

    assert verdict.tier is FindingTier.CONFIRMED
    assert set(verdict.agreeing) == {"expression_evaluated", "dialect_identified"}
    assert verdict.dialect == "curly-brace"
    assert "Jinja2" in verdict.engines
    assert "Jinja2" in verdict.reason


async def test_reflected_template_braces_are_not_template_injection(target) -> None:
    """The braces come back untouched. Reflected syntax is not evaluation."""
    async with await _client(target) as http:
        verifier = SstiVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/braces?name=guest"), "name")

    assert verdict.tier is FindingTier.DISCARDED
    assert "reflected into the page untouched" in verdict.reason
    assert "printed as data" in verdict.reason


async def test_a_plain_reflection_is_not_template_injection(target) -> None:
    async with await _client(target) as http:
        verifier = SstiVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/xss?q=test"), "q")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.dialect == ""


def test_ssti_operands_cannot_appear_in_the_payload() -> None:
    """The expected product must be a value the request never contained."""
    from reconx.verify.ssti import _operands

    for _ in range(200):
        left, right, product = _operands()
        assert str(product) not in f"{left}*{right}"
        assert product == left * right


# ---------------------------------------------------------------------------
# command injection
# ---------------------------------------------------------------------------


async def test_a_real_command_injection_is_confirmed_by_two_mechanisms(target) -> None:
    async with await _client(target) as http:
        verifier = CmdiVerifier(http, attempts=2, required=2, enable_timing=False)
        verdict = await verifier.verify(target.url("/ping?host=127.0.0.1"), "host")

    assert verdict.tier is FindingTier.CONFIRMED
    assert set(verdict.agreeing) == {"arithmetic_expansion", "command_substitution"}
    assert verdict.separator == ";"


async def test_an_endpoint_that_echoes_the_command_line_is_discarded(target) -> None:
    """The classic false positive: the canary comes back without anything running."""
    async with await _client(target) as http:
        verifier = CmdiVerifier(http, attempts=2, required=2, enable_timing=False)
        verdict = await verifier.verify(target.url("/echo-cmd?host=127.0.0.1"), "host")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.agreeing == []
    assert "echoed into the response" in verdict.reason
    assert "prints its input rather than running it" in verdict.reason
    # The three mechanisms failed the same way, so the reason says it once.
    assert verdict.reason.count("prints its input") == 1


async def test_a_parameter_that_reaches_no_shell_is_discarded(target) -> None:
    async with await _client(target) as http:
        verifier = CmdiVerifier(http, attempts=2, required=2, enable_timing=False)
        verdict = await verifier.verify(target.url("/?host=127.0.0.1"), "host")

    assert verdict.tier is FindingTier.DISCARDED
    assert "no value the shell would have had to compute" in verdict.reason


async def test_a_blocked_host_is_not_reported_as_command_injection(target) -> None:
    async with await _client(target) as http:
        verifier = CmdiVerifier(http, attempts=2, required=2, enable_timing=False)
        verdict = await verifier.verify(target.url("/waf?host=1"), "host")

    assert verdict.obstructed is True
    assert verdict.tier is FindingTier.NEEDS_REVIEW


def test_command_injection_probes_are_read_only() -> None:
    """Nothing in the payload set writes, deletes, reads a file or reaches out.

    This is a property of the tool, not of a target, so it is asserted against
    the payload table rather than observed in a response.
    """
    from reconx.verify.cmdi import MECHANISMS

    forbidden = (
        ">", "rm ", "mv ", "cp ", "dd ", "chmod", "chown", "curl", "wget", "nc ",
        "bash", "/bin/sh", "python", "perl", "cat ", "head ", "tail ", "touch",
        "mkdir", "kill", "reboot", "shutdown", "eval",
    )
    for mechanism in MECHANISMS:
        rendered = mechanism.template.format(left=7, right=7)
        for token in forbidden:
            assert token not in rendered, f"{mechanism.name} contains {token!r}"


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------


async def test_a_real_ssrf_is_confirmed_by_a_callback_and_the_returned_body(
    target,
) -> None:
    async with await _client(target) as http, LocalCollaborator() as collaborator:
        verifier = SsrfVerifier(
            http, collaborator, attempts=2, required=2, callback_timeout=5.0
        )
        verdict = await verifier.verify(target.url("/fetch?url=/"), "url")

    assert verdict.tier is FindingTier.CONFIRMED
    assert set(verdict.agreeing) == {"callback_received", "fetched_body_returned"}
    assert verdict.interactions >= 1
    assert verdict.callback_url


async def test_an_endpoint_that_only_fetches_a_fixed_url_is_discarded(target) -> None:
    """It does fetch internally, but the parameter cannot redirect it."""
    async with await _client(target) as http, LocalCollaborator() as collaborator:
        verifier = SsrfVerifier(
            http, collaborator, attempts=2, required=2, callback_timeout=2.0
        )
        verdict = await verifier.verify(target.url("/internal-only?url=/"), "url")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.interactions == 0
    assert "did not fetch the URL the parameter named" in verdict.reason


async def test_an_open_redirect_to_the_listener_is_not_reported_as_ssrf(target) -> None:
    """A false positive the fixture actually produced, and the reason it cannot recur.

    ``/redirect`` answers with ``Location:`` set to whatever the parameter says.
    Point that at the callback listener and, if the scanner follows the hop, the
    listener records a request *and* the response carries the listener's marker --
    so both oracles agree, on the scanner's own traffic. It read as a confirmed
    SSRF on an endpoint that never fetched anything.

    Two things stop it: the probe does not follow redirects, and a callback
    carrying ReconX's own user agent is discarded rather than counted.
    """
    async with await _client(target) as http, LocalCollaborator() as collaborator:
        verifier = SsrfVerifier(
            http, collaborator, attempts=2, required=2, callback_timeout=2.0
        )
        verdict = await verifier.verify(target.url("/redirect?next=/"), "next")

    assert verdict.tier is not FindingTier.CONFIRMED, verdict.reason
    assert verdict.vulnerable is False, verdict.reason


async def test_the_collaborator_can_tell_our_own_callbacks_apart() -> None:
    """The mechanism behind the test above, checked directly."""
    import asyncio
    import urllib.request

    async with LocalCollaborator() as collaborator:
        token = collaborator.new_token()

        def call(agent: str) -> None:
            request = urllib.request.Request(
                collaborator.url_for(token), headers={"User-Agent": agent}
            )
            urllib.request.urlopen(request, timeout=3).read()

        await asyncio.to_thread(call, "ReconX/0.1 (authorized security research)")
        assert len(collaborator.received(token)) == 1
        assert collaborator.received(token, exclude_user_agents=("ReconX",)) == []

        await asyncio.to_thread(call, "SomeServer/2.0")
        kept = collaborator.received(token, exclude_user_agents=("ReconX",))
        assert len(kept) == 1
        assert kept[0].user_agent == "SomeServer/2.0"


async def test_ssrf_without_a_listener_is_needs_review_not_clean(target) -> None:
    """An untested parameter must not read as a tested one."""
    async with await _client(target) as http:
        verifier = SsrfVerifier(http, LocalCollaborator(), attempts=2, required=2)
        verdict = await verifier.verify(target.url("/fetch?url=/"), "url")

    assert verdict.tier is FindingTier.NEEDS_REVIEW
    assert verdict.vulnerable is False
    assert "not running" in verdict.reason


async def test_the_collaborator_is_loopback_and_contacts_nothing_external() -> None:
    """The listener must never be a third-party interaction service."""
    async with LocalCollaborator() as collaborator:
        assert collaborator.bind_host == "127.0.0.1"
        assert collaborator.is_loopback_only is True
        assert collaborator.base_url.startswith("http://127.0.0.1:")
        # No setting points it at a hosted service; an operator supplies their own.
        assert collaborator.public_base_url == ""


async def test_the_collaborator_records_only_what_reached_it() -> None:
    import asyncio
    import urllib.request

    async with LocalCollaborator() as collaborator:
        token = collaborator.new_token()
        await asyncio.to_thread(
            lambda: urllib.request.urlopen(collaborator.url_for(token), timeout=3).read()
        )
        hits = await collaborator.wait_for(token, timeout=3.0)

        assert len(hits) == 1
        assert hits[0].token == token
        assert hits[0].method == "GET"
        # A token that was never sent must never appear.
        assert await collaborator.wait_for(collaborator.new_token(), timeout=0.2) == []


def test_a_remote_target_needs_a_reachable_listener_and_says_so() -> None:
    """A quiet loopback listener is not evidence that a remote target is safe."""
    collaborator = LocalCollaborator()
    verifier = SsrfVerifier(None, collaborator)  # type: ignore[arg-type]
    reason = verifier._no_callback_reason("https://remote.example.com/f?url=x")
    assert "bound to loopback" in reason
    assert "not evidence that the parameter is safe" in reason

    local = verifier._no_callback_reason("http://127.0.0.1:8080/f?url=x")
    assert "bound to loopback" not in local


# ---------------------------------------------------------------------------
# insecure deserialization
# ---------------------------------------------------------------------------


async def test_a_real_deserialization_is_confirmed_by_two_oracles(target) -> None:
    async with await _client(target) as http:
        verifier = DeserVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/pickle?data=Ti4="), "data")

    assert verdict.tier is FindingTier.CONFIRMED
    assert set(verdict.agreeing) == {"format_differential", "deserialization_error"}
    assert verdict.engine_hint == "Python pickle"
    assert verdict.confidence >= 90
    assert verdict.evidence, "a confirmed finding must carry evidence"


async def test_a_page_documenting_unpickling_errors_is_discarded(target) -> None:
    """The defining false positive: the error string is in the page already."""
    async with await _client(target) as http:
        verifier = DeserVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(
            target.url("/pickle-docs?topic=overview"), "topic"
        )

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.agreeing == []
    assert "already present in the unmodified page" in verdict.reason


async def test_a_parameter_that_deserializes_nothing_is_discarded(target) -> None:
    async with await _client(target) as http:
        verifier = DeserVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/echo-url?next=/"), "next")

    assert verdict.tier is FindingTier.DISCARDED
    assert verdict.agreeing == []
    assert "deserializer error" in verdict.reason


async def test_a_blocked_host_is_not_reported_as_deserialization(target) -> None:
    async with await _client(target) as http:
        verifier = DeserVerifier(http, attempts=2, required=2)
        verdict = await verifier.verify(target.url("/waf?data=1"), "data")

    assert verdict.obstructed is True
    assert verdict.tier is FindingTier.NEEDS_REVIEW


def test_deserialization_signatures_name_a_real_engine() -> None:
    """A bare "error" match would fire on most of the internet."""
    assert find_deser_signature(b"<p>Error: something broke</p>") is None
    engine, _ = find_deser_signature(
        b"<p>_pickle.UnpicklingError: invalid load key, 'x'.</p>"
    )
    assert engine == "Python pickle"


def test_deserialization_probes_cannot_execute() -> None:
    """No gadget, no reduce, no execution primitive in any probe value.

    This is a property of the tool, not of a target, so it is asserted against
    the payload tables rather than observed in a response.
    """
    for value in (*VALID_PICKLES, *(corrupt for _, corrupt in CORRUPT_VALUES)):
        for token in _FORBIDDEN_TOKENS:
            assert token not in value, f"a deserialization probe contains {token!r}"
