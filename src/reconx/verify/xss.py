"""Cross-site scripting verification.

"The input is reflected" is not a finding. Most reflected input is harmless,
because the application encodes it, or it lands somewhere inert, or the
characters needed to break out of its context do not survive. Reporting
reflection as XSS is the single largest source of noise in web scanning.

Verification here runs in three steps, each of which can end it:

1. **Reflection** — inject a unique alphanumeric canary and find where it
   appears. Alphanumeric so that nothing is encoded and the search is exact.
2. **Context and escape analysis** — work out what surrounds the canary (HTML
   body, a quoted or unquoted attribute, a JavaScript string, a comment, a URL)
   and determine which characters would be needed to break out. Then send those
   characters and check which survive unencoded. If the ones that matter are
   encoded, the reflection is inert and is discarded with that reason.
3. **Execution** — when Chromium is available, load the page with a payload
   that calls a known function and confirm it actually runs.

Only step 3 yields **Confirmed**. Step 2 alone yields **Probable**: worth a
researcher's attention, not worth submitting unverified.

The payloads call a harmless marker function. Nothing here exfiltrates data,
persists anything, or targets another user.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from enum import StrEnum

from reconx.db.models import FindingTier
from reconx.verify.base import (
    Evidence,
    OracleResult,
    OracleStrength,
    ParameterVerdict,
    ParameterVerifier,
    ParamTarget,
)
from reconx.verify.reproduce import reproduce

__all__ = [
    "ReflectionKind",
    "ReflectionSite",
    "XssVerdict",
    "XssVerifier",
    "MARKER_FUNCTION",
    "resolve_chromium_path",
]

# The payload calls this. A unique name so nothing else could define it.
MARKER_FUNCTION = "__reconx_xss_marker"


class ReflectionKind(StrEnum):
    NONE = "none"
    HTML_BODY = "html_body"
    ATTRIBUTE_DOUBLE = "attribute_double_quoted"
    ATTRIBUTE_SINGLE = "attribute_single_quoted"
    ATTRIBUTE_UNQUOTED = "attribute_unquoted"
    SCRIPT_STRING_DOUBLE = "script_string_double_quoted"
    SCRIPT_STRING_SINGLE = "script_string_single_quoted"
    SCRIPT_BLOCK = "script_block"
    HTML_COMMENT = "html_comment"
    STYLE_BLOCK = "style_block"


# What each context needs in order to escape it, and a payload shape that does.
_CONTEXT_REQUIREMENTS: dict[ReflectionKind, tuple[tuple[str, ...], str]] = {
    ReflectionKind.HTML_BODY: (
        ("<", ">"),
        "<script>{fn}()</script>",
    ),
    ReflectionKind.ATTRIBUTE_DOUBLE: (
        ('"',),
        '"><script>{fn}()</script>',
    ),
    ReflectionKind.ATTRIBUTE_SINGLE: (
        ("'",),
        "'><script>{fn}()</script>",
    ),
    ReflectionKind.ATTRIBUTE_UNQUOTED: (
        (" ", ">"),
        " onmouseover={fn}() autofocus onfocus={fn}() x",
    ),
    ReflectionKind.SCRIPT_STRING_DOUBLE: (
        ('"',),
        '";{fn}();//',
    ),
    ReflectionKind.SCRIPT_STRING_SINGLE: (
        ("'",),
        "';{fn}();//",
    ),
    ReflectionKind.SCRIPT_BLOCK: (
        (";",),
        ";{fn}();//",
    ),
    ReflectionKind.HTML_COMMENT: (
        ("<", ">", "-"),
        "--><script>{fn}()</script>",
    ),
    ReflectionKind.STYLE_BLOCK: (
        ("<", ">"),
        "</style><script>{fn}()</script>",
    ),
}

def resolve_chromium_path(explicit: str = "") -> str | None:
    """Find a usable Chromium executable.

    Playwright ships against a specific browser build, so a machine that has
    Chromium installed by other means, or a pinned build that does not match the
    installed Python package, will fail to launch with the default settings.
    Rather than treat that as "no browser", the common locations are checked so
    execution confirmation keeps working.

    Returns None when nothing usable is found, in which case the verdict is
    downgraded to Probable rather than a real finding being discarded.
    """
    import glob
    import os
    import shutil

    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)

    browsers_root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    for root in filter(None, [browsers_root, "/opt/pw-browsers"]):
        candidates.append(os.path.join(root, "chromium"))
        candidates.extend(sorted(glob.glob(os.path.join(root, "chromium-*/chrome-linux/chrome")),
                                reverse=True))
        candidates.extend(
            sorted(
                glob.glob(
                    os.path.join(root, "chromium_headless_shell-*/chrome-linux/headless_shell")
                ),
                reverse=True,
            )
        )

    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        found = shutil.which(name)
        if found:
            candidates.append(found)

    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


_SCRIPT_OPEN = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r"</script\s*>", re.IGNORECASE)
_STYLE_OPEN = re.compile(r"<style\b[^>]*>", re.IGNORECASE)
_STYLE_CLOSE = re.compile(r"</style\s*>", re.IGNORECASE)


@dataclass
class ReflectionSite:
    """Where a canary landed, and what it would take to escape."""

    kind: ReflectionKind
    offset: int
    snippet: str
    required_chars: tuple[str, ...] = ()
    payload_template: str = ""
    surviving_chars: tuple[str, ...] = ()
    encoded_chars: tuple[str, ...] = ()

    @property
    def escapable(self) -> bool:
        """True when every character needed to break out survives."""
        if self.kind is ReflectionKind.NONE or not self.required_chars:
            return False
        return set(self.required_chars).issubset(set(self.surviving_chars))

    def describe(self) -> str:
        return (
            f"reflected into {self.kind.value.replace('_', ' ')} at byte {self.offset}"
        )


@dataclass
class XssVerdict(ParameterVerdict):
    site: ReflectionSite | None = None
    dom_confirmed: bool = False
    dom_available: bool = False
    reproduced: str = ""

    def as_dict(self) -> dict:
        return {
            **super().as_dict(),
            "context": self.site.kind.value if self.site else "none",
            "escapable": self.site.escapable if self.site else False,
            "surviving_chars": list(self.site.surviving_chars) if self.site else [],
            "encoded_chars": list(self.site.encoded_chars) if self.site else [],
            "dom_confirmed": self.dom_confirmed,
            "dom_available": self.dom_available,
        }


def classify_reflection(body: str, canary: str) -> ReflectionSite:
    """Work out what surrounds the first occurrence of ``canary``."""
    offset = body.find(canary)
    if offset == -1:
        return ReflectionSite(kind=ReflectionKind.NONE, offset=-1, snippet="")

    before = body[:offset]
    window_start = max(0, offset - 120)
    snippet = body[window_start : offset + len(canary) + 80]

    kind = _classify(before, body, offset)
    required, template = _CONTEXT_REQUIREMENTS.get(kind, ((), ""))
    return ReflectionSite(
        kind=kind,
        offset=offset,
        snippet=snippet,
        required_chars=required,
        payload_template=template,
    )


def _inside(before: str, body: str, offset: int, open_re, close_re) -> bool:
    """True when ``offset`` sits between an unclosed open tag and its close."""
    last_open = None
    for match in open_re.finditer(before):
        last_open = match
    if last_open is None:
        return False
    return close_re.search(before, last_open.end()) is None


def _classify(before: str, body: str, offset: int) -> ReflectionKind:
    # An HTML comment beats everything else: content inside is inert.
    comment_open = before.rfind("<!--")
    if comment_open != -1 and before.find("-->", comment_open) == -1:
        return ReflectionKind.HTML_COMMENT

    if _inside(before, body, offset, _SCRIPT_OPEN, _SCRIPT_CLOSE):
        quote = _enclosing_quote(before)
        if quote == '"':
            return ReflectionKind.SCRIPT_STRING_DOUBLE
        if quote == "'":
            return ReflectionKind.SCRIPT_STRING_SINGLE
        return ReflectionKind.SCRIPT_BLOCK

    if _inside(before, body, offset, _STYLE_OPEN, _STYLE_CLOSE):
        return ReflectionKind.STYLE_BLOCK

    # Inside a tag? Find the last unclosed "<".
    tag_open = before.rfind("<")
    if tag_open != -1 and ">" not in before[tag_open:]:
        attribute_part = before[tag_open:]
        quote = _enclosing_quote(attribute_part)
        if quote == '"':
            return ReflectionKind.ATTRIBUTE_DOUBLE
        if quote == "'":
            return ReflectionKind.ATTRIBUTE_SINGLE
        return ReflectionKind.ATTRIBUTE_UNQUOTED

    return ReflectionKind.HTML_BODY


def _enclosing_quote(text: str) -> str | None:
    """Which quote character, if any, the position sits inside."""
    in_quote: str | None = None
    for character in text:
        if in_quote is None:
            if character in "\"'":
                in_quote = character
        elif character == in_quote:
            in_quote = None
    return in_quote


class XssVerifier(ParameterVerifier):
    """Verifies reflected XSS by context analysis and, where possible, execution."""

    vuln_class = "xss"
    title = "Reflected cross-site scripting"
    verdict_class = XssVerdict

    def __init__(
        self,
        http,
        *,
        attempts: int = 3,
        required: int = 3,
        headless_confirm: bool = True,
        chromium_path: str = "",
        session_headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(http, attempts=attempts, required=required)
        self._headless_confirm = headless_confirm
        self._chromium_path = chromium_path
        # The browser gets a blank profile by default, so an authenticated page
        # loads as the sign-in form and DOM confirmation fails on every real
        # finding behind a login -- which downgrades it to Probable for a reason
        # that has nothing to do with the bug. Seeding the context fixes that.
        self._session_headers = dict(session_headers or {})

    # -- entry point -------------------------------------------------------

    async def verify(
        self, target: ParamTarget | str, parameter: str | None = None
    ) -> XssVerdict:
        target = self.target_of(target, parameter)
        verdict: XssVerdict = self.new_verdict(target)  # type: ignore[assignment]

        canary = f"rx{secrets.token_hex(5)}zz"
        result = await self.fetch(target.apply(canary))
        if not result.ok:
            verdict.reason = f"the probe request could not be completed ({result.error})"
            return verdict

        if self.gate_obstruction(verdict, result):
            return verdict

        # --- step 1: is it reflected at all? ------------------------------
        site = classify_reflection(result.text, canary)
        verdict.site = site
        if site.kind is ReflectionKind.NONE:
            verdict.oracles.append(
                OracleResult(
                    name="reflection",
                    agreed=False,
                    reason="the value is not reflected in the response",
                )
            )
            self._decide(verdict)
            return verdict

        # Reflection must be reliable, not a one-off from a cache or a log view.
        async def reflection_probe(_index: int) -> tuple[bool, str | None]:
            fresh = f"rx{secrets.token_hex(5)}zz"
            again = await self.fetch(target.apply(fresh))
            if not again.ok:
                return False, f"request failed ({again.error})"
            return (fresh in again.text), None

        outcome = await reproduce(
            reflection_probe, attempts=self._attempts, required=self._required
        )
        verdict.reproduced = outcome.explain()
        verdict.oracles.append(
            OracleResult(
                name="reflection",
                agreed=outcome.stable,
                reason=(
                    f"{site.describe()}, {outcome.explain()}"
                    if outcome.stable
                    else f"reflection is not reliable: {outcome.explain()}"
                ),
                reproduced=outcome.successes,
                attempts=outcome.total,
            )
        )
        if not outcome.stable:
            self._decide(verdict)
            return verdict

        # --- step 2: do the characters needed to escape survive? ----------
        await self._probe_escaping(target, site)

        verdict.oracles.append(
            OracleResult(
                name="context_escape",
                agreed=site.escapable,
                reason=(
                    f"every character needed to escape {site.kind.value} survives "
                    f"unencoded ({', '.join(repr(c) for c in site.surviving_chars)})"
                    if site.escapable
                    else (
                        f"{', '.join(repr(c) for c in site.encoded_chars) or 'the required characters'}"
                        " are encoded or stripped"
                    )
                ),
                detail={"context": site.kind.value},
            )
        )

        if not site.escapable:
            verdict.add(
                Evidence(
                    label="inert reflection",
                    context=site.kind.value,
                    snippet=site.snippet,
                    detail={"encoded_chars": list(site.encoded_chars)},
                )
            )
            self._decide(verdict)
            return verdict

        payload = site.payload_template.format(fn=MARKER_FUNCTION)
        payload_request = target.apply(payload)
        verdict.add(
            Evidence.comparison(
                "escapable reflection",
                payload=payload_request,
                context=site.kind.value,
                snippet=site.snippet,
                surviving_chars=list(site.surviving_chars),
            )
        )

        # --- step 3: does it actually execute? ----------------------------
        if self._headless_confirm:
            confirmed, detail, available = await self._confirm_execution(
                payload_request.url
            )
            verdict.dom_available = available
            verdict.dom_confirmed = confirmed
            verdict.oracles.append(
                OracleResult(
                    name="browser_execution",
                    agreed=confirmed,
                    reason=detail,
                    strength=OracleStrength.DECISIVE,
                )
            )

        self._decide(verdict)
        return verdict

    # -- decision ----------------------------------------------------------

    def _decide(self, verdict: XssVerdict) -> None:
        """Turn the three steps into a tier.

        XSS does not use :func:`~reconx.verify.base.decide_from_oracles`, because
        its oracles are not independent: each one gates the next. Reflection is a
        precondition for escape analysis, and escape analysis is a precondition
        for execution. Counting them as agreeing votes would let two views of the
        same fact reach Confirmed, which is exactly the mistake the two-oracle
        rule exists to prevent.

        So the ladder is explicit. Only real execution in a browser confirms.
        """
        site = verdict.site
        agreed = {oracle.name for oracle in verdict.oracles if oracle.agreed}
        verdict.signals = sorted(agreed)

        if site is None or site.kind is ReflectionKind.NONE:
            verdict.tier = FindingTier.DISCARDED
            verdict.confidence = 0
            verdict.reason = "the value is not reflected in the response"
            return

        if "reflection" not in agreed:
            verdict.tier = FindingTier.DISCARDED
            verdict.confidence = 0
            verdict.reason = f"reflection is not reliable: {verdict.reproduced}"
            return

        if not site.escapable:
            verdict.tier = FindingTier.DISCARDED
            verdict.confidence = 0
            encoded = ", ".join(repr(c) for c in site.encoded_chars)
            verdict.reason = (
                f"{site.describe()}, but {encoded or 'the required characters'} are "
                "encoded or stripped, so the reflection cannot break out of its "
                "context and is inert"
            )
            return

        execution = next(
            (o for o in verdict.oracles if o.name == "browser_execution"), None
        )
        if execution is not None and execution.agreed:
            verdict.tier = FindingTier.CONFIRMED
            verdict.confidence = 95
            verdict.reason = (
                f"{site.describe()}, the characters needed to escape it survive, and "
                f"the payload executed in a real browser ({execution.reason})"
            )
            return

        if execution is not None and verdict.dom_available:
            verdict.tier = FindingTier.NEEDS_REVIEW
            verdict.confidence = 45
            verdict.reason = (
                f"{site.describe()} and the escape characters survive, but the payload "
                f"did not execute in a real browser ({execution.reason}). Something "
                "else is preventing it, such as a Content-Security-Policy"
            )
            return

        # No browser was available, so the strongest claim the evidence supports
        # is that the reflection *can* escape its context. That is Probable, not
        # a finding: a missing browser must downgrade confidence, never lose a
        # real bug and never invent one.
        verdict.tier = FindingTier.PROBABLE
        verdict.confidence = 70
        verdict.reason = (
            f"{site.describe()} and every character needed to escape that context "
            f"survives unencoded ({', '.join(repr(c) for c in site.surviving_chars)}). "
            "Execution was not confirmed because a headless browser is unavailable, so "
            "verify by hand before reporting"
        )

    # -- escape analysis ---------------------------------------------------

    async def _probe_escaping(self, target: ParamTarget, site: ReflectionSite) -> None:
        """Send the characters that matter and record which come back intact."""
        if not site.required_chars:
            return

        marker = f"rx{secrets.token_hex(4)}"
        # Wrap each character in the marker so it can be located precisely even
        # if the page contains the character elsewhere.
        probe_value = marker + "".join(
            f"{character}{marker}" for character in site.required_chars
        )
        result = await self.fetch(target.apply(probe_value))
        if not result.ok:
            return

        text = result.text
        survived: list[str] = []
        encoded: list[str] = []
        for character in site.required_chars:
            if f"{marker}{character}{marker}" in text:
                survived.append(character)
            else:
                encoded.append(character)

        site.surviving_chars = tuple(survived)
        site.encoded_chars = tuple(encoded)

    # -- execution confirmation --------------------------------------------

    async def _confirm_execution(self, payload_url: str) -> tuple[bool, str, bool]:
        """Load the URL in Chromium and see whether the marker runs.

        Returns ``(confirmed, detail, browser_available)``. A missing browser is
        not a failure: it downgrades the verdict to Probable rather than
        discarding a real finding.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return False, "playwright is not installed", False

        fired: list[str] = []
        launch_args = {"args": ["--no-sandbox", "--disable-dev-shm-usage"]}
        try:
            async with async_playwright() as playwright:
                try:
                    browser = await playwright.chromium.launch(**launch_args)
                except Exception:
                    # Playwright's bundled build is missing or mismatched. Fall
                    # back to whatever Chromium the machine actually has.
                    executable = resolve_chromium_path(self._chromium_path)
                    if executable is None:
                        return False, "no usable Chromium was found", False
                    browser = await playwright.chromium.launch(
                        executable_path=executable, **launch_args
                    )
                try:
                    context = await browser.new_context(
                        ignore_https_errors=True,
                        # Without these the browser is a stranger to the
                        # application: an authenticated page renders as the login
                        # form, the marker never runs, and a real finding is
                        # downgraded for the wrong reason.
                        extra_http_headers=self._session_headers or None,
                    )
                    page = await context.new_page()

                    # The payload calls this. Nothing else defines it, so a call
                    # is proof the injected script ran.
                    await page.expose_function(
                        MARKER_FUNCTION, lambda: fired.append("marker function called")
                    )
                    # A dialog is the other common proof, and some payloads land
                    # as an event handler that alerts.
                    page.on(
                        "dialog",
                        lambda dialog: (
                            fired.append(f"dialog: {dialog.type}"),
                            dialog.dismiss(),
                        ),
                    )
                    page.on(
                        "pageerror",
                        lambda error: fired.append(f"page error: {str(error)[:80]}")
                        if MARKER_FUNCTION in str(error)
                        else None,
                    )

                    await page.goto(payload_url, wait_until="load", timeout=15_000)
                    # Give an event-handler payload a chance to fire.
                    await page.wait_for_timeout(700)
                finally:
                    await browser.close()
        except Exception as exc:
            return False, f"browser check failed: {type(exc).__name__}: {exc}", True

        executed = [item for item in fired if not item.startswith("page error")]
        if executed:
            return True, executed[0], True
        if fired:
            return False, fired[0], True
        return False, "the marker never ran", True
