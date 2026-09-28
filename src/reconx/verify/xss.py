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
from dataclasses import dataclass, field
from enum import StrEnum

from reconx.db.models import FindingTier
from reconx.verify.reproduce import reproduce
from reconx.verify.sqli import set_parameter
from reconx.verify.waf import WafState, classify_response

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
class XssVerdict:
    url: str
    parameter: str
    tier: FindingTier
    confidence: int
    site: ReflectionSite | None = None
    dom_confirmed: bool = False
    dom_available: bool = False
    reason: str = ""
    evidence: list[dict] = field(default_factory=list)
    obstructed: bool = False
    reproduced: str = ""

    @property
    def vulnerable(self) -> bool:
        return self.tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE)

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "tier": self.tier.value,
            "confidence": self.confidence,
            "context": self.site.kind.value if self.site else "none",
            "escapable": self.site.escapable if self.site else False,
            "surviving_chars": list(self.site.surviving_chars) if self.site else [],
            "encoded_chars": list(self.site.encoded_chars) if self.site else [],
            "dom_confirmed": self.dom_confirmed,
            "dom_available": self.dom_available,
            "reason": self.reason,
            "obstructed": self.obstructed,
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


class XssVerifier:
    """Verifies reflected XSS by context analysis and, where possible, execution."""

    def __init__(
        self,
        http,
        *,
        attempts: int = 3,
        required: int = 3,
        headless_confirm: bool = True,
        chromium_path: str = "",
    ) -> None:
        self._http = http
        self._attempts = attempts
        self._required = required
        self._headless_confirm = headless_confirm
        self._chromium_path = chromium_path

    # -- entry point -------------------------------------------------------

    async def verify(self, url: str, parameter: str) -> XssVerdict:
        verdict = XssVerdict(
            url=url, parameter=parameter, tier=FindingTier.DISCARDED, confidence=0
        )

        canary = f"rx{secrets.token_hex(5)}zz"
        probe_url = set_parameter(url, parameter, canary)

        response = await self._get(probe_url)
        if response is None:
            verdict.reason = "the probe request could not be completed"
            return verdict

        obstruction = classify_response(
            status=response.status, headers=response.headers, body=response.body
        )
        if obstruction.state is not WafState.CLEAN:
            verdict.obstructed = True
            verdict.tier = FindingTier.NEEDS_REVIEW
            verdict.reason = (
                f"the host was {obstruction.state.value} during testing, so this "
                "result is not trustworthy; re-test when it is responsive"
            )
            return verdict

        # --- step 1: is it reflected at all? ------------------------------
        site = classify_reflection(response.text, canary)
        verdict.site = site
        if site.kind is ReflectionKind.NONE:
            verdict.reason = "the value is not reflected in the response"
            return verdict

        # Reflection must be reliable, not a one-off from a cache or a log view.
        async def reflection_probe(_index: int) -> tuple[bool, str | None]:
            fresh = f"rx{secrets.token_hex(5)}zz"
            again = await self._get(set_parameter(url, parameter, fresh))
            if again is None:
                return False, "request failed"
            return (fresh in again.text), None

        outcome = await reproduce(
            reflection_probe, attempts=self._attempts, required=self._required
        )
        verdict.reproduced = outcome.explain()
        if not outcome.stable:
            verdict.reason = f"reflection is not reliable: {outcome.explain()}"
            return verdict

        # --- step 2: do the characters needed to escape survive? ----------
        await self._probe_escaping(url, parameter, site)

        if not site.escapable:
            verdict.reason = (
                f"{site.describe()}, but "
                f"{', '.join(repr(c) for c in site.encoded_chars) or 'the required characters'} "
                "are encoded or stripped, so the reflection cannot break out of its "
                "context and is inert"
            )
            verdict.evidence.append(
                {"label": "inert reflection", "context": site.kind.value,
                 "snippet": site.snippet}
            )
            return verdict

        payload = site.payload_template.format(fn=MARKER_FUNCTION)
        payload_url = set_parameter(url, parameter, payload)
        verdict.evidence.append(
            {
                "label": "escapable reflection",
                "context": site.kind.value,
                "payload_url": payload_url,
                "snippet": site.snippet,
                "surviving_chars": list(site.surviving_chars),
            }
        )

        # --- step 3: does it actually execute? ----------------------------
        if self._headless_confirm:
            confirmed, detail, available = await self._confirm_execution(payload_url)
            verdict.dom_available = available
            verdict.dom_confirmed = confirmed
            if confirmed:
                verdict.tier = FindingTier.CONFIRMED
                verdict.confidence = 95
                verdict.reason = (
                    f"{site.describe()}, the characters needed to escape it survive, and "
                    f"the payload executed in a real browser ({detail})"
                )
                return verdict
            if available:
                verdict.tier = FindingTier.NEEDS_REVIEW
                verdict.confidence = 45
                verdict.reason = (
                    f"{site.describe()} and the escape characters survive, but the "
                    f"payload did not execute in a real browser ({detail}). Something "
                    "else is preventing it, such as a Content-Security-Policy"
                )
                return verdict

        verdict.tier = FindingTier.PROBABLE
        verdict.confidence = 70
        verdict.reason = (
            f"{site.describe()} and every character needed to escape that context "
            f"survives unencoded ({', '.join(repr(c) for c in site.surviving_chars)}). "
            "Execution was not confirmed because a headless browser is unavailable, so "
            "verify by hand before reporting"
        )
        return verdict

    # -- escape analysis ---------------------------------------------------

    async def _probe_escaping(self, url: str, parameter: str, site: ReflectionSite) -> None:
        """Send the characters that matter and record which come back intact."""
        if not site.required_chars:
            return

        marker = f"rx{secrets.token_hex(4)}"
        # Wrap each character in the marker so it can be located precisely even
        # if the page contains the character elsewhere.
        probe_value = marker + "".join(
            f"{character}{marker}" for character in site.required_chars
        )
        response = await self._get(set_parameter(url, parameter, probe_value))
        if response is None:
            return

        text = response.text
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
                    context = await browser.new_context(ignore_https_errors=True)
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

    # -- transport ---------------------------------------------------------

    async def _get(self, url: str):
        try:
            return await self._http.get(url)
        except Exception:
            return None
