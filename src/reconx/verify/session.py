"""Knowing whether the scan is still logged in.

This module exists because of the worst failure an authenticated scanner can
have, and it is a silent one. A session expires forty minutes into a scan. Every
request after that gets the logged-out version of the application. Every verifier
finds no signal. The run completes, reports nothing, and looks exactly like a
clean scan of a well-built site.

There is no error to notice. The tool would be confidently wrong about the part
of the application the operator most wanted checked, and nothing in the output
would say so.

The fix is the same shape as :mod:`reconx.verify.waf`, which solves the same
problem for a host that starts blocking: decide explicitly, and treat work done
in that state as provisional rather than as a result.

Two mechanisms, because they catch different things:

* :class:`SessionMonitor` is authoritative. It fetches a URL the operator named
  and requires text that only appears while signed in. Run at stage boundaries.
* :func:`looks_logged_out` is a cheap per-response heuristic, so a verifier can
  stop mid-check instead of spending twenty requests establishing that a login
  page is not vulnerable.

Neither ever logs the credential, and the check URL is validated against the
scope when the scope loads, so a session check cannot reach a third party.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from reconx.scope.model import AuthConfig

__all__ = [
    "SessionState",
    "SessionVerdict",
    "SessionMonitor",
    "looks_logged_out",
]


class SessionState(StrEnum):
    NOT_CONFIGURED = "not_configured"  # no auth block, or no credential in the env
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"
    UNKNOWN = "unknown"  # the check itself could not be completed


# Markers of a logged-out page. Used only to corroborate an absent session
# marker, never on their own: plenty of signed-in pages carry a login widget in
# a navigation bar, and a password field on a change-password form is normal.
_LOGIN_FORM = re.compile(
    r"<input[^>]+type=[\"']?password|name=[\"']?(?:password|passwd|pwd)[\"']?",
    re.IGNORECASE,
)
_LOGIN_PATH = re.compile(
    r"/(?:login|signin|sign-in|log-in|auth|session|account/login|sso)\b",
    re.IGNORECASE,
)
_LOGGED_OUT_TEXT = re.compile(
    r"(?:please (?:log|sign) ?in|you (?:must|need to) (?:log|sign) ?in|"
    r"session (?:has )?expired|your session timed out|login required)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SessionVerdict:
    """What the last check concluded about the session."""

    state: SessionState
    signal: str | None = None
    checked_at: datetime | None = None

    @property
    def active(self) -> bool:
        return self.state is SessionState.AUTHENTICATED

    @property
    def obstructed(self) -> bool:
        """True when results gathered now cannot be trusted.

        ``UNKNOWN`` counts. A check that could not be completed is exactly the
        case where a dead session goes unnoticed, so the conservative reading is
        the safe one: report it rather than assume the session held.
        """
        return self.state in {SessionState.EXPIRED, SessionState.UNKNOWN}

    def explain(self) -> str:
        if self.state is SessionState.AUTHENTICATED:
            return f"the session was valid ({self.signal or 'marker present'})"
        if self.state is SessionState.EXPIRED:
            return (
                "the session expired during the scan, so anything measured after the "
                f"last good check is unreliable ({self.signal or 'marker absent'}). "
                "Refresh the credential and re-run"
            )
        if self.state is SessionState.UNKNOWN:
            return (
                "the session could not be verified, so it is not known whether these "
                f"results were gathered while signed in ({self.signal or 'check failed'})"
            )
        return "no session is configured; this was an unauthenticated scan"

    def as_dict(self) -> dict:
        return {
            "state": self.state.value,
            "signal": self.signal,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


def looks_logged_out(body: str, *, marker: str, status: int = 200, location: str = "") -> str | None:
    """A cheap per-response guess at whether the session has gone.

    Returns the reason when the response looks logged out, else None.

    Deliberately conservative, and it requires the *absence of the operator's
    marker* before considering anything else. Guessing from a login form alone
    would fire on every homepage with a sign-in box, and a scanner that keeps
    announcing a dead session it does not have is one whose warnings get ignored.
    """
    if marker and marker in body:
        return None

    if status in {301, 302, 303, 307, 308} and location and _LOGIN_PATH.search(location):
        return f"redirected to {location}, which looks like a login page"
    if status == 401:
        return "HTTP 401, and the signed-in marker is absent"

    window = body[:40_000]
    if _LOGGED_OUT_TEXT.search(window):
        match = _LOGGED_OUT_TEXT.search(window)
        return f"the page says {match.group(0)!r} and the signed-in marker is absent"
    if _LOGIN_FORM.search(window) and status == 200:
        return "a password field is present and the signed-in marker is absent"
    return None


@dataclass
class SessionMonitor:
    """Checks, and re-checks, that the scan is still signed in.

    Holds the credential in memory for the duration of a scan and never writes it
    anywhere. :meth:`headers` is the only way it leaves, and
    :class:`~reconx.net.http.ScopedHttpClient` sends those only to hosts the guard
    has already allowed.
    """

    auth: AuthConfig | None = None
    credential: str = field(default="", repr=False)
    verdict: SessionVerdict = field(
        default_factory=lambda: SessionVerdict(SessionState.NOT_CONFIGURED)
    )
    checks: int = 0
    expiries: int = 0

    def __repr__(self) -> str:  # pragma: no cover - keeps the secret out of logs
        state = self.verdict.state.value
        return f"SessionMonitor(configured={self.configured}, state={state!r})"

    @classmethod
    def from_scope(cls, scope, environ=None) -> SessionMonitor:
        """Build from a scope, resolving the credential out of the environment."""
        auth = getattr(scope, "auth", None)
        if auth is None:
            return cls()
        return cls(auth=auth, credential=auth.resolve_credential(environ))

    # -- state -------------------------------------------------------------

    @property
    def configured(self) -> bool:
        """An auth block exists and the credential was found in the environment."""
        return self.auth is not None and bool(self.credential)

    @property
    def marker(self) -> str:
        return self.auth.session_check_marker if self.auth else ""

    def headers(self) -> dict[str, str]:
        """The headers carrying the session, or nothing when unconfigured."""
        if not self.configured:
            return {}
        return self.auth.headers(self.credential)  # type: ignore[union-attr]

    def redactions(self) -> tuple[str, ...]:
        """Strings that must never appear in stored evidence or a report."""
        if not self.credential:
            return ()
        values = {self.credential}
        # A cookie header is often "a=1; session=SECRET; b=2", so the individual
        # values matter too: redacting only the whole header would leak the token
        # anywhere a single cookie was recorded.
        for part in self.credential.split(";"):
            _, _, value = part.partition("=")
            candidate = value.strip()
            if len(candidate) >= 8:
                values.add(candidate)
        return tuple(sorted(values, key=len, reverse=True))

    # -- checking ----------------------------------------------------------

    async def check(self, http) -> SessionVerdict:
        """Fetch the check URL and decide. Retries once before giving up.

        The retry matters: a single transport blip would otherwise read as
        ``UNKNOWN`` and poison a whole stage's results as untrustworthy.
        """
        if not self.configured:
            self.verdict = SessionVerdict(SessionState.NOT_CONFIGURED)
            return self.verdict

        assert self.auth is not None
        last_error = ""
        # The retry covers a failed *request* only. A response that arrives
        # without the marker is an answer, not a blip, so it decides immediately.
        for _attempt in range(2):
            try:
                response = await http.get(self.auth.session_check_url)
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                continue

            self.checks += 1
            now = datetime.now(UTC)
            body = response.text

            if self.marker in body:
                self.verdict = SessionVerdict(
                    SessionState.AUTHENTICATED,
                    signal=f"{self.marker!r} present at {self.auth.session_check_url}",
                    checked_at=now,
                )
                return self.verdict

            reason = looks_logged_out(
                body,
                marker=self.marker,
                status=response.status,
                location=response.header("location"),
            )
            self.expiries += 1
            self.verdict = SessionVerdict(
                SessionState.EXPIRED,
                signal=reason
                or (
                    f"{self.marker!r} is absent from {self.auth.session_check_url} "
                    f"(HTTP {response.status})"
                ),
                checked_at=now,
            )
            return self.verdict

        self.verdict = SessionVerdict(
            SessionState.UNKNOWN,
            signal=f"the check request failed: {last_error}",
            checked_at=datetime.now(UTC),
        )
        return self.verdict

    def note_response(self, *, body: str, status: int, location: str = "") -> str | None:
        """Per-response check, for a verifier that should stop now.

        Does not change :attr:`verdict`: only :meth:`check` is authoritative, and
        one page that happens to lack the marker is not proof the session died.
        """
        if not self.configured:
            return None
        return looks_logged_out(body, marker=self.marker, status=status, location=location)

    def summary(self) -> dict:
        return {
            "configured": self.configured,
            "checks": self.checks,
            "expiries": self.expiries,
            **self.verdict.as_dict(),
        }
