"""The scope chokepoint.

Every DNS lookup and every HTTP request ReconX makes resolves through a
:class:`ScopeGuard`. The network layer in :mod:`reconx.net` takes a guard as a
required constructor argument, so there is no code path that reaches the
network without one.

Decision order is deliberate and not configurable:

1. If any out-of-scope rule matches, the target is **denied**. Out-of-scope
   always beats in-scope, so ``*.acme.com`` minus ``payments.acme.com``
   behaves the way a program means it.
2. Otherwise, if any in-scope rule matches, the target is **allowed**.
3. Otherwise the target is **denied**. Absence of a rule is never permission.

There is a fourth rule that applies only to an **authenticated** scan, and it sits
ahead of the other three: a path that changes state is denied. A logged-in crawler
is not a reader, it is something acting as the operator, and it will find
``/logout``, ``/settings/delete-account`` and ``/billing/cancel`` and follow them.
It lives here rather than in a stage so that every channel inherits it from the one
chokepoint, and it is off for unauthenticated scans, where a GET of ``/logout``
does nothing and hiding it would hide real surface.
"""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from reconx.scope.model import Scope, ScopeParseError, ScopeRule, normalize_host

__all__ = [
    "DESTRUCTIVE_PATH_MARKERS",
    "ScopeDecision",
    "ScopeGuard",
    "OutOfScopeError",
]

_MAX_BLOCKED_SAMPLES = 200

# Path substrings that name an action rather than a page. Refused while
# authenticated, because following one as the logged-in operator does the thing.
#
# Chosen to be specific enough not to swallow real surface: "delete" is here but
# "deleted" would also match, which is the intended trade -- a false refusal costs
# one endpoint, and a false permission costs the operator's account. Anything more
# aggressive belongs in a program's own `extra_forbidden_paths`.
DESTRUCTIVE_PATH_MARKERS: tuple[str, ...] = (
    # ending the session, which would silently turn the rest of the scan
    # unauthenticated -- the exact failure verify/session.py exists to catch
    "/logout",
    "/signout",
    "/sign-out",
    "/log-out",
    "/session/destroy",
    # destroying things
    "/delete",
    "/destroy",
    "/remove",
    "/purge",
    "/wipe",
    "/revoke",
    "/deactivate",
    "/close-account",
    "/cancel",
    "/unsubscribe",
    # credentials and identity, where a change locks the operator out
    "/change-password",
    "/reset-password",
    "/forgot-password",
    "/change-email",
    "/verify-email",
    "/2fa",
    "/mfa",
    "/api-keys",
    "/rotate",
    # money
    "/billing",
    "/payment",
    "/checkout",
    "/refund",
    "/payout",
    "/subscription",
    "/invoice",
    # reaching other people, which is the one mistake a program cannot undo
    "/invite",
    "/send",
    "/notify",
    "/broadcast",
    "/export",
    "/import",
)


@dataclass(frozen=True)
class ScopeDecision:
    """The result of a scope check, including why."""

    target: str
    allowed: bool
    reason: str
    matched_rule: str | None = None
    level: str = "host"

    def __bool__(self) -> bool:
        return self.allowed


class OutOfScopeError(RuntimeError):
    """Raised when something tried to touch a target outside the scope."""

    def __init__(self, decision: ScopeDecision) -> None:
        self.decision = decision
        super().__init__(
            f"refusing out-of-scope target {decision.target!r}: {decision.reason}"
        )


@dataclass
class GuardStats:
    """Counters for what the guard permitted and refused."""

    allowed: int = 0
    blocked: int = 0
    blocked_reasons: Counter = field(default_factory=Counter)
    blocked_samples: deque = field(default_factory=lambda: deque(maxlen=_MAX_BLOCKED_SAMPLES))

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "blocked": self.blocked,
            "blocked_reasons": dict(self.blocked_reasons),
            "blocked_samples": list(self.blocked_samples),
        }


class ScopeGuard:
    """Enforces a :class:`~reconx.scope.model.Scope`.

    Cheap to call: host decisions are memoized, so a tool emitting a hundred
    thousand candidate subdomains costs one decision per distinct host.
    """

    def __init__(self, scope: Scope, *, authenticated: bool = False) -> None:
        self._scope = scope
        self._host_cache: dict[str, ScopeDecision] = {}
        self.stats = GuardStats()
        # Authenticated scanning turns a crawler into something that can act as
        # the operator. The deny list below applies only in that state, because
        # unauthenticated GETs of /logout and /delete do nothing and excluding
        # them would hide real surface.
        self._authenticated = authenticated
        self._forbidden_paths = self._build_forbidden_paths(scope, authenticated)

    @staticmethod
    def _build_forbidden_paths(scope: Scope, authenticated: bool) -> tuple[str, ...]:
        auth = getattr(scope, "auth", None)
        if not authenticated or auth is None or not auth.avoid_state_changing_paths:
            return ()
        return tuple(
            sorted({*DESTRUCTIVE_PATH_MARKERS, *(m.lower() for m in auth.extra_forbidden_paths)})
        )

    @property
    def authenticated(self) -> bool:
        return self._authenticated

    @property
    def forbidden_paths(self) -> tuple[str, ...]:
        """Path substrings refused while authenticated. Empty when not."""
        return self._forbidden_paths

    # -- properties -------------------------------------------------------

    @property
    def scope(self) -> Scope:
        return self._scope

    @property
    def program(self) -> str:
        return self._scope.program

    # -- internals --------------------------------------------------------

    def _record(self, decision: ScopeDecision) -> ScopeDecision:
        if decision.allowed:
            self.stats.allowed += 1
        else:
            self.stats.blocked += 1
            self.stats.blocked_reasons[decision.reason] += 1
            self.stats.blocked_samples.append(decision.target)
        return decision

    @staticmethod
    def _host_scoped(rule: ScopeRule) -> bool:
        """True when a rule restricts a whole host rather than just a path."""
        return not (rule.kind == "url" and rule.path_prefix)

    # -- host-level decisions --------------------------------------------

    def decide_host(self, host: str) -> ScopeDecision:
        """Decide a bare host, for DNS resolution and port-level work.

        Path-restricted out-of-scope rules are not applied here: excluding
        ``https://acme.com/logout`` must not make ``acme.com`` unresolvable.
        """
        try:
            normalized = normalize_host(host)
        except ScopeParseError as exc:
            return self._record(
                ScopeDecision(str(host), False, f"unparseable host ({exc})", level="host")
            )

        cached = self._host_cache.get(normalized)
        if cached is not None:
            return self._record(cached)

        decision = self._decide_host_uncached(normalized)
        self._host_cache[normalized] = decision
        return self._record(decision)

    def _decide_host_uncached(self, host: str) -> ScopeDecision:
        for rule in self._scope.out_of_scope_rules:
            if self._host_scoped(rule) and rule.matches_host(host):
                return ScopeDecision(
                    host, False, "matched an out-of-scope rule", str(rule), "host"
                )
        for rule in self._scope.in_scope_rules:
            if rule.matches_host(host):
                return ScopeDecision(host, True, "matched an in-scope rule", str(rule), "host")
        return ScopeDecision(host, False, "no in-scope rule matches this host", None, "host")

    # -- url-level decisions ---------------------------------------------

    def decide_url(self, url: str) -> ScopeDecision:
        """Decide a full URL, enforcing path-restricted rules."""
        parts = urlsplit(url if "://" in url else f"http://{url}")
        if not parts.hostname:
            return self._record(
                ScopeDecision(url, False, "URL has no host", level="url")
            )
        try:
            host = normalize_host(parts.hostname)
        except ScopeParseError as exc:
            return self._record(
                ScopeDecision(url, False, f"unparseable host ({exc})", level="url")
            )
        path = parts.path or "/"

        # Checked before the in-scope rules, and alongside the out-of-scope ones,
        # because it is the same kind of statement: a place this scan must not go.
        # Only populated while authenticated.
        if self._forbidden_paths:
            lowered = path.lower()
            for marker in self._forbidden_paths:
                if marker in lowered:
                    return self._record(
                        ScopeDecision(
                            url,
                            False,
                            f"the path contains {marker!r}, which changes state, and "
                            "this scan is authenticated. Set "
                            "auth.avoid_state_changing_paths: false to test it",
                            f"authenticated deny: {marker}",
                            "url",
                        )
                    )

        for rule in self._scope.out_of_scope_rules:
            if rule.matches_url(host, path):
                return self._record(
                    ScopeDecision(url, False, "matched an out-of-scope rule", str(rule), "url")
                )
        for rule in self._scope.in_scope_rules:
            if rule.matches_url(host, path):
                return self._record(
                    ScopeDecision(url, True, "matched an in-scope rule", str(rule), "url")
                )
        return self._record(
            ScopeDecision(url, False, "no in-scope rule matches this URL", None, "url")
        )

    # -- convenience ------------------------------------------------------

    def decide(self, target: str) -> ScopeDecision:
        """Decide a target, treating anything with a scheme or path as a URL."""
        text = str(target).strip()
        if "://" in text:
            return self.decide_url(text)
        # A bare "host/path" is still a URL-shaped target.
        if "/" in text and not text.replace(".", "").replace(":", "").isdigit():
            head = text.split("/", 1)[0]
            if head:
                return self.decide_url(text)
        return self.decide_host(text)

    def is_in_scope(self, target: str) -> bool:
        return self.decide(target).allowed

    def assert_in_scope(self, target: str) -> ScopeDecision:
        """Return the decision, or raise :class:`OutOfScopeError`."""
        decision = self.decide(target)
        if not decision.allowed:
            raise OutOfScopeError(decision)
        return decision

    def filter_hosts(self, hosts: Iterable[str]) -> list[str]:
        """Keep only in-scope hosts, deduplicated, order preserved.

        This is the funnel for tool output. Passive sources routinely return
        unrelated domains; they get dropped here rather than scanned.
        """
        seen: set[str] = set()
        kept: list[str] = []
        for host in hosts:
            decision = self.decide_host(host)
            if decision.allowed and decision.target not in seen:
                seen.add(decision.target)
                kept.append(decision.target)
        return kept

    def filter_urls(self, urls: Iterable[str]) -> list[str]:
        """Keep only in-scope URLs, deduplicated, order preserved."""
        seen: set[str] = set()
        kept: list[str] = []
        for url in urls:
            if self.decide_url(url).allowed and url not in seen:
                seen.add(url)
                kept.append(url)
        return kept

    # -- limits -----------------------------------------------------------

    def effective_limit(self, name: str, default: float | int) -> float | int:
        """Program-declared limits win over global configuration."""
        value = getattr(self._scope.limits, name, None)
        return default if value is None else value

    def __repr__(self) -> str:  # pragma: no cover - display only
        return (
            f"ScopeGuard(program={self._scope.program!r}, "
            f"in_scope={len(self._scope.in_scope_rules)}, "
            f"out_of_scope={len(self._scope.out_of_scope_rules)})"
        )
