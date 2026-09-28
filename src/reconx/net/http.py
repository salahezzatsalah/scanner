"""The only HTTP client ReconX uses.

:class:`ScopedHttpClient` takes a :class:`~reconx.scope.guard.ScopeGuard` as a
**required** first argument. There is deliberately no way to construct one
without a guard, which is what makes "nothing reaches the network unchecked" a
structural property rather than a convention.

Three behaviours are worth calling out:

* **Redirects are re-checked at every hop.** A 302 to an out-of-scope host is
  not followed, because otherwise a target could walk the scanner off-scope.
* **Distress is respected.** 429/503 and transport errors put the host in the
  penalty box via :class:`~reconx.net.ratelimit.HostRateLimiter`, honouring
  ``Retry-After`` when present.
* **Every request is audited.** The audit trail is what lets a researcher show
  precisely what they touched and when.
* **A session can be contained.** A check that authenticates would otherwise
  leave its cookies in the shared jar and silently authenticate the rest of the
  scan; :meth:`ScopedHttpClient.isolated_cookies` scopes them to the check.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from reconx.config import Settings, get_settings
from reconx.net.fingerprint import ResponseFingerprint, fingerprint_response
from reconx.net.ratelimit import HostRateLimiter
from reconx.scope.guard import OutOfScopeError, ScopeDecision, ScopeGuard

__all__ = [
    "AuditRecord",
    "ScopedResponse",
    "ScopedHttpClient",
    "RequestBudgetExceeded",
]

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_DISTRESS_STATUSES = {429, 502, 503, 504, 507, 509}
_MAX_AUDIT_IN_MEMORY = 10_000


class RequestBudgetExceeded(RuntimeError):
    """The scan hit the request budget declared in the scope."""


@dataclass(frozen=True)
class AuditRecord:
    """One line of the audit trail."""

    timestamp: datetime
    method: str
    url: str
    host: str
    status: int | None
    duration_ms: float
    response_bytes: int
    error: str | None = None
    matched_rule: str | None = None
    attempt: int = 1
    blocked: bool = False
    block_reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "status": self.status,
            "duration_ms": round(self.duration_ms, 2),
            "response_bytes": self.response_bytes,
            "error": self.error,
            "matched_rule": self.matched_rule,
            "attempt": self.attempt,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
        }


@dataclass
class ScopedResponse:
    """An HTTP response plus what ReconX needs to reason about it."""

    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    fingerprint: ResponseFingerprint
    redirect_chain: list[tuple[int, str]] = field(default_factory=list)
    redirect_stopped_reason: str | None = None
    throttled_host: bool = False
    tls_error: str | None = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    def header(self, name: str, default: str = "") -> str:
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return default


class ScopedHttpClient:
    """Scope-enforcing, rate-limited, audited async HTTP client."""

    def __init__(
        self,
        guard: ScopeGuard,
        *,
        settings: Settings | None = None,
        limiter: HostRateLimiter | None = None,
        audit_sink: Callable[[AuditRecord], Any] | None = None,
        max_redirects: int = 5,
        request_budget: int | None = None,
        verify_target_tls: bool = False,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not isinstance(guard, ScopeGuard):
            raise TypeError(
                "ScopedHttpClient requires a ScopeGuard: every request must be "
                "checked against an authorized scope."
            )
        self._guard = guard
        self._settings = settings or get_settings()
        self._max_redirects = max(0, max_redirects)
        self._audit_sink = audit_sink
        self._audit: deque[AuditRecord] = deque(maxlen=_MAX_AUDIT_IN_MEMORY)

        limits = guard.scope.limits
        self._budget = request_budget if request_budget is not None else limits.max_requests_per_scan
        self._requests_made = 0
        # Requests made on our behalf by an external tool. Tracked separately so
        # "requests made" stays a true statement about this client.
        self._external_requests = 0

        rate = guard.effective_limit(
            "requests_per_second_per_host", self._settings.requests_per_second_per_host
        )
        concurrent = guard.effective_limit(
            "max_concurrent_requests", self._settings.max_concurrent_requests
        )
        self._limiter = limiter or HostRateLimiter(
            rate_per_host=float(rate),
            max_concurrent_requests=int(concurrent),
        )

        # TLS verification is off for *target* traffic by default. Scanning
        # hosts with expired or self-signed certificates is routine, and a
        # broken certificate is something to record as an observation rather
        # than a reason to refuse to look. Set verify_target_tls=True to
        # require valid certificates.
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            verify=verify_target_tls,
            timeout=httpx.Timeout(self._settings.http_timeout_seconds),
            follow_redirects=False,  # handled manually so scope is re-checked
            headers={"User-Agent": self._settings.user_agent},
            http2=True,
            # trust_env is left on so a researcher can route traffic through
            # an intercepting proxy such as Burp via HTTPS_PROXY.
            trust_env=True,
        )

    # -- lifecycle --------------------------------------------------------

    async def __aenter__(self) -> ScopedHttpClient:
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- properties -------------------------------------------------------

    @property
    def guard(self) -> ScopeGuard:
        return self._guard

    @property
    def limiter(self) -> HostRateLimiter:
        return self._limiter

    @property
    def requests_made(self) -> int:
        """Requests this client sent itself."""
        return self._requests_made

    @property
    def cookies(self) -> dict[str, str]:
        """A snapshot of the cookie jar, so a check can see what a response set."""
        return dict(self._client.cookies)

    @property
    def external_requests(self) -> int:
        """Requests external tools sent on our behalf."""
        return self._external_requests

    @property
    def total_requests(self) -> int:
        return self._requests_made + self._external_requests

    def audit_records(self) -> list[AuditRecord]:
        return list(self._audit)

    # -- sessions ---------------------------------------------------------

    @contextmanager
    def isolated_cookies(self) -> Iterator[None]:
        """Contain any cookies a block picks up, then restore the jar.

        A check that registers or logs in receives a session cookie, and the
        underlying client keeps cookies for the rest of its life. Without this,
        one authentication would quietly authenticate every later request in the
        scan: baselines would be learned as a logged-in user, and "this page is
        reachable" would stop meaning what it says.

        The jar is per-client rather than per-task, so this *contains* a session
        rather than partitioning one. Use it around a single check at a time.
        """
        saved = httpx.Cookies(self._client.cookies)
        try:
            yield
        finally:
            self._client.cookies = saved

    # -- audit ------------------------------------------------------------

    def _audit_record(self, record: AuditRecord) -> None:
        self._audit.append(record)
        if self._audit_sink is not None:
            self._audit_sink(record)

    def record_external_request(
        self,
        *,
        method: str,
        url: str,
        host: str,
        status: int | None = None,
        duration_ms: float = 0.0,
        response_bytes: int = 0,
        via: str = "external tool",
    ) -> None:
        """Fold a request made by an external tool into the audit trail.

        ReconX delegates some probing to tools like httpx that make their own
        requests. Recording them here keeps one complete record of everything
        that was touched, which is the point of the audit trail.
        """
        self._external_requests += 1
        self._audit_record(
            AuditRecord(
                timestamp=datetime.now(UTC),
                method=method,
                url=url,
                host=host,
                status=status,
                duration_ms=duration_ms,
                response_bytes=response_bytes,
                matched_rule=f"via {via}",
            )
        )

    # -- core -------------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        content: bytes | str | None = None,
        data: Mapping[str, Any] | None = None,
        json: Any = None,
        cookies: Mapping[str, str] | None = None,
        follow_redirects: bool = True,
        read_body: bool = True,
        max_body_bytes: int = 2_000_000,
    ) -> ScopedResponse:
        """Perform a request, enforcing scope on the target and every redirect."""
        current_method = method.upper()
        current_url = url
        chain: list[tuple[int, str]] = []
        stopped_reason: str | None = None
        last_response: ScopedResponse | None = None

        for hop in range(self._max_redirects + 1):
            decision = self._guard.decide_url(current_url)
            if not decision.allowed:
                if hop == 0:
                    self._audit_record(
                        AuditRecord(
                            timestamp=datetime.now(UTC),
                            method=current_method,
                            url=current_url,
                            host=urlsplit(current_url).hostname or "",
                            status=None,
                            duration_ms=0.0,
                            response_bytes=0,
                            blocked=True,
                            block_reason=decision.reason,
                        )
                    )
                    raise OutOfScopeError(decision)
                # A target tried to redirect us off-scope. Stop here and say so.
                stopped_reason = (
                    f"redirect to out-of-scope target {current_url!r} was not followed "
                    f"({decision.reason})"
                )
                self._audit_record(
                    AuditRecord(
                        timestamp=datetime.now(UTC),
                        method=current_method,
                        url=current_url,
                        host=urlsplit(current_url).hostname or "",
                        status=None,
                        duration_ms=0.0,
                        response_bytes=0,
                        blocked=True,
                        block_reason=stopped_reason,
                    )
                )
                break

            response = await self._send_with_retries(
                current_method,
                current_url,
                decision=decision,
                headers=headers,
                params=params,
                content=content,
                data=data,
                json=json,
                cookies=cookies,
                read_body=read_body,
                max_body_bytes=max_body_bytes,
            )
            response.redirect_chain = list(chain)

            location = response.header("location")
            if not (follow_redirects and response.status in _REDIRECT_STATUSES and location):
                response.redirect_stopped_reason = stopped_reason
                return response

            if hop == self._max_redirects:
                response.redirect_stopped_reason = (
                    f"redirect limit of {self._max_redirects} reached"
                )
                return response

            chain.append((response.status, current_url))
            next_url = urljoin(current_url, location)
            # 303, and 301/302 in practice, turn a non-GET into a GET.
            if response.status == 303 or (
                response.status in {301, 302} and current_method not in {"GET", "HEAD"}
            ):
                current_method = "GET"
                content = data = json = None
            current_url = next_url
            last_response = response

        # Fell out of the loop because a redirect left the scope. The break
        # can only be reached after at least one response was received.
        if last_response is None:  # pragma: no cover - defensive
            raise RuntimeError(f"no response was obtained for {url!r}")
        last_response.redirect_stopped_reason = stopped_reason
        last_response.redirect_chain = list(chain)
        return last_response

    async def _send_with_retries(
        self,
        method: str,
        url: str,
        *,
        decision: ScopeDecision,
        headers: Mapping[str, str] | None,
        params: Mapping[str, Any] | None,
        content: bytes | str | None,
        data: Mapping[str, Any] | None,
        json: Any,
        cookies: Mapping[str, str] | None = None,
        read_body: bool = True,
        max_body_bytes: int = 2_000_000,
    ) -> ScopedResponse:
        host = urlsplit(url).hostname or ""
        attempts = self._settings.max_retries + 1
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            if self._budget is not None and self._requests_made >= self._budget:
                raise RequestBudgetExceeded(
                    f"scan request budget of {self._budget} reached "
                    f"(max_requests_per_scan in the scope file)"
                )

            was_throttled = self._limiter.is_throttled(host)
            started = time.monotonic()
            try:
                async with self._limiter.slot(host):
                    self._requests_made += 1
                    raw = await self._client.request(
                        method,
                        url,
                        headers=dict(headers) if headers else None,
                        params=dict(params) if params else None,
                        content=content,
                        data=dict(data) if data else None,
                        json=json,
                        cookies=dict(cookies) if cookies else None,
                    )
                    body = b""
                    if read_body:
                        body = raw.content[:max_body_bytes]
                elapsed_ms = (time.monotonic() - started) * 1000

                response_headers = dict(raw.headers)
                scoped = ScopedResponse(
                    url=str(raw.request.url),
                    status=raw.status_code,
                    headers=response_headers,
                    body=body,
                    elapsed_ms=elapsed_ms,
                    fingerprint=fingerprint_response(
                        status=raw.status_code, body=body, headers=response_headers
                    ),
                    throttled_host=was_throttled,
                )

                self._audit_record(
                    AuditRecord(
                        timestamp=datetime.now(UTC),
                        method=method,
                        url=url,
                        host=host,
                        status=raw.status_code,
                        duration_ms=elapsed_ms,
                        response_bytes=len(body),
                        matched_rule=decision.matched_rule,
                        attempt=attempt,
                    )
                )

                if raw.status_code in _DISTRESS_STATUSES:
                    self._handle_distress(host, scoped)
                else:
                    self._limiter.note_success(host)
                return scoped

            except (httpx.TransportError, httpx.HTTPError) as exc:
                elapsed_ms = (time.monotonic() - started) * 1000
                last_error = exc
                self._audit_record(
                    AuditRecord(
                        timestamp=datetime.now(UTC),
                        method=method,
                        url=url,
                        host=host,
                        status=None,
                        duration_ms=elapsed_ms,
                        response_bytes=0,
                        error=f"{type(exc).__name__}: {exc}",
                        matched_rule=decision.matched_rule,
                        attempt=attempt,
                    )
                )
                errors = self._limiter.note_error(host)
                if errors >= 3:
                    self._limiter.penalize(host, 2.0, signal="repeated transport errors")
                if attempt < attempts:
                    await asyncio.sleep(min(2 ** (attempt - 1) * 0.5, 8.0))

        raise httpx.TransportError(
            f"{method} {url} failed after {attempts} attempts: {last_error}"
        ) from last_error

    def _handle_distress(self, host: str, response: ScopedResponse) -> None:
        """Back off when a host signals it has had enough."""
        retry_after = response.header("retry-after")
        seconds = 5.0
        if retry_after:
            try:
                seconds = max(1.0, float(int(retry_after)))
            except ValueError:
                seconds = 30.0  # HTTP-date form; be generous rather than clever
        self._limiter.penalize(host, seconds, signal=f"HTTP {response.status}")
        response.throttled_host = True

    # -- convenience ------------------------------------------------------

    async def get(self, url: str, **kwargs) -> ScopedResponse:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs) -> ScopedResponse:
        kwargs.setdefault("read_body", False)
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs) -> ScopedResponse:
        return await self.request("POST", url, **kwargs)

    async def get_many(
        self, urls: Iterable[str], *, ignore_errors: bool = True, **kwargs
    ) -> list[ScopedResponse]:
        """Fetch many URLs concurrently. Out-of-scope URLs are skipped, not raised."""
        targets = self._guard.filter_urls(urls)

        async def one(target: str) -> ScopedResponse | None:
            try:
                return await self.get(target, **kwargs)
            except Exception:
                if ignore_errors:
                    return None
                raise

        results = await asyncio.gather(*(one(u) for u in targets))
        return [r for r in results if r is not None]
