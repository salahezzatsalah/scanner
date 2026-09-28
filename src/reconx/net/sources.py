"""Public intelligence sources.

Passive reconnaissance asks third parties *about* a target: certificate
transparency logs, registry RDAP data, web archives, passive DNS. Those
services are not in the program's scope and must not be, so they cannot go
through :class:`~reconx.net.http.ScopedHttpClient`.

They are not unrestricted either. :class:`SourceClient` can reach **only** the
hosts in :data:`SOURCE_ALLOWLIST`, which is defined in code rather than
configuration precisely so a target host can never be added to it at runtime.
The result is two separate, separately-constrained channels:

* target traffic — gated by the program scope,
* source traffic — gated by a fixed allowlist of read-only data services.

Everything a source *returns* is funnelled back through the program
:class:`~reconx.scope.guard.ScopeGuard` before it is scanned, so out-of-scope
names that a source volunteers are dropped rather than probed.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

import httpx

from reconx.config import Settings, get_settings
from reconx.net.ratelimit import HostRateLimiter

__all__ = [
    "SOURCE_ALLOWLIST",
    "SourceClient",
    "SourceNotAllowed",
    "SourceResponse",
    "SourceUnavailable",
]


class SourceNotAllowed(RuntimeError):
    """An attempt to use SourceClient for a host that is not a known data source."""


class SourceUnavailable(RuntimeError):
    """A source failed. Never fatal: passive recon degrades source by source."""


# Read-only public data services. Code-defined on purpose: making this
# configurable would let a target be reclassified as a "source" and bypass the
# scope guard entirely.
SOURCE_ALLOWLIST: MappingProxyType[str, str] = MappingProxyType(
    {
        "crt.sh": "certificate transparency log search",
        "api.certspotter.com": "certificate transparency (Cert Spotter)",
        "web.archive.org": "Wayback Machine URL archive",
        "index.commoncrawl.org": "Common Crawl URL index",
        "urlscan.io": "URLScan submitted-scan search",
        "otx.alienvault.com": "AlienVault OTX passive DNS",
        "rdap.org": "RDAP registration data (domains and IPs)",
        "rdap.arin.net": "ARIN RDAP",
        "rdap.db.ripe.net": "RIPE RDAP",
        "dns.google": "Google DNS-over-HTTPS",
        "cloudflare-dns.com": "Cloudflare DNS-over-HTTPS",
        # These require an API key and are skipped when none is configured.
        "api.securitytrails.com": "SecurityTrails (API key required)",
        "www.virustotal.com": "VirusTotal (API key required)",
        "api.shodan.io": "Shodan (API key required)",
        "api.github.com": "GitHub code search (token required)",
    }
)


@dataclass
class SourceResponse:
    """A response from an intelligence source."""

    source: str
    url: str
    status: int
    body: bytes

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        import json

        return json.loads(self.body)


class SourceClient:
    """HTTP client restricted to :data:`SOURCE_ALLOWLIST`.

    Deliberately polite: these are free services that reconnaissance tooling
    routinely overloads, so the default rate is low and a failure degrades the
    stage rather than failing it.
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        requests_per_second: float = 2.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._limiter = HostRateLimiter(
            rate_per_host=requests_per_second,
            max_concurrent_requests=8,
            max_concurrent_per_host=2,
        )
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
            headers={"User-Agent": self._settings.user_agent},
            trust_env=True,
        )
        self.calls = 0
        self.failures: dict[str, str] = {}

    async def __aenter__(self) -> SourceClient:
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- allowlist --------------------------------------------------------

    @staticmethod
    def is_allowed(url: str) -> bool:
        host = urlsplit(url).hostname or ""
        return host.lower() in SOURCE_ALLOWLIST

    @staticmethod
    def _assert_allowed(url: str) -> str:
        host = (urlsplit(url).hostname or "").lower()
        if host not in SOURCE_ALLOWLIST:
            raise SourceNotAllowed(
                f"{host or url!r} is not a known intelligence source. SourceClient "
                "may only reach the fixed allowlist in reconx.net.sources; target "
                "traffic belongs on ScopedHttpClient, which enforces the program scope."
            )
        return host

    # -- requests ---------------------------------------------------------

    async def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        source: str | None = None,
    ) -> SourceResponse:
        """Fetch from an allowlisted source. Raises :class:`SourceNotAllowed` otherwise."""
        host = self._assert_allowed(url)
        label = source or host

        async with self._limiter.slot(host):
            self.calls += 1
            try:
                response = await self._client.get(url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                self.failures[label] = f"{type(exc).__name__}: {exc}"
                raise SourceUnavailable(f"{label} unreachable: {exc}") from exc

        if response.status_code == 429:
            self._limiter.penalize(host, 30.0, signal="HTTP 429")
        if response.status_code >= 400:
            self.failures[label] = f"HTTP {response.status_code}"

        return SourceResponse(
            source=label,
            url=str(response.url),
            status=response.status_code,
            body=response.content,
        )

    async def try_get(
        self, url: str, *, params: dict[str, Any] | None = None, **kwargs
    ) -> SourceResponse | None:
        """Fetch, returning None on any failure.

        Passive recon should survive a source being down or rate-limiting. Use
        this for optional sources and report the gap rather than aborting.
        """
        try:
            response = await self.get(url, params=params, **kwargs)
        except (TimeoutError, SourceUnavailable):
            return None
        except SourceNotAllowed:
            raise
        return response if response.ok else None

    def stats(self) -> dict:
        return {"calls": self.calls, "failures": dict(self.failures)}
