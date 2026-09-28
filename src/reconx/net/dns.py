"""Scope-enforcing DNS resolution, with wildcard detection.

Wildcard DNS is the single largest source of false positives in reconnaissance.
A zone with ``*.example.com`` answering everything makes a brute-force wordlist
look like tens of thousands of live subdomains, none of which exist.

:class:`ScopedResolver` handles it by profiling the zone first: it resolves
several random labels that cannot plausibly exist. If those answer, the zone is
a wildcard and the answers they return are recorded. A brute-forced name whose
answers are a subset of that recording is a **suspected wildcard artifact**, and
is only promoted to a real asset once its HTTP response fingerprint diverges
from the wildcard's (done by :mod:`reconx.stages.subdomains`).
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from reconx.config import Settings, get_settings
from reconx.net.ratelimit import TokenBucket
from reconx.scope.guard import ScopeGuard
from reconx.scope.model import ScopeParseError, normalize_host

__all__ = ["DnsAnswer", "WildcardProfile", "ScopedResolver", "RECORD_TYPES"]

RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

_PROBE_PREFIX = "reconx-wildcard-probe"


@dataclass(frozen=True)
class DnsAnswer:
    """The outcome of one DNS query."""

    host: str
    rdtype: str
    values: tuple[str, ...] = ()
    error: str | None = None
    out_of_scope: bool = False

    @property
    def resolved(self) -> bool:
        return bool(self.values)

    @property
    def value_set(self) -> frozenset[str]:
        return frozenset(self.values)

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "rdtype": self.rdtype,
            "values": list(self.values),
            "error": self.error,
            "out_of_scope": self.out_of_scope,
        }


@dataclass
class WildcardProfile:
    """What a zone does with names that should not exist."""

    domain: str
    probed: bool = False
    is_wildcard: bool = False
    values: frozenset[str] = frozenset()
    cnames: frozenset[str] = frozenset()
    probes: list[str] = field(default_factory=list)
    reason: str | None = None

    def covers(self, answer: DnsAnswer) -> bool:
        """True when this answer is explainable as a wildcard response.

        Requires the answer to be non-empty and entirely contained in what the
        wildcard returns. A name resolving to anything the wildcard does *not*
        return is a real, distinct host.
        """
        if not self.is_wildcard or not answer.values:
            return False
        return answer.value_set.issubset(self.values)

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "probed": self.probed,
            "is_wildcard": self.is_wildcard,
            "values": sorted(self.values),
            "cnames": sorted(self.cnames),
            "probes": list(self.probes),
            "reason": self.reason,
        }


class ScopedResolver:
    """Async DNS resolver that refuses to look up out-of-scope names.

    Takes a :class:`~reconx.scope.guard.ScopeGuard` as a **required** first
    argument, matching :class:`~reconx.net.http.ScopedHttpClient`.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        *,
        settings: Settings | None = None,
        nameservers: Sequence[str] | None = None,
        max_concurrent: int = 50,
        queries_per_second: float = 100.0,
    ) -> None:
        if not isinstance(guard, ScopeGuard):
            raise TypeError(
                "ScopedResolver requires a ScopeGuard: every lookup must be "
                "checked against an authorized scope."
            )
        self._guard = guard
        self._settings = settings or get_settings()

        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.timeout = self._settings.dns_timeout_seconds
        self._resolver.lifetime = self._settings.dns_timeout_seconds
        if nameservers:
            self._resolver.nameservers = list(nameservers)

        self._semaphore = asyncio.Semaphore(max(1, max_concurrent))
        self._bucket = TokenBucket(queries_per_second, capacity=max(1.0, queries_per_second / 4))
        self._wildcards: dict[str, WildcardProfile] = {}
        self.queries = 0
        self.blocked = 0

    @property
    def guard(self) -> ScopeGuard:
        return self._guard

    # -- single queries ---------------------------------------------------

    async def resolve(self, host: str, rdtype: str = "A") -> DnsAnswer:
        """Resolve one name, or explain why not."""
        try:
            normalized = normalize_host(host)
        except ScopeParseError as exc:
            return DnsAnswer(host=str(host), rdtype=rdtype, error=f"invalid host: {exc}")

        if not self._guard.decide_host(normalized).allowed:
            self.blocked += 1
            return DnsAnswer(
                host=normalized,
                rdtype=rdtype,
                error="out of scope",
                out_of_scope=True,
            )
        return await self._resolve_unchecked(normalized, rdtype)

    async def _resolve_unchecked(self, host: str, rdtype: str) -> DnsAnswer:
        async with self._semaphore:
            await self._bucket.acquire()
            self.queries += 1
            try:
                answer = await self._resolver.resolve(host, rdtype)
            except dns.resolver.NXDOMAIN:
                return DnsAnswer(host=host, rdtype=rdtype, error="NXDOMAIN")
            except dns.resolver.NoAnswer:
                return DnsAnswer(host=host, rdtype=rdtype, error="NoAnswer")
            except dns.resolver.NoNameservers as exc:
                return DnsAnswer(host=host, rdtype=rdtype, error=f"NoNameservers: {exc}")
            except dns.exception.Timeout:
                return DnsAnswer(host=host, rdtype=rdtype, error="timeout")
            except dns.exception.DNSException as exc:
                return DnsAnswer(host=host, rdtype=rdtype, error=f"{type(exc).__name__}: {exc}")

        values = tuple(sorted(rdata.to_text().strip('"').rstrip(".") for rdata in answer))
        return DnsAnswer(host=host, rdtype=rdtype, values=values)

    async def resolve_many(
        self, hosts: Iterable[str], rdtype: str = "A"
    ) -> list[DnsAnswer]:
        """Resolve many names concurrently, bounded by the configured limits."""
        targets = list(hosts)
        if not targets:
            return []
        return list(await asyncio.gather(*(self.resolve(h, rdtype) for h in targets)))

    async def records(
        self, host: str, rdtypes: Sequence[str] = RECORD_TYPES
    ) -> dict[str, DnsAnswer]:
        """Collect a full record set for one host, for information gathering."""
        answers = await asyncio.gather(*(self.resolve(host, rt) for rt in rdtypes))
        return {answer.rdtype: answer for answer in answers}

    # -- wildcard profiling ----------------------------------------------

    async def profile_wildcard(
        self, domain: str, *, probes: int | None = None, refresh: bool = False
    ) -> WildcardProfile:
        """Determine whether ``domain`` answers names that cannot exist.

        Results are cached per domain, since a zone's wildcard behaviour does
        not change mid-scan.
        """
        try:
            base = normalize_host(domain)
        except ScopeParseError as exc:
            return WildcardProfile(domain=str(domain), reason=f"invalid domain: {exc}")

        if not refresh and base in self._wildcards:
            return self._wildcards[base]

        count = probes if probes is not None else self._settings.wildcard_probe_count
        labels = [
            f"{_PROBE_PREFIX}-{secrets.token_hex(6)}.{base}" for _ in range(max(1, count))
        ]

        # The probes must themselves be in scope; a wildcard zone is only
        # meaningful for a scope that covers its subdomains.
        in_scope = [label for label in labels if self._guard.decide_host(label).allowed]
        if not in_scope:
            profile = WildcardProfile(
                domain=base,
                reason=(
                    "wildcard probing skipped: random subdomains of this domain are "
                    "not in scope, so the zone cannot be profiled"
                ),
            )
            self._wildcards[base] = profile
            return profile

        a_answers = await asyncio.gather(
            *(self._resolve_unchecked(label, "A") for label in in_scope)
        )
        cname_answers = await asyncio.gather(
            *(self._resolve_unchecked(label, "CNAME") for label in in_scope)
        )

        values: set[str] = set()
        cnames: set[str] = set()
        for answer in a_answers:
            values.update(answer.values)
        for answer in cname_answers:
            cnames.update(answer.values)
            values.update(answer.values)

        profile = WildcardProfile(
            domain=base,
            probed=True,
            is_wildcard=bool(values),
            values=frozenset(values),
            cnames=frozenset(cnames),
            probes=in_scope,
            reason=(
                None
                if values
                else "random labels did not resolve, so this zone is not a wildcard"
            ),
        )
        self._wildcards[base] = profile
        return profile

    def cached_wildcard(self, domain: str) -> WildcardProfile | None:
        try:
            return self._wildcards.get(normalize_host(domain))
        except ScopeParseError:
            return None

    async def wildcard_for_host(self, host: str) -> WildcardProfile | None:
        """Profile the immediate parent zone of ``host``.

        Multi-level wildcards are common (``*.dev.example.com``), so the parent
        of the candidate is what matters, not the registrable root.
        """
        try:
            normalized = normalize_host(host)
        except ScopeParseError:
            return None
        parent = normalized.partition(".")[2]
        if not parent or "." not in parent:
            return None
        return await self.profile_wildcard(parent)

    def stats(self) -> dict:
        return {
            "queries": self.queries,
            "blocked_out_of_scope": self.blocked,
            "wildcard_zones": {
                domain: profile.is_wildcard for domain, profile in self._wildcards.items()
            },
        }
