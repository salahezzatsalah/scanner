"""Subdomain enumeration for wildcard programs.

Enumeration is the easy half. The hard half is deciding which of the results are
real, and that is where most reconnaissance tooling fails: a zone answering
``*.example.com`` makes every word in a wordlist look like a live host.

The verdict pipeline here is:

1. Gather candidates from passive sources (subfinder, certificate transparency,
   passive DNS) and, optionally, active brute force and permutations.
2. Funnel every candidate through the program scope. Passive sources routinely
   volunteer unrelated domains; they are dropped, not scanned.
3. Resolve what survives, and profile the wildcard behaviour of each distinct
   parent zone — not just the registrable root, because ``*.dev.example.com``
   is common.
4. A name whose answers are entirely explained by the wildcard is a *suspect*,
   not an asset. It is only promoted if its HTTP response fingerprint diverges
   from what the wildcard itself serves.
5. Suspects backed by passive evidence (a name in a certificate log really was
   issued) are always divergence-checked. Brute-force-only suspects are checked
   up to a budget, because a wildcard zone can produce more of them than it is
   polite to probe.

Everything dropped is counted by reason, so the stage can report "12,000 in,
41 out, 11,890 wildcard artifacts" rather than asking to be trusted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from reconx.db.models import AssetKind, BaselineKind
from reconx.db.store import save_baseline, upsert_asset
from reconx.net.dns import DnsAnswer, WildcardProfile
from reconx.net.fingerprint import ResponseFingerprint
from reconx.stages.base import Stage, StageContext, StageResult
from reconx.stages.wordlists import (
    COMMON_SUBDOMAIN_LABELS,
    PERMUTATION_AFFIXES,
    load_wordlist,
)
from reconx.tools.base import ToolNotAvailable

__all__ = ["SubdomainStage"]

_CRTSH = "https://crt.sh/"
_CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
_OTX = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

# Sources whose results carry independent evidence that a name existed.
_EVIDENCE_SOURCES = frozenset(
    {"crt.sh", "certspotter", "otx", "subfinder", "amass", "passive_recon:dns"}
)


@dataclass
class _Candidates:
    """Candidate hosts and which sources proposed each one."""

    by_host: dict[str, list[str]] = field(default_factory=dict)

    def add(self, host: str, source: str) -> None:
        normalized = host.strip().lower().rstrip(".").lstrip("*.")
        if not normalized or " " in normalized or "/" in normalized:
            return
        sources = self.by_host.setdefault(normalized, [])
        if source not in sources:
            sources.append(source)

    def add_many(self, hosts, source: str) -> None:
        for host in hosts:
            self.add(host, source)

    def has_evidence(self, host: str) -> bool:
        """True when at least one source for this host is evidence-backed."""
        return any(src in _EVIDENCE_SOURCES for src in self.by_host.get(host, []))

    def __len__(self) -> int:
        return len(self.by_host)


class SubdomainStage(Stage):
    name = "subdomains"
    description = "Passive and active subdomain enumeration with wildcard filtering"
    requires = ()
    active = True  # brute force sends DNS queries the target did not invite

    def __init__(
        self,
        *,
        wordlist_path: str | None = None,
        brute_force: bool = True,
        permutations: bool = True,
        max_candidates: int = 200_000,
        max_wildcard_http_checks: int = 300,
    ) -> None:
        self._wordlist_path = wordlist_path
        self._brute_force = brute_force
        self._permutations = permutations
        self._max_candidates = max_candidates
        self._max_wildcard_http_checks = max_wildcard_http_checks

    # -- entry point -------------------------------------------------------

    async def run(self, ctx: StageContext) -> StageResult:
        result = StageResult(stage=self.name)
        roots = ctx.scope.wildcard_roots

        candidates = _Candidates()
        for host in ctx.scope.seed_hosts:
            candidates.add(host, "scope")

        if not roots:
            result.note(
                "scope declares no wildcard domains, so only the named hosts are "
                "enumerated; add '*.example.com' to the scope to enumerate subdomains"
            )
        else:
            await self._gather_passive(ctx, roots, candidates, result)
            if self._brute_force:
                self._add_brute_candidates(ctx, roots, candidates, result)
            if self._permutations:
                self._add_permutations(roots, candidates, result)

        result.items_in = len(candidates)
        if result.items_in > self._max_candidates:
            result.note(
                f"candidate list capped at {self._max_candidates} "
                f"(generated {result.items_in})"
            )

        # --- scope funnel -------------------------------------------------
        proposed = list(candidates.by_host)[: self._max_candidates]
        in_scope = ctx.guard.filter_hosts(proposed)
        dropped = len(proposed) - len(in_scope)
        if dropped:
            result.filtered("out_of_scope", dropped)

        if not in_scope:
            result.note("no in-scope candidates to resolve")
            return result

        # --- resolve and adjudicate --------------------------------------
        accepted = await self._resolve_and_adjudicate(ctx, in_scope, candidates, result)

        # --- persist -------------------------------------------------------
        for host, (answer, cleared_by) in accepted.items():
            _, is_new = await upsert_asset(
                ctx.session,
                ctx.program_id,
                host,
                kind=AssetKind.DOMAIN,
                sources=candidates.by_host.get(host, ["subdomains"]),
                resolved_values=list(answer.values) or None,
                wildcard_suspect=False,
                wildcard_cleared_by=cleared_by,
            )
            if is_new:
                result.new_assets.append(host)

        result.items_out = len(accepted)
        result.checkpoint = {"roots": roots, "accepted": sorted(accepted)}
        ctx.shared["subdomain_hosts"] = sorted(accepted)
        return result

    # -- passive sources ---------------------------------------------------

    async def _gather_passive(
        self,
        ctx: StageContext,
        roots: list[str],
        candidates: _Candidates,
        result: StageResult,
    ) -> None:
        for root in roots:
            await self._subfinder(ctx, root, candidates, result)
            await self._crtsh(ctx, root, candidates, result)
            await self._certspotter(ctx, root, candidates, result)
            await self._otx(ctx, root, candidates, result)

    async def _subfinder(
        self, ctx: StageContext, root: str, candidates: _Candidates, result: StageResult
    ) -> None:
        runner = ctx.tool("subfinder")
        if not await runner.ensure_available():
            result.used_fallback("certificate transparency instead of subfinder")
            return
        try:
            # "-d" immediately precedes the scope-checked target appended by run().
            outcome = await runner.run(
                ["-silent", "-timeout", "30", "-d"], targets=[root], timeout=300.0
            )
        except ToolNotAvailable:
            result.used_fallback("certificate transparency instead of subfinder")
            return
        if outcome.ok:
            before = len(candidates)
            candidates.add_many(outcome.lines, "subfinder")
            result.used_tool("subfinder")
            result.note(f"subfinder proposed {len(candidates) - before} new names for {root}")
        else:
            result.note(f"subfinder failed for {root}: {outcome.stderr.strip()[:120]}")

    async def _crtsh(
        self, ctx: StageContext, root: str, candidates: _Candidates, result: StageResult
    ) -> None:
        """Certificate transparency. Works with no tools and no API key."""
        response = await ctx.sources.try_get(
            _CRTSH, params={"q": f"%.{root}", "output": "json"}, source="crt.sh"
        )
        if response is None:
            result.note(f"crt.sh was unavailable for {root}")
            return
        try:
            rows = response.json()
        except ValueError:
            result.note(f"crt.sh returned unparseable data for {root}")
            return
        if not isinstance(rows, list):
            return

        before = len(candidates)
        for row in rows:
            if not isinstance(row, dict):
                continue
            for field_name in ("name_value", "common_name"):
                raw = row.get(field_name)
                if not raw:
                    continue
                candidates.add_many(str(raw).split("\n"), "crt.sh")
        result.used_tool("crt.sh")
        result.note(f"crt.sh proposed {len(candidates) - before} new names for {root}")

    async def _certspotter(
        self, ctx: StageContext, root: str, candidates: _Candidates, result: StageResult
    ) -> None:
        response = await ctx.sources.try_get(
            _CERTSPOTTER,
            params={
                "domain": root,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
            source="certspotter",
        )
        if response is None:
            return
        try:
            rows = response.json()
        except ValueError:
            return
        if not isinstance(rows, list):
            return
        before = len(candidates)
        for row in rows:
            if isinstance(row, dict):
                candidates.add_many(row.get("dns_names") or [], "certspotter")
        if len(candidates) > before:
            result.used_tool("certspotter")

    async def _otx(
        self, ctx: StageContext, root: str, candidates: _Candidates, result: StageResult
    ) -> None:
        response = await ctx.sources.try_get(_OTX.format(domain=root), source="otx")
        if response is None:
            return
        try:
            payload = response.json()
        except ValueError:
            return
        records = payload.get("passive_dns") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            return
        before = len(candidates)
        for record in records:
            if isinstance(record, dict) and record.get("hostname"):
                candidates.add(str(record["hostname"]), "otx")
        if len(candidates) > before:
            result.used_tool("otx")

    # -- active generation -------------------------------------------------

    def _add_brute_candidates(
        self,
        ctx: StageContext,
        roots: list[str],
        candidates: _Candidates,
        result: StageResult,
    ) -> None:
        words = load_wordlist(self._wordlist_path, COMMON_SUBDOMAIN_LABELS)
        for root in roots:
            for label in words:
                candidates.add(f"{label}.{root}", "bruteforce")
        result.note(f"brute force added {len(words)} labels per root ({len(roots)} roots)")
        if self._wordlist_path is None:
            result.note(
                "using the built-in wordlist; pass a larger list with "
                "--wordlist for deeper coverage"
            )

    def _add_permutations(
        self, roots: list[str], candidates: _Candidates, result: StageResult
    ) -> None:
        """Derive names from ones already proposed, e.g. api -> api-dev, api2."""
        known = [
            host
            for host, sources in candidates.by_host.items()
            if any(src in _EVIDENCE_SOURCES for src in sources)
        ]
        added = 0
        for host in known:
            label, _, parent = host.partition(".")
            if not parent or not label:
                continue
            for affix in PERMUTATION_AFFIXES:
                for variant in (f"{label}-{affix}", f"{affix}-{label}", f"{label}{affix}"):
                    before = len(candidates)
                    candidates.add(f"{variant}.{parent}", "permutation")
                    added += len(candidates) - before
        if added:
            result.note(f"permutations added {added} candidate names")

    # -- resolution and the wildcard verdict -------------------------------

    async def _resolve_and_adjudicate(
        self,
        ctx: StageContext,
        hosts: list[str],
        candidates: _Candidates,
        result: StageResult,
    ) -> dict[str, tuple[DnsAnswer, str | None]]:
        """Resolve candidates and decide which are real.

        Returns ``{host: (answer, wildcard_cleared_by)}`` for accepted hosts.
        """
        answers = await self._resolve(ctx, hosts, result)

        live: dict[str, DnsAnswer] = {}
        for host, answer in answers.items():
            if answer.resolved:
                live[host] = answer
            else:
                result.filtered("did_not_resolve")

        if not live:
            result.note("nothing resolved")
            return {}

        # Profile every distinct parent zone: multi-level wildcards are common.
        parents = sorted({host.partition(".")[2] for host in live if "." in host})
        profiles: dict[str, WildcardProfile] = {}
        for parent in parents:
            if parent.count(".") < 1:
                continue
            profiles[parent] = await ctx.dns.profile_wildcard(parent)

        wildcard_zones = [p.domain for p in profiles.values() if p.is_wildcard]
        if wildcard_zones:
            result.note(
                f"wildcard DNS detected on {len(wildcard_zones)} zone(s): "
                f"{', '.join(wildcard_zones[:5])}"
                + ("..." if len(wildcard_zones) > 5 else "")
            )

        accepted: dict[str, tuple[DnsAnswer, str | None]] = {}
        suspects: dict[str, DnsAnswer] = {}

        for host, answer in live.items():
            profile = profiles.get(host.partition(".")[2])
            if profile is not None and profile.covers(answer):
                suspects[host] = answer
            else:
                accepted[host] = (answer, None)

        if suspects:
            rescued = await self._clear_suspects_by_http(
                ctx, suspects, profiles, candidates, result
            )
            accepted.update(rescued)

        return accepted

    async def _resolve(
        self, ctx: StageContext, hosts: list[str], result: StageResult
    ) -> dict[str, DnsAnswer]:
        """Resolve candidates, preferring dnsx for large sets."""
        runner = ctx.tool("dnsx")
        dnsx_usable = await runner.ensure_available()
        if dnsx_usable and len(hosts) > 2000:
            resolved = await self._resolve_with_dnsx(runner, hosts, result)
            if resolved is not None:
                return resolved

        if len(hosts) > 2000 and not dnsx_usable:
            result.used_fallback(
                f"resolving {len(hosts)} names with dnspython; installing dnsx "
                "would make this much faster"
            )
        answers = await ctx.dns.resolve_many(hosts, "A")
        return {answer.host: answer for answer in answers}

    async def _resolve_with_dnsx(
        self, runner, hosts: list[str], result: StageResult
    ) -> dict[str, DnsAnswer] | None:
        try:
            outcome = await runner.run(
                ["-silent", "-a", "-json"], stdin_targets=hosts, timeout=900.0
            )
        except ToolNotAvailable:
            return None
        if not outcome.ok:
            result.note(f"dnsx failed, falling back to dnspython: {outcome.stderr[:120]}")
            return None

        result.used_tool("dnsx")
        out: dict[str, DnsAnswer] = {}
        for line in outcome.lines:
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = str(row.get("host", "")).lower().rstrip(".")
            if not host:
                continue
            values = tuple(sorted(row.get("a") or []))
            out[host] = DnsAnswer(host=host, rdtype="A", values=values)
        # Anything dnsx did not mention did not resolve.
        for host in hosts:
            out.setdefault(host, DnsAnswer(host=host, rdtype="A", error="NXDOMAIN"))
        return out

    async def _clear_suspects_by_http(
        self,
        ctx: StageContext,
        suspects: dict[str, DnsAnswer],
        profiles: dict[str, WildcardProfile],
        candidates: _Candidates,
        result: StageResult,
    ) -> dict[str, tuple[DnsAnswer, str | None]]:
        """Rescue real hosts hiding behind a wildcard, by HTTP divergence.

        A wildcard zone resolves everything, so DNS alone cannot distinguish a
        real host from a catch-all. What can is the HTTP response: a real host
        serves something different from what the wildcard serves.

        Evidence-backed suspects (a certificate really was issued for the name)
        are always checked. Brute-force-only suspects share a budget, because a
        wildcard zone can generate more of them than it is polite to probe.
        """
        baselines: dict[str, ResponseFingerprint | None] = {}
        for domain, profile in profiles.items():
            if profile.is_wildcard:
                baselines[domain] = await self._wildcard_http_baseline(ctx, profile, result)

        evidence_backed = [h for h in suspects if candidates.has_evidence(h)]
        guesses = [h for h in suspects if not candidates.has_evidence(h)]
        budget = max(0, self._max_wildcard_http_checks - len(evidence_backed))
        to_check = evidence_backed + guesses[:budget]
        skipped = len(guesses) - len(guesses[:budget])

        if skipped:
            result.filtered("wildcard_dns_unchecked", skipped)
            result.note(
                f"{skipped} brute-force names matched the wildcard and were dropped "
                f"without an HTTP check (budget {self._max_wildcard_http_checks}); "
                "raise --max-wildcard-checks to probe more"
            )

        rescued: dict[str, tuple[DnsAnswer, str | None]] = {}
        for host in to_check:
            parent = host.partition(".")[2]
            baseline = baselines.get(parent)
            fingerprint = await self._fetch_fingerprint(ctx, host)

            if fingerprint is None:
                # No HTTP service: DNS says wildcard and nothing contradicts it.
                result.filtered("wildcard_dns")
                continue
            if baseline is None:
                # Could not learn what the wildcard serves, so this is unproven
                # either way. Keep it, flagged, rather than guessing.
                rescued[host] = (
                    suspects[host],
                    "wildcard baseline unavailable; accepted unverified",
                )
                continue
            if fingerprint.looks_same_as(baseline):
                result.filtered("wildcard_dns")
                continue

            rescued[host] = (
                suspects[host],
                f"HTTP fingerprint diverged from the wildcard baseline "
                f"(similarity {fingerprint.similarity(baseline):.2f})",
            )

        if rescued:
            result.note(
                f"{len(rescued)} of {len(suspects)} wildcard-matching names were "
                "confirmed real by HTTP divergence"
            )
        return rescued

    async def _wildcard_http_baseline(
        self, ctx: StageContext, profile: WildcardProfile, result: StageResult
    ) -> ResponseFingerprint | None:
        """Learn what the wildcard itself serves over HTTP."""
        for probe in profile.probes:
            fingerprint = await self._fetch_fingerprint(ctx, probe)
            if fingerprint is not None:
                await save_baseline(
                    ctx.session,
                    ctx.program_id,
                    profile.domain,
                    BaselineKind.WILDCARD,
                    fingerprint=fingerprint,
                    sample_url=f"https://{probe}/",
                )
                return fingerprint
        result.note(
            f"could not fetch a wildcard HTTP baseline for {profile.domain}; "
            "suspects there are accepted unverified rather than dropped"
        )
        return None

    async def _fetch_fingerprint(
        self, ctx: StageContext, host: str
    ) -> ResponseFingerprint | None:
        """Fetch a host over HTTPS then HTTP, returning the first fingerprint."""
        for scheme in ("https", "http"):
            try:
                response = await ctx.http.get(f"{scheme}://{host}/")
            except Exception:
                continue
            return response.fingerprint
        return None
