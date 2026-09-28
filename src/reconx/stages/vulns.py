"""Vulnerability detection and verification.

Runs the detectors, then puts everything they produce through verification
before any of it becomes a reported finding:

* **nuclei**, when installed, for template-driven coverage. Its results are not
  trusted as-is: each match is re-fetched, checked against the host's not-found
  baseline (a soft-404 host makes many templates match nothing), and required to
  reproduce. DoS, fuzzing and intrusive template tags are excluded outright.
* **SQL injection**, on parameters that visibly affect the response, via the
  two-oracle verifier.
* **Cross-site scripting**, on parameters that reflect, via context analysis and
  real browser execution.
* **Subdomain takeover**, requiring delegation, an unclaimed service page, and a
  dangling check.

Findings are correlated on the vulnerability class and the normalised path and
parameter rather than on the full URL, so one issue across fifty hosts of the
same application is one finding with fifty affected hosts.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from sqlmodel import select

from reconx.db.models import Asset, Endpoint, FindingTier, Severity
from reconx.db.store import add_evidence, upsert_finding
from reconx.report.repro import curl_command
from reconx.stages.base import Stage, StageContext, StageResult
from reconx.tools.base import ToolNotAvailable
from reconx.verify.baseline import BaselineCollector
from reconx.verify.reproduce import reproduce
from reconx.verify.sqli import SqliVerifier
from reconx.verify.takeover import TakeoverVerifier
from reconx.verify.xss import XssVerifier

__all__ = ["VulnStage"]

# Template categories ReconX will not run. Availability is not ours to spend.
_EXCLUDED_NUCLEI_TAGS = "dos,fuzz,intrusive,stress"

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}

# Numeric path segments vary per request; collapse them so the same endpoint
# shape groups together rather than producing one finding per id.
_NUMERIC_SEGMENT = re.compile(r"/\d+(?=/|$)")
_UUID_SEGMENT = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
    re.IGNORECASE,
)


def normalize_path_template(url: str) -> str:
    """Reduce a URL path to a shape, for correlating findings across hosts."""
    path = urlsplit(url).path or "/"
    path = _UUID_SEGMENT.sub("/{uuid}", path)
    path = _NUMERIC_SEGMENT.sub("/{n}", path)
    return path


class VulnStage(Stage):
    name = "vulns"
    description = "Vulnerability detection with independent verification"
    requires = ("params",)
    active = True

    def __init__(
        self,
        *,
        run_nuclei: bool = True,
        check_sqli: bool = True,
        check_xss: bool = True,
        check_takeover: bool = True,
        enable_timing: bool = True,
        headless_xss: bool = True,
        max_parameters: int = 150,
        max_takeover_hosts: int = 200,
    ) -> None:
        self._run_nuclei = run_nuclei
        self._check_sqli = check_sqli
        self._check_xss = check_xss
        self._check_takeover = check_takeover
        self._enable_timing = enable_timing
        self._headless_xss = headless_xss
        self._max_parameters = max_parameters
        self._max_takeover_hosts = max_takeover_hosts

    # -- entry point -------------------------------------------------------

    async def run(self, ctx: StageContext) -> StageResult:
        result = StageResult(stage=self.name)
        self._surfaced = 0
        self._baselines = BaselineCollector(
            ctx.http,
            probes=ctx.settings.soft404_probe_count,
            session=ctx.session,
            program_id=ctx.program_id,
        )

        if self._check_takeover:
            await self._takeovers(ctx, result)
        if self._run_nuclei:
            await self._nuclei(ctx, result)
        if self._check_sqli or self._check_xss:
            await self._parameter_checks(ctx, result)

        result.items_out = self._surfaced
        result.note(
            "only Confirmed and Probable findings surface by default; discarded "
            "candidates are kept with their reason so the filter can be checked"
        )
        return result

    # -- subdomain takeover -------------------------------------------------

    async def _takeovers(self, ctx: StageContext, result: StageResult) -> None:
        rows = await ctx.session.execute(
            select(Asset).where(
                Asset.program_id == ctx.program_id,
                Asset.cname.is_not(None),  # only delegated names can be taken over
            )
        )
        assets = [
            asset
            for asset in rows.scalars().all()
            if ctx.guard.decide_host(asset.host).allowed
        ][: self._max_takeover_hosts]

        if not assets:
            return

        verifier = TakeoverVerifier(ctx.http, ctx.dns)
        result.items_in += len(assets)

        for asset in assets:
            verdict = await verifier.verify(asset.host)
            if verdict.tier is FindingTier.DISCARDED:
                result.filtered("takeover_not_confirmed")

            await self._save(
                ctx,
                result,
                dedup_key=f"takeover::{verdict.service or 'unknown'}",
                vuln_class="subdomain_takeover",
                title=(
                    f"Subdomain takeover via {verdict.service}"
                    if verdict.service
                    else "Possible subdomain takeover"
                ),
                severity=verdict.severity,
                tier=verdict.tier,
                confidence=verdict.confidence,
                reason=verdict.reason,
                signals=verdict.signals,
                hosts=[asset.host],
                detector="reconx:takeover",
                evidence=verdict.evidence,
                asset_id=asset.id,
                recommendation=(
                    "Claim the resource in the named service to prove impact, if the "
                    "program permits it, then report with the CNAME chain. The fix is "
                    "to remove the dangling DNS record."
                ),
            )

    # -- nuclei -------------------------------------------------------------

    async def _nuclei(self, ctx: StageContext, result: StageResult) -> None:
        runner = ctx.tool("nuclei")
        if not await runner.ensure_available():
            result.used_fallback(
                "nuclei is not installed, so only ReconX's own checks ran; "
                "this is the single biggest coverage gap to close"
            )
            return

        targets = await self._live_urls(ctx)
        if not targets:
            return

        rate = int(
            ctx.guard.effective_limit(
                "requests_per_second_per_host", ctx.settings.requests_per_second_per_host
            )
        )
        args = [
            "-silent", "-jsonl", "-no-color",
            "-severity", "low,medium,high,critical",
            "-exclude-tags", _EXCLUDED_NUCLEI_TAGS,
            "-rate-limit", str(max(1, rate)),
            "-timeout", str(int(ctx.settings.http_timeout_seconds)),
            "-retries", "1",
            "-disable-update-check",
        ]
        try:
            outcome = await runner.run(args, stdin_targets=targets, timeout=3600.0)
        except ToolNotAvailable:
            return

        if not outcome.lines:
            result.used_tool("nuclei")
            result.note("nuclei ran and matched nothing")
            return

        result.used_tool("nuclei")
        matches = 0
        for line in outcome.lines:
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            matches += 1
            await self._verify_nuclei_match(ctx, row, result)

        result.items_in += matches
        result.note(f"nuclei produced {matches} match(es), each re-verified")

    async def _verify_nuclei_match(
        self, ctx: StageContext, row: dict, result: StageResult
    ) -> None:
        """Re-prove a template match before reporting it.

        Two things go wrong with raw template output. On a host that answers
        every path with HTTP 200, many templates match the not-found page. And a
        match seen once may not survive a second look. Both are checked here.
        """
        matched_at = str(row.get("matched-at") or row.get("host") or "")
        template_id = str(row.get("template-id") or "unknown")
        info = row.get("info") or {}
        name = str(info.get("name") or template_id)
        severity = _SEVERITY_MAP.get(str(info.get("severity") or "info").lower(), Severity.INFO)
        tags = info.get("tags") or []

        if not matched_at or not ctx.guard.decide_url(matched_at).allowed:
            result.filtered("out_of_scope")
            return

        host = urlsplit(matched_at).hostname or ""
        scheme = urlsplit(matched_at).scheme or "https"
        base_url = f"{scheme}://{host}"

        first = await self._get(ctx, matched_at)
        if first is None:
            await self._save(
                ctx, result,
                dedup_key=f"nuclei::{template_id}",
                vuln_class="nuclei", title=name, severity=severity,
                tier=FindingTier.DISCARDED, confidence=0,
                reason="the matched URL could not be re-fetched, so the match is unverified",
                signals=["template_match"], hosts=[host], detector=f"nuclei:{template_id}",
            )
            result.filtered("nuclei_unreachable")
            return

        # Is this simply the host's not-found page?
        is_missing, missing_reason = await self._baselines.is_not_found(
            base_url, urlsplit(matched_at).path or "/", first.fingerprint
        )
        if is_missing:
            await self._save(
                ctx, result,
                dedup_key=f"nuclei::{template_id}",
                vuln_class="nuclei", title=name, severity=severity,
                tier=FindingTier.DISCARDED, confidence=0,
                reason=(
                    f"nuclei matched a page that is indistinguishable from the host's "
                    f"not-found response. {missing_reason}"
                ),
                signals=["template_match"], hosts=[host], detector=f"nuclei:{template_id}",
            )
            result.filtered("nuclei_soft_404")
            return

        # Does the response hold still?
        reference = first.fingerprint

        async def probe(_index: int) -> tuple[bool, str | None]:
            again = await self._get(ctx, matched_at)
            if again is None:
                return False, "re-fetch failed"
            return again.fingerprint.looks_same_as(reference), None

        stability = await reproduce(
            probe,
            attempts=ctx.settings.reproduce_attempts,
            required=max(2, ctx.settings.reproduce_required - 1),
        )
        if not stability.stable:
            await self._save(
                ctx, result,
                dedup_key=f"nuclei::{template_id}",
                vuln_class="nuclei", title=name, severity=severity,
                tier=FindingTier.DISCARDED, confidence=0,
                reason=f"the matched response was not stable: {stability.explain()}",
                signals=["template_match"], hosts=[host], detector=f"nuclei:{template_id}",
            )
            result.filtered("nuclei_unstable")
            return

        await self._save(
            ctx, result,
            dedup_key=f"nuclei::{template_id}",
            vuln_class="nuclei",
            title=name,
            severity=severity,
            tier=FindingTier.PROBABLE,
            confidence=65 if severity in (Severity.HIGH, Severity.CRITICAL) else 55,
            reason=(
                f"nuclei template {template_id} matched and the response reproduced "
                f"({stability.explain()}). Template matching is not independent proof, "
                "so this is Probable rather than Confirmed: read the evidence before "
                "reporting"
            ),
            signals=["template_match", "reproduced"],
            hosts=[host],
            detector=f"nuclei:{template_id}",
            evidence=[
                {
                    "label": "nuclei match",
                    "request_url": matched_at,
                    "response_status": first.status,
                    "note": f"tags: {', '.join(str(tag) for tag in tags)}",
                }
            ],
            recommendation=(
                f"Open {matched_at} and confirm the template's claim by hand. Nuclei "
                "tells you where to look, not what is true."
            ),
        )

    # -- parameter checks ---------------------------------------------------

    async def _parameter_checks(self, ctx: StageContext, result: StageResult) -> None:
        parameters = ctx.shared.get("parameters") or await self._parameters_from_db(ctx)
        if not parameters:
            result.note("no parameters to test; run the params stage first")
            return

        sqli_targets = [
            entry
            for entry in parameters
            if entry.get("changes_response") or entry.get("reflected")
        ][: self._max_parameters]
        xss_targets = [entry for entry in parameters if entry.get("reflected")][
            : self._max_parameters
        ]

        result.items_in += len(sqli_targets) + len(xss_targets)

        if self._check_sqli and sqli_targets:
            verifier = SqliVerifier(
                ctx.http,
                attempts=ctx.settings.reproduce_attempts,
                required=ctx.settings.reproduce_required,
                enable_timing=self._enable_timing,
            )
            for entry in sqli_targets:
                verdict = await verifier.verify(entry["url"], entry["name"])
                if verdict.tier is FindingTier.DISCARDED:
                    result.filtered("sqli_not_confirmed")
                await self._save_parameter_verdict(
                    ctx, result, verdict, vuln_class="sqli",
                    title_prefix="SQL injection", detector="reconx:sqli",
                    severity=Severity.CRITICAL,
                    recommendation=(
                        "Confirm by hand with the recorded requests, then report with "
                        "the boolean pair as proof. The fix is parameterised queries, "
                        "not input filtering."
                    ),
                )

        if self._check_xss and xss_targets:
            verifier = XssVerifier(
                ctx.http,
                attempts=ctx.settings.reproduce_attempts,
                required=ctx.settings.reproduce_required,
                headless_confirm=self._headless_xss and ctx.settings.headless_xss_confirm,
                chromium_path=ctx.settings.chromium_path,
            )
            for entry in xss_targets:
                verdict = await verifier.verify(entry["url"], entry["name"])
                if verdict.tier is FindingTier.DISCARDED:
                    result.filtered("xss_not_confirmed")
                await self._save_parameter_verdict(
                    ctx, result, verdict, vuln_class="xss",
                    title_prefix="Reflected cross-site scripting",
                    detector="reconx:xss", severity=Severity.HIGH,
                    recommendation=(
                        "The recorded payload URL reproduces it. Report with the "
                        "context that made it exploitable; the fix is context-correct "
                        "output encoding."
                    ),
                )

    async def _parameters_from_db(self, ctx: StageContext) -> list[dict]:
        rows = await ctx.session.execute(
            select(Endpoint).where(Endpoint.program_id == ctx.program_id)
        )
        out: list[dict] = []
        for endpoint in rows.scalars().all():
            reflected = set(endpoint.reflected_parameters or [])
            for name in endpoint.parameters or []:
                out.append(
                    {
                        "url": endpoint.url,
                        "name": name,
                        "reflected": name in reflected,
                        "changes_response": True,
                    }
                )
        return out

    async def _save_parameter_verdict(
        self,
        ctx: StageContext,
        result: StageResult,
        verdict,
        *,
        vuln_class: str,
        title_prefix: str,
        detector: str,
        severity: Severity,
        recommendation: str,
    ) -> None:
        host = urlsplit(verdict.url).hostname or ""
        template = normalize_path_template(verdict.url)
        signals = (
            verdict.agreeing
            if hasattr(verdict, "agreeing")
            else (["reflection", "context_escape"] if verdict.vulnerable else [])
        )
        if getattr(verdict, "dom_confirmed", False):
            signals = [*signals, "browser_execution"]

        await self._save(
            ctx,
            result,
            dedup_key=f"{vuln_class}::{template}::{verdict.parameter}",
            vuln_class=vuln_class,
            title=f"{title_prefix} in '{verdict.parameter}' at {template}",
            severity=severity if verdict.vulnerable else Severity.INFO,
            tier=verdict.tier,
            confidence=verdict.confidence,
            reason=verdict.reason,
            signals=signals,
            hosts=[host],
            detector=detector,
            evidence=verdict.evidence,
            obstructed=verdict.obstructed,
            recommendation=recommendation if verdict.vulnerable else None,
        )

    # -- persistence --------------------------------------------------------

    async def _save(
        self,
        ctx: StageContext,
        result: StageResult,
        *,
        dedup_key: str,
        vuln_class: str,
        title: str,
        severity: Severity,
        tier: FindingTier,
        confidence: int,
        reason: str,
        signals: list[str],
        hosts: list[str],
        detector: str,
        evidence: list[dict] | None = None,
        asset_id: int | None = None,
        obstructed: bool = False,
        recommendation: str | None = None,
    ) -> None:
        finding, is_new = await upsert_finding(
            ctx.session,
            ctx.program_id,
            dedup_key=dedup_key,
            vuln_class=vuln_class,
            title=title,
            severity=severity,
            tier=tier,
            confidence=confidence,
            description=reason,
            discard_reason=reason if tier is FindingTier.DISCARDED else None,
            signals=signals,
            affected_hosts=[host for host in hosts if host],
            detector=detector,
            scan_run_id=ctx.scan_run_id,
            asset_id=asset_id,
            tested_while_throttled=obstructed,
            recommendation=recommendation,
        )

        for item in evidence or []:
            request_url = item.get("request_url") or item.get("payload_url") or item.get(
                "true_url"
            )
            await add_evidence(
                ctx.session,
                finding.id,
                kind="request_response",
                label=str(item.get("label") or "")[:120],
                request_method="GET",
                request_url=request_url,
                response_status=item.get("response_status"),
                response_excerpt=str(item.get("snippet") or "")[:4000] or None,
                note=str(item.get("note") or "")[:2000] or None,
                curl_command=curl_command("GET", request_url) if request_url else None,
            )

        if tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE):
            self._surfaced += 1
            label = f"{tier.value.upper()} | {severity.value.upper()}: {title}"
            if label not in result.new_findings:
                result.new_findings.append(label)
        del is_new

    # -- helpers ------------------------------------------------------------

    async def _live_urls(self, ctx: StageContext) -> list[str]:
        rows = await ctx.session.execute(
            select(Asset).where(
                Asset.program_id == ctx.program_id,
                Asset.is_live == True,  # noqa: E712
            )
        )
        out: list[str] = []
        for asset in rows.scalars().all():
            if not ctx.guard.decide_host(asset.host).allowed:
                continue
            scheme = asset.scheme or "https"
            port = asset.port
            if port and port not in (80, 443):
                out.append(f"{scheme}://{asset.host}:{port}")
            else:
                out.append(f"{scheme}://{asset.host}")
        return out

    async def _get(self, ctx: StageContext, url: str):
        try:
            return await ctx.http.get(url)
        except Exception:
            return None
