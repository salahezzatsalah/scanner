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
* **Open redirect, CORS misconfiguration, path traversal, template injection and
  command injection**, each requiring two independent oracles and each paired
  with a deliberate trap in the test fixture. A class without a trap does not
  ship, because nothing has shown it can say no.
* **SSRF**, when the out-of-band collaborator is enabled. It is off by default
  because it opens a listening port, and it is local-only by design: using a
  hosted interaction service would publish the target's hostnames to a third
  party outside the program.

Findings are correlated on the vulnerability class and the normalised path and
parameter rather than on the full URL, so one issue across fifty hosts of the
same application is one finding with fifty affected hosts.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlmodel import select

from reconx.db.models import Asset, Endpoint, Finding, FindingTier, Severity
from reconx.db.store import add_evidence, upsert_finding
from reconx.report.repro import SESSION_PLACEHOLDER, curl_command, redact
from reconx.stages.base import Stage, StageContext, StageResult
from reconx.tools.base import ToolNotAvailable
from reconx.triage.priority import compute_priority
from reconx.verify.base import (
    Evidence,
    EvidenceRequest,
    ParamLocation,
    ParamTarget,
    PreparedRequest,
    try_fetch,
)
from reconx.verify.baseline import BaselineCollector
from reconx.verify.cmdi import CmdiVerifier
from reconx.verify.collaborator import LocalCollaborator
from reconx.verify.cors import CorsVerifier
from reconx.verify.redirect import RedirectVerifier
from reconx.verify.reproduce import reproduce
from reconx.verify.sqli import SqliVerifier
from reconx.verify.ssrf import SsrfVerifier
from reconx.verify.ssti import SstiVerifier
from reconx.verify.takeover import TakeoverVerifier
from reconx.verify.traversal import TraversalVerifier
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


# Parameter names that suggest what a parameter is for. A hint, never a
# requirement: the value's shape is checked too, and the cheap classes test
# everything. Their purpose is to spend the expensive checks where they pay.
_REDIRECT_NAMES = frozenset({
    "next", "url", "target", "redirect", "redirect_to", "redirect_uri", "redirecturl",
    "return", "return_to", "returnurl", "return_url", "continue", "dest",
    "destination", "go", "goto", "out", "view", "to", "image_url", "callback",
    "checkout_url", "login_url", "logout_url", "forward", "location",
})
_FILE_NAMES = frozenset({
    "file", "filename", "filepath", "path", "page", "doc", "document", "folder",
    "download", "template", "include", "require", "read", "load", "resource",
    "attachment", "name", "style", "log", "conf", "config", "report",
})
_COMMAND_NAMES = frozenset({
    "host", "hostname", "ip", "domain", "cmd", "command", "exec", "ping", "query",
    "dns", "lookup", "target", "address", "url", "code", "run", "shell", "arg",
    "args", "option", "flag", "interface", "device",
})
_URL_NAMES = frozenset({
    "url", "uri", "src", "source", "dest", "destination", "feed", "callback",
    "webhook", "proxy", "fetch", "load", "link", "remote", "image", "imageurl",
    "img", "avatar", "endpoint", "upstream", "host", "site", "page", "target",
    "domain", "data", "path", "reference", "open", "continue", "redirect",
})

_URLISH = re.compile(r"^(?:https?://|//|/|\.\.?/)", re.IGNORECASE)
_FILEISH = re.compile(r"[\w-]+\.[a-z0-9]{1,5}$|^/|\.\./", re.IGNORECASE)


def _name_of(entry: dict) -> str:
    return str(entry.get("name") or "").lower()


def _value_of(entry: dict) -> str:
    from urllib.parse import parse_qsl as _pairs

    name = entry.get("name")
    for key, value in _pairs(urlsplit(entry.get("url") or "").query, keep_blank_values=True):
        if key == name:
            return value
    return ""


@dataclass(frozen=True)
class ParameterCheck:
    """One vulnerability class, and how the stage feeds and files it."""

    name: str
    vuln_class: str
    title_prefix: str
    detector: str
    severity: Severity
    recommendation: str
    build: Callable[[VulnStage, StageContext, LocalCollaborator | None], object]
    selects: Callable[[dict], bool]
    max_targets: int = 150
    needs_collaborator: bool = False


def _build_sqli(stage: VulnStage, ctx: StageContext, _collab) -> SqliVerifier:
    return SqliVerifier(
        ctx.http,
        attempts=ctx.settings.reproduce_attempts,
        required=ctx.settings.reproduce_required,
        enable_timing=stage._enable_timing,
    )


def _build_xss(stage: VulnStage, ctx: StageContext, _collab) -> XssVerifier:
    monitor = getattr(ctx, "session_monitor", None)
    return XssVerifier(
        ctx.http,
        attempts=ctx.settings.reproduce_attempts,
        required=ctx.settings.reproduce_required,
        headless_confirm=stage._headless_xss and ctx.settings.headless_xss_confirm,
        chromium_path=ctx.settings.chromium_path,
        # The browser needs the session too, or an authenticated finding is
        # downgraded because the page it loaded was the login form.
        session_headers=monitor.headers() if monitor is not None else None,
    )


def _plain(cls):
    def build(_stage: VulnStage, ctx: StageContext, _collab):
        return cls(
            ctx.http,
            attempts=ctx.settings.reproduce_attempts,
            required=ctx.settings.reproduce_required,
        )

    return build


def _build_cmdi(stage: VulnStage, ctx: StageContext, _collab) -> CmdiVerifier:
    return CmdiVerifier(
        ctx.http,
        attempts=ctx.settings.reproduce_attempts,
        required=ctx.settings.reproduce_required,
        enable_timing=stage._enable_timing,
    )


def _build_ssrf(_stage: VulnStage, ctx: StageContext, collab) -> SsrfVerifier:
    return SsrfVerifier(
        ctx.http,
        collab,
        attempts=ctx.settings.reproduce_attempts,
        required=max(1, ctx.settings.reproduce_required - 1),
        callback_timeout=ctx.settings.oob_callback_timeout_seconds,
        # So a callback the scanner itself made is recognised as ours.
        own_user_agent=ctx.settings.user_agent,
    )


PARAMETER_CHECKS: tuple[ParameterCheck, ...] = (
    ParameterCheck(
        name="sqli",
        vuln_class="sqli",
        title_prefix="SQL injection",
        detector="reconx:sqli",
        severity=Severity.CRITICAL,
        recommendation=(
            "Confirm by hand with the recorded requests, then report with the boolean "
            "pair as proof. The fix is parameterised queries, not input filtering."
        ),
        build=_build_sqli,
        selects=lambda e: bool(e.get("changes_response") or e.get("reflected")),
    ),
    ParameterCheck(
        name="xss",
        vuln_class="xss",
        title_prefix="Reflected cross-site scripting",
        detector="reconx:xss",
        severity=Severity.HIGH,
        recommendation=(
            "The recorded payload URL reproduces it. Report with the context that made "
            "it exploitable; the fix is context-correct output encoding."
        ),
        build=_build_xss,
        selects=lambda e: bool(e.get("reflected")),
    ),
    ParameterCheck(
        name="redirect",
        vuln_class="open_redirect",
        title_prefix="Open redirect",
        detector="reconx:redirect",
        severity=Severity.LOW,
        recommendation=(
            "On its own this is usually informational. Chain it with something that "
            "trusts the destination -- an OAuth redirect_uri, a reset link, a token in "
            "the fragment -- and report what leaks across the hop."
        ),
        build=_plain(RedirectVerifier),
        selects=lambda e: (
            _name_of(e) in _REDIRECT_NAMES or bool(_URLISH.match(_value_of(e)))
        ),
    ),
    ParameterCheck(
        name="traversal",
        vuln_class="path_traversal",
        title_prefix="Path traversal",
        detector="reconx:traversal",
        severity=Severity.HIGH,
        recommendation=(
            "The boundary crossing is the finding. Report the parameter, the depth "
            "needed and the one record matched, and do not read further."
        ),
        build=_plain(TraversalVerifier),
        selects=lambda e: (
            _name_of(e) in _FILE_NAMES or bool(_FILEISH.search(_value_of(e)))
        ),
        max_targets=40,
    ),
    ParameterCheck(
        name="ssti",
        vuln_class="template_injection",
        title_prefix="Server-side template injection",
        detector="reconx:ssti",
        severity=Severity.CRITICAL,
        recommendation=(
            "Report the evaluation with the engine named and the computed value as "
            "proof. Whether to pursue code execution is the program's call, not a "
            "default."
        ),
        build=_plain(SstiVerifier),
        # Evaluation has to be visible, so a reflected parameter is the only kind
        # worth the requests.
        selects=lambda e: bool(e.get("reflected")),
        max_targets=60,
    ),
    ParameterCheck(
        name="cmdi",
        vuln_class="command_injection",
        title_prefix="Command injection",
        detector="reconx:cmdi",
        severity=Severity.CRITICAL,
        recommendation=(
            "The computed value is complete proof that the command string is yours. "
            "Report it as is; running anything beyond arithmetic on someone else's "
            "host is the escalation that gets reports closed."
        ),
        build=_build_cmdi,
        selects=lambda e: (
            _name_of(e) in _COMMAND_NAMES
            or bool(e.get("reflected"))
            or bool(e.get("changes_response"))
        ),
        max_targets=30,
    ),
    ParameterCheck(
        name="ssrf",
        vuln_class="ssrf",
        title_prefix="Server-side request forgery",
        detector="reconx:ssrf",
        severity=Severity.HIGH,
        recommendation=(
            "Severity is decided by reach: cloud metadata, an internal service, or "
            "only outward. Report with the callback log and say which you established."
        ),
        build=_build_ssrf,
        selects=lambda e: (
            _name_of(e) in _URL_NAMES or bool(_URLISH.match(_value_of(e)))
        ),
        max_targets=40,
        needs_collaborator=True,
    ),
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
        check_redirect: bool = True,
        check_cors: bool = True,
        check_traversal: bool = True,
        check_ssti: bool = True,
        check_cmdi: bool = True,
        check_ssrf: bool = True,
        enable_timing: bool = True,
        headless_xss: bool = True,
        max_parameters: int = 150,
        max_takeover_hosts: int = 200,
        max_cors_urls: int = 60,
    ) -> None:
        self._run_nuclei = run_nuclei
        self._check_takeover = check_takeover
        self._enable_timing = enable_timing
        self._headless_xss = headless_xss
        self._max_parameters = max_parameters
        self._max_takeover_hosts = max_takeover_hosts
        self._max_cors_urls = max_cors_urls
        # SSRF defaults on here but still needs the collaborator, which is off by
        # default: enabling it opens a listening port, which is the operator's
        # decision rather than a scanner's.
        self._enabled = {
            "sqli": check_sqli,
            "xss": check_xss,
            "redirect": check_redirect,
            "cors": check_cors,
            "traversal": check_traversal,
            "ssti": check_ssti,
            "cmdi": check_cmdi,
            "ssrf": check_ssrf,
        }

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
        if any(self._enabled.values()):
            await self._parameter_checks(ctx, result)

        await self._recheck_session(ctx, result)

        result.items_out = self._surfaced
        result.note(
            "only Confirmed and Probable findings surface by default; discarded "
            "candidates are kept with their reason so the filter can be checked"
        )
        return result

    async def _recheck_session(self, ctx: StageContext, result: StageResult) -> None:
        """If the session died during this stage, say so on the findings.

        An expired session produces **false negatives**, not false positives: the
        verifiers were testing a logged-out application, so "not vulnerable" means
        "not vulnerable to an anonymous visitor" and nothing more. A Confirmed
        finding is still confirmed -- a bug that reproduced, reproduced.

        So the discards are what get promoted to Needs review. Leaving them as
        discards is the failure this whole gate exists to prevent: a scan that
        silently lost its session, reporting an empty result that looks exactly
        like a clean one.
        """
        monitor = getattr(ctx, "session_monitor", None)
        if monitor is None or not monitor.configured:
            return

        verdict = await monitor.check(ctx.http)
        if verdict.active:
            return

        rows = await ctx.session.execute(
            select(Finding).where(
                Finding.program_id == ctx.program_id,
                Finding.scan_run_id == ctx.scan_run_id,
                Finding.tier == FindingTier.DISCARDED,
            )
        )
        affected = rows.scalars().all()
        for finding in affected:
            finding.tier = FindingTier.NEEDS_REVIEW
            finding.tested_while_throttled = True
            finding.discard_reason = None
            finding.description = (
                f"{finding.description or ''}\n\nThis was discarded while the scan "
                f"was not signed in: {verdict.explain()} So it means only that an "
                "anonymous visitor could not reach it. Refresh the credential and "
                "re-run before treating it as clean."
            ).strip()
            ctx.session.add(finding)
        await ctx.session.flush()

        result.note(
            f"the session was not valid at the end of this stage ({verdict.state.value}), "
            f"so {len(affected)} discarded candidate(s) became Needs review: they were "
            "tested against a logged-out application"
        )

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
                Evidence.comparison(
                    "nuclei match",
                    payload=PreparedRequest(url=matched_at),
                    roles=("match", "control"),
                    note=f"tags: {', '.join(str(tag) for tag in tags)}",
                    response_status=first.status,
                )
            ],
            recommendation=(
                f"Open {matched_at} and confirm the template's claim by hand. Nuclei "
                "tells you where to look, not what is true."
            ),
        )

    # -- parameter checks ---------------------------------------------------

    async def _parameter_checks(self, ctx: StageContext, result: StageResult) -> None:
        """Run every enabled parameter check, one table row per vulnerability class.

        This used to be a copy-pasted block per class. It is a table now because
        the interesting part of adding a class is its oracles, not the plumbing
        that feeds it parameters and saves what it decided.
        """
        # CORS does not need parameters, so it runs before the early return.
        await self._cors_checks(ctx, result)

        parameters = ctx.shared.get("parameters") or await self._parameters_from_db(ctx)
        if not parameters:
            result.note("no parameters to test; run the params stage first")
            return

        parameters = self._allowed_parameters(ctx, parameters, result)
        if not parameters:
            return

        collaborator: LocalCollaborator | None = None
        try:
            for check in PARAMETER_CHECKS:
                if not self._enabled.get(check.name, False):
                    continue

                targets = [entry for entry in parameters if check.selects(entry)]
                if not targets:
                    continue
                targets = targets[: min(check.max_targets, self._max_parameters)]

                if check.needs_collaborator:
                    collaborator = collaborator or await self._start_collaborator(
                        ctx, result
                    )
                    if collaborator is None:
                        result.used_fallback(
                            "the out-of-band collaborator is disabled, so SSRF was not "
                            "tested. Enable RECONX_ENABLE_OOB_COLLABORATOR to test it"
                        )
                        continue

                verifier = check.build(self, ctx, collaborator)
                result.items_in += len(targets)

                for entry in targets:
                    verdict = await verifier.verify(self._param_target(entry))
                    if verdict.tier is FindingTier.DISCARDED:
                        result.filtered(f"{check.vuln_class}_not_confirmed")
                    await self._save_parameter_verdict(
                        ctx, result, verdict,
                        vuln_class=check.vuln_class,
                        title_prefix=check.title_prefix,
                        detector=check.detector,
                        severity=check.severity,
                        recommendation=check.recommendation,
                    )
        finally:
            if collaborator is not None:
                await collaborator.stop()

    def _allowed_parameters(
        self, ctx: StageContext, parameters: list[dict], result: StageResult
    ) -> list[dict]:
        """Drop parameters this scan must not fuzz.

        Two filters, and the second only applies while authenticated. Fuzzing a
        form or JSON parameter means sending a POST, and a POST to an
        authenticated endpoint changes the operator's own data: it places an
        order, sends a message, updates a profile. Unauthenticated that is mostly
        harmless and worth testing; signed in it is the scanner acting as the
        person who authorized it.
        """
        # A URL the guard now refuses -- because it changes state and this scan is
        # authenticated -- must not be fuzzed either.
        in_scope = [
            entry for entry in parameters if ctx.guard.decide_url(entry["url"]).allowed
        ]
        refused = len(parameters) - len(in_scope)
        if refused:
            result.filtered("state_changing_path", refused)
            result.note(
                f"{refused} parameter(s) sit on paths that change state, and this scan "
                "is authenticated, so they were not tested"
            )

        auth = getattr(ctx.scope, "auth", None)
        if not ctx.authenticated or auth is None or auth.fuzz_write_methods:
            return in_scope

        writes = [
            entry
            for entry in in_scope
            if str(entry.get("method") or "GET").upper() != "GET"
            or ParamLocation(entry.get("location") or ParamLocation.QUERY)
            is not ParamLocation.QUERY
        ]
        if writes:
            result.filtered("write_method_while_authenticated", len(writes))
            result.note(
                f"{len(writes)} form or JSON parameter(s) were not fuzzed: a write to "
                "an authenticated endpoint changes your own data. Set "
                "auth.fuzz_write_methods: true to include them"
            )
        skipped = {id(entry) for entry in writes}
        return [entry for entry in in_scope if id(entry) not in skipped]

    def _param_target(self, entry: dict) -> ParamTarget:
        """Turn a discovered parameter into a target a verifier can send through.

        Form parameters carry their siblings and are sent as a POST body, which is
        how they are actually reached. Before ``ParamTarget`` existed they were
        rewritten into the query string, so a form-only parameter was tested at a
        place the application does not read.
        """
        location = ParamLocation(entry.get("location") or ParamLocation.QUERY)
        return ParamTarget(
            url=entry["url"],
            name=entry["name"],
            location=location,
            method=str(entry.get("method") or ""),
            siblings=dict(entry.get("siblings") or {}),
        )

    async def _start_collaborator(
        self, ctx: StageContext, result: StageResult
    ) -> LocalCollaborator | None:
        """Start the loopback callback listener, if the operator enabled it."""
        settings = ctx.settings
        if not settings.enable_oob_collaborator:
            return None
        collaborator = LocalCollaborator(
            bind_host=settings.oob_bind_host,
            bind_port=settings.oob_bind_port,
            public_base_url=settings.oob_public_base_url,
        )
        await collaborator.start()
        if collaborator.is_loopback_only:
            result.note(
                "the callback listener is bound to loopback, so only a target on this "
                "machine can reach it. Set RECONX_OOB_PUBLIC_BASE_URL to an address the "
                "target can reach before treating a quiet listener as a clean result"
            )
        return collaborator

    async def _cors_checks(self, ctx: StageContext, result: StageResult) -> None:
        """CORS is a property of a response, so it is checked per URL.

        Fed from every discovered endpoint rather than from the parameter list.
        Drawing it from parameters looked reasonable and silently skipped every
        endpoint that takes none -- which is most API endpoints, and precisely the
        ones whose responses are worth reading cross-origin.
        """
        if not self._enabled.get("cors", False):
            return

        rows = await ctx.session.execute(
            select(Endpoint)
            .where(Endpoint.program_id == ctx.program_id)
            .order_by(Endpoint.interesting_score.desc())
        )
        seen: list[str] = []
        for endpoint in rows.scalars().all():
            url = endpoint.url.split("?")[0]
            if url not in seen and ctx.guard.decide_url(url).allowed:
                seen.append(url)
        urls = seen[: self._max_cors_urls]
        if not urls:
            return

        verifier = CorsVerifier(
            ctx.http,
            attempts=ctx.settings.reproduce_attempts,
            required=ctx.settings.reproduce_required,
        )
        result.items_in += len(urls)
        for url in urls:
            verdict = await verifier.verify(url)
            if verdict.tier is FindingTier.DISCARDED:
                result.filtered("cors_misconfiguration_not_confirmed")
            await self._save_parameter_verdict(
                ctx, result, verdict,
                vuln_class="cors_misconfiguration",
                title_prefix="CORS allows credentialed cross-origin reads",
                detector="reconx:cors",
                severity=Severity.MEDIUM,
                recommendation=(
                    "Name one endpoint whose response is worth reading and prove it is "
                    "readable cross-origin as an authenticated user. The fix is an exact "
                    "allowlist comparison, not a substring match."
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
        # Every verdict now declares its own signals, so the stage no longer has
        # to guess them from the verifier's class.
        signals = list(verdict.signals or verdict.agreeing)

        # A class that is a property of the response rather than of a parameter
        # (CORS) has no parameter to name, and " in '' at /x" reads like a bug.
        title = (
            f"{title_prefix} in '{verdict.parameter}' at {template}"
            if verdict.parameter
            else f"{title_prefix} at {template}"
        )

        await self._save(
            ctx,
            result,
            dedup_key=f"{vuln_class}::{template}::{verdict.parameter}",
            vuln_class=vuln_class,
            title=title,
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
        evidence: list[Evidence] | None = None,
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

        # Order the queue by more than severity: confidence, verification tier
        # and what the affected host looks like all matter.
        asset = None
        if finding.asset_id is not None:
            asset = (
                await ctx.session.execute(
                    select(Asset).where(Asset.id == finding.asset_id)
                )
            ).scalars().first()
        breakdown = compute_priority(finding, asset=asset)
        finding.priority = breakdown.priority
        ctx.session.add(finding)
        await ctx.session.flush()

        for item in evidence or []:
            await self._save_evidence(ctx, finding.id, item)

        if tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE):
            self._surfaced += 1
            label = f"{tier.value.upper()} | {severity.value.upper()}: {title}"
            if label not in result.new_findings:
                result.new_findings.append(label)
        del is_new

    async def _save_evidence(self, ctx: StageContext, finding_id: int, item: Evidence) -> None:
        """Write one piece of evidence, keeping every request it rests on.

        Evidence is usually a comparison, and the control half is what makes the
        payload half mean anything. The previous writer looked for one of three
        known keys and dropped the rest, so ``control_url``, ``false_url`` and
        ``surviving_chars`` never reached the database and a reviewer was handed
        a conclusion with half its proof. Each request now becomes its own row,
        with its own runnable reproduction.
        """
        requests = item.requests or [EvidenceRequest(role="observed")]
        note = item.rendered_note()
        multi = len(requests) > 1

        # Everything written below is shared with a program, so the session is
        # stripped on the way in. Redacting at the point of storage rather than at
        # the point of display means no unredacted copy exists to be leaked by a
        # report format added later.
        secrets = self._session_secrets(ctx)
        needs_session = False

        for index, request in enumerate(requests):
            label = f"{item.label} ({request.role})" if multi else item.label
            headers = {
                name: (redact(value, secrets) or "")
                for name, value in request.headers.items()
            }
            body = redact(request.body, secrets)
            if secrets and headers != dict(request.headers):
                needs_session = True

            reproduction = None
            if request.url:
                reproduction = redact(
                    curl_command(
                        request.method or "GET",
                        request.url,
                        headers=dict(request.headers),
                        body=request.body,
                        # A cookie-borne payload does not reproduce without its
                        # cookie, so cookies are kept here even though
                        # reproductions otherwise strip them. The session inside
                        # that header is then replaced by the redaction below --
                        # the payload survives, the credential does not.
                        include_cookies=True,
                    ),
                    secrets,
                )

            suffix = ""
            if needs_session and index == 0:
                suffix = (
                    f" Replace {SESSION_PLACEHOLDER} with a valid session: this was "
                    "found while authenticated and does not reproduce without one."
                )
            await add_evidence(
                ctx.session,
                finding_id,
                kind="request_response",
                label=label[:120],
                request_method=request.method or "GET",
                request_url=request.url or None,
                request_headers=headers,
                request_body=body,
                response_status=request.status or item.detail.get("response_status"),
                # The body excerpt belongs to the request that produced the
                # signal, not to the control it is compared against.
                response_excerpt=(
                    (redact(item.snippet, secrets) or "")[:4000] or None
                )
                if index == 0
                else None,
                note=(
                    ((redact(note, secrets) or "") + suffix)[:2000] or None
                )
                if index == 0
                else f"the {request.role} request",
                curl_command=reproduction,
            )

    @staticmethod
    def _session_secrets(ctx: StageContext) -> tuple[str, ...]:
        """Credential strings that must never be stored. Empty when unauthenticated."""
        monitor = getattr(ctx, "session_monitor", None)
        return monitor.redactions() if monitor is not None else ()

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
        result = await try_fetch(ctx.http, url)
        return result.response
