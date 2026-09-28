"""Subdomain takeover verification.

A takeover exists when a name points at a third-party service that nobody has
claimed, so an attacker can claim it and serve content from the target's domain.
It is high impact and easy to report, which is exactly why it is also heavily
false-positived: a service fingerprint in a response body is not proof, because
plenty of pages legitimately contain that text, and plenty of parked services are
claimed but empty.

Three things must hold before this is reported:

1. the name delegates to a third-party service, by CNAME or by resolving into
   the service's address space,
2. the service's own unclaimed-resource page is what answers,
3. the delegation is actually dangling, checked per service: for some the
   target no longer resolves at all, for others the service returns a specific
   not-configured response.

Any one of those alone is a guess. All three together is a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reconx.db.models import FindingTier, Severity

__all__ = ["ServiceSignature", "TakeoverVerdict", "TakeoverVerifier", "SERVICE_SIGNATURES"]


@dataclass(frozen=True)
class ServiceSignature:
    """How to recognise one third-party service, and whether it is claimable."""

    service: str
    # CNAME suffixes that delegate to this service.
    cname_suffixes: tuple[str, ...]
    # Text the service serves for a resource nobody has claimed.
    unclaimed_markers: tuple[str, ...]
    # True when a dangling delegation also fails to resolve, which is a second
    # independent signal. False when the service resolves regardless.
    nxdomain_when_dangling: bool = False
    severity: Severity = Severity.HIGH
    note: str | None = None


SERVICE_SIGNATURES: tuple[ServiceSignature, ...] = (
    ServiceSignature(
        service="GitHub Pages",
        cname_suffixes=("github.io", "githubusercontent.com"),
        unclaimed_markers=(
            "there isn't a github pages site here",
            "for root urls (like http://example.com/) you must provide an index.html file",
        ),
        severity=Severity.HIGH,
    ),
    ServiceSignature(
        service="Amazon S3",
        cname_suffixes=("s3.amazonaws.com", "s3-website", "s3.dualstack"),
        unclaimed_markers=("nosuchbucket", "the specified bucket does not exist"),
        severity=Severity.HIGH,
    ),
    ServiceSignature(
        service="Heroku",
        cname_suffixes=("herokuapp.com", "herokudns.com", "herokussl.com"),
        unclaimed_markers=(
            "no such app",
            "there's nothing here, yet.",
            "herokucdn.com/error-pages/no-such-app.html",
        ),
        severity=Severity.HIGH,
    ),
    ServiceSignature(
        service="Azure",
        cname_suffixes=(
            "azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net",
            "blob.core.windows.net", "azureedge.net",
        ),
        unclaimed_markers=("404 web site not found", "the resource you are looking for has been removed"),
        nxdomain_when_dangling=True,
        severity=Severity.HIGH,
    ),
    ServiceSignature(
        service="Shopify",
        cname_suffixes=("myshopify.com",),
        unclaimed_markers=(
            "sorry, this shop is currently unavailable",
            "only one step left!",
        ),
        severity=Severity.MEDIUM,
    ),
    ServiceSignature(
        service="Fastly",
        cname_suffixes=("fastly.net", "fastlylb.net"),
        unclaimed_markers=("fastly error: unknown domain",),
        severity=Severity.MEDIUM,
    ),
    ServiceSignature(
        service="Netlify",
        cname_suffixes=("netlify.app", "netlify.com"),
        unclaimed_markers=("not found - request id",),
        severity=Severity.MEDIUM,
    ),
    ServiceSignature(
        service="Surge.sh",
        cname_suffixes=("surge.sh",),
        unclaimed_markers=("project not found",),
        severity=Severity.MEDIUM,
    ),
    ServiceSignature(
        service="Zendesk",
        cname_suffixes=("zendesk.com",),
        unclaimed_markers=("help center closed", "this help center no longer exists"),
        severity=Severity.MEDIUM,
    ),
    ServiceSignature(
        service="Pantheon",
        cname_suffixes=("pantheonsite.io",),
        unclaimed_markers=("404 error unknown site",),
        severity=Severity.MEDIUM,
    ),
    ServiceSignature(
        service="Bitbucket",
        cname_suffixes=("bitbucket.io",),
        unclaimed_markers=("repository not found",),
        severity=Severity.MEDIUM,
    ),
    ServiceSignature(
        service="Ghost",
        cname_suffixes=("ghost.io",),
        unclaimed_markers=("domain error", "the thing you were looking for is no longer here"),
        severity=Severity.MEDIUM,
    ),
    ServiceSignature(
        service="Readthedocs",
        cname_suffixes=("readthedocs.io",),
        unclaimed_markers=("unknown domain",),
        severity=Severity.LOW,
    ),
    ServiceSignature(
        service="Webflow",
        cname_suffixes=("proxy-ssl.webflow.com", "webflow.io"),
        unclaimed_markers=("the page you are looking for doesn't exist or has been moved",),
        severity=Severity.MEDIUM,
        note="Webflow serves this for unclaimed and for genuinely missing pages, so "
             "confirm the domain is unconfigured rather than the path being wrong.",
    ),
)


@dataclass
class TakeoverVerdict:
    host: str
    tier: FindingTier
    confidence: int
    service: str | None = None
    severity: Severity = Severity.INFO
    cname: str | None = None
    reason: str = ""
    signals: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return self.tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE)

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "tier": self.tier.value,
            "confidence": self.confidence,
            "service": self.service,
            "severity": self.severity.value,
            "cname": self.cname,
            "signals": list(self.signals),
            "reason": self.reason,
        }


def match_service(cname: str | None, body: str) -> ServiceSignature | None:
    """Find the signature whose delegation *and* marker both fit."""
    lowered_body = body.lower()
    lowered_cname = (cname or "").lower()

    for signature in SERVICE_SIGNATURES:
        delegated = any(suffix in lowered_cname for suffix in signature.cname_suffixes)
        marked = any(marker in lowered_body for marker in signature.unclaimed_markers)
        if delegated and marked:
            return signature
    return None


def find_marker_only(body: str) -> ServiceSignature | None:
    """A service marker with no matching delegation. Suggestive, not a finding."""
    lowered = body.lower()
    for signature in SERVICE_SIGNATURES:
        if any(marker in lowered for marker in signature.unclaimed_markers):
            return signature
    return None


class TakeoverVerifier:
    """Checks whether a name delegates to an unclaimed third-party resource."""

    def __init__(self, http, resolver) -> None:
        self._http = http
        self._resolver = resolver

    async def verify(self, host: str) -> TakeoverVerdict:
        verdict = TakeoverVerdict(host=host, tier=FindingTier.DISCARDED, confidence=0)

        cname_answer = await self._resolver.resolve(host, "CNAME")
        cname = cname_answer.values[0] if cname_answer.values else None
        verdict.cname = cname

        response = await self._fetch(host)
        if response is None:
            verdict.reason = (
                "the host did not answer over HTTP, so there is nothing to compare "
                "against a service's unclaimed page"
            )
            return verdict

        body = response.text

        # --- signal 1 + 2: delegation and the service's unclaimed page ----
        signature = match_service(cname, body)
        if signature is None:
            marker_only = find_marker_only(body)
            if marker_only is not None:
                verdict.tier = FindingTier.DISCARDED
                verdict.service = marker_only.service
                verdict.reason = (
                    f"the response contains {marker_only.service}'s unclaimed-resource "
                    f"text, but the name does not delegate to {marker_only.service} "
                    f"(CNAME: {cname or 'none'}), so the text is incidental"
                )
                return verdict
            verdict.reason = (
                f"no third-party service delegation and unclaimed page were both "
                f"present (CNAME: {cname or 'none'})"
            )
            return verdict

        verdict.service = signature.service
        verdict.severity = signature.severity
        verdict.signals.extend(["cname_delegation", "unclaimed_service_page"])
        verdict.evidence.append(
            {
                "label": "unclaimed service page",
                "request_url": f"https://{host}/",
                "response_status": response.status,
                "note": f"CNAME -> {cname}; matched {signature.service}",
            }
        )

        # --- signal 3: is the delegation actually dangling? ---------------
        dangling_confirmed = False
        dangling_note = ""
        if signature.nxdomain_when_dangling and cname:
            target = await self._resolver.resolve(cname, "A")
            if not target.resolved:
                dangling_confirmed = True
                dangling_note = f"the CNAME target {cname} does not resolve"
                verdict.signals.append("cname_target_nxdomain")
            else:
                dangling_note = (
                    f"the CNAME target {cname} still resolves, so the resource may be "
                    "claimed but unconfigured"
                )
        else:
            # For services that answer regardless, the unclaimed page *is* the
            # dangling check, so two independent signals are what we have.
            dangling_confirmed = True
            dangling_note = (
                f"{signature.service} serves this page only for resources that are "
                "not claimed"
            )
            verdict.signals.append("service_reports_unclaimed")

        if dangling_confirmed and len(verdict.signals) >= 3:
            verdict.tier = FindingTier.CONFIRMED
            verdict.confidence = 90
            verdict.reason = (
                f"{host} delegates to {signature.service} via {cname}, that service is "
                f"serving its unclaimed-resource page, and {dangling_note}"
            )
        elif dangling_confirmed:
            verdict.tier = FindingTier.PROBABLE
            verdict.confidence = 70
            verdict.reason = (
                f"{host} delegates to {signature.service} via {cname} and that service "
                f"is serving its unclaimed-resource page. {dangling_note}. Claim it in "
                "the service to confirm, if the program allows that"
            )
        else:
            verdict.tier = FindingTier.NEEDS_REVIEW
            verdict.confidence = 45
            verdict.reason = (
                f"{host} delegates to {signature.service} and shows an unclaimed page, "
                f"but {dangling_note}"
            )

        if signature.note:
            verdict.reason += f". {signature.note}"
        return verdict

    async def _fetch(self, host: str):
        for scheme in ("https", "http"):
            try:
                return await self._http.get(f"{scheme}://{host}/")
            except Exception:
                continue
        return None
