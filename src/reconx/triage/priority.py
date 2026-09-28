"""Finding priority.

Severity alone is a poor queue. A critical finding nobody has verified should
not outrank a confirmed high one, and the same issue on an admin console matters
more than on a marketing page. Priority combines three things:

* **severity** — how bad it is if real,
* **confidence** — how sure we are that it is real,
* **asset criticality** — what the affected host appears to be.

The result is a single number to sort by, and it is deliberately explainable:
:func:`explain_priority` says which factors moved it, so a researcher can
disagree with the ordering rather than being told to trust it.
"""

from __future__ import annotations

from dataclasses import dataclass

from reconx.db.models import Asset, Finding, FindingTier, Severity

__all__ = [
    "asset_criticality",
    "compute_priority",
    "explain_priority",
    "PriorityBreakdown",
]

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.5,
}

# A tier multiplier on top of the numeric confidence, because the distinction
# between "proved" and "looks likely" is categorical, not just a few points.
_TIER_MULTIPLIER = {
    FindingTier.CONFIRMED: 1.0,
    FindingTier.PROBABLE: 0.75,
    FindingTier.NEEDS_REVIEW: 0.4,
    FindingTier.DISCARDED: 0.0,
}

# Signals in a host name, title or technology list that suggest what it is.
_CRITICALITY_SIGNALS: tuple[tuple[str, float, str], ...] = (
    ("admin", 1.6, "administrative interface"),
    ("console", 1.5, "management console"),
    ("dashboard", 1.4, "dashboard"),
    ("manage", 1.4, "management interface"),
    ("internal", 1.5, "internal system"),
    ("auth", 1.5, "authentication surface"),
    ("login", 1.35, "authentication surface"),
    ("sso", 1.5, "single sign-on"),
    ("oauth", 1.45, "authorization surface"),
    ("account", 1.3, "account surface"),
    ("api", 1.35, "API surface"),
    ("graphql", 1.45, "GraphQL endpoint"),
    ("payment", 1.7, "payment surface"),
    ("billing", 1.6, "billing surface"),
    ("checkout", 1.5, "checkout surface"),
    ("upload", 1.4, "file upload surface"),
    ("staging", 1.25, "non-production environment, often less protected"),
    ("dev", 1.2, "development environment, often less protected"),
    ("test", 1.15, "test environment, often less protected"),
    ("uat", 1.2, "pre-production environment"),
    ("jenkins", 1.6, "build system"),
    ("gitlab", 1.55, "source control"),
    ("jira", 1.4, "issue tracker"),
    ("grafana", 1.4, "monitoring interface"),
    ("kibana", 1.45, "log interface"),
    ("phpmyadmin", 1.7, "database interface"),
    # Downweights: a static asset host is rarely where the interesting bug is.
    ("cdn", 0.75, "content delivery host"),
    ("static", 0.75, "static asset host"),
    ("assets", 0.8, "static asset host"),
    ("img", 0.7, "image host"),
    ("media", 0.8, "media host"),
)


@dataclass
class PriorityBreakdown:
    """Why a finding sits where it does in the queue."""

    priority: float
    severity_weight: float
    confidence_factor: float
    tier_factor: float
    criticality: float
    reasons: list[str]

    def as_dict(self) -> dict:
        return {
            "priority": round(self.priority, 2),
            "severity_weight": self.severity_weight,
            "confidence_factor": round(self.confidence_factor, 2),
            "tier_factor": self.tier_factor,
            "criticality": round(self.criticality, 2),
            "reasons": list(self.reasons),
        }


def asset_criticality(
    host: str = "",
    *,
    title: str | None = None,
    technologies: list[str] | None = None,
    url: str | None = None,
) -> tuple[float, list[str]]:
    """Estimate how much an asset matters, from what it looks like.

    Returns ``(multiplier, reasons)``. The multiplier is clamped so a host name
    stuffed with keywords cannot dominate the ordering.
    """
    haystack = " ".join(
        part.lower()
        for part in [host, title or "", url or "", " ".join(technologies or [])]
        if part
    )
    if not haystack:
        return 1.0, []

    multiplier = 1.0
    reasons: list[str] = []
    seen: set[str] = set()

    for token, weight, label in _CRITICALITY_SIGNALS:
        if token in haystack and label not in seen:
            seen.add(label)
            multiplier *= weight
            reasons.append(label)

    # Clamp: keep the ordering sane on pathological names.
    multiplier = max(0.5, min(multiplier, 2.5))
    return multiplier, reasons


def compute_priority(
    finding: Finding, *, asset: Asset | None = None
) -> PriorityBreakdown:
    """Score a finding for the work queue."""
    severity_weight = _SEVERITY_WEIGHT.get(finding.severity, 1.0)
    tier_factor = _TIER_MULTIPLIER.get(finding.tier, 0.5)
    # Confidence contributes, but never to zero: a low-confidence confirmed
    # finding is still a finding.
    confidence_factor = 0.4 + (max(0, min(100, finding.confidence)) / 100) * 0.6

    host = (finding.affected_hosts or [""])[0]
    criticality, criticality_reasons = asset_criticality(
        host,
        title=asset.title if asset else None,
        technologies=asset.technologies if asset else None,
    )

    priority = severity_weight * confidence_factor * tier_factor * criticality

    reasons: list[str] = [
        f"{finding.severity.value} severity",
        f"{finding.tier.value} at confidence {finding.confidence}",
    ]
    reasons.extend(criticality_reasons)

    # Testing while a host was throttling makes any result less trustworthy.
    if finding.tested_while_throttled:
        priority *= 0.6
        reasons.append("the host was rate-limiting during testing")

    # Breadth matters: the same issue on many hosts is worth more attention.
    host_count = len(finding.affected_hosts or [])
    if host_count > 1:
        breadth = min(1.5, 1.0 + (host_count / 50))
        priority *= breadth
        reasons.append(f"affects {host_count} hosts")

    return PriorityBreakdown(
        priority=round(priority, 2),
        severity_weight=severity_weight,
        confidence_factor=confidence_factor,
        tier_factor=tier_factor,
        criticality=criticality,
        reasons=reasons,
    )


def explain_priority(breakdown: PriorityBreakdown) -> str:
    """A one-line explanation of a priority score."""
    return (
        f"priority {breakdown.priority:.1f} = "
        f"severity {breakdown.severity_weight:.0f} "
        f"x confidence {breakdown.confidence_factor:.2f} "
        f"x tier {breakdown.tier_factor:.2f} "
        f"x asset {breakdown.criticality:.2f}"
        + (f" ({', '.join(breakdown.reasons[2:])})" if len(breakdown.reasons) > 2 else "")
    )
