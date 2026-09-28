"""Change detection.

Continuous scanning only pays off if you hear about what changed. On a wildcard
program, a subdomain that appeared four hours ago and has not been looked at by
anyone else is the single most valuable thing this tool produces.

Changes are derived from the history the database already keeps, so nothing extra
has to be recorded: a row whose ``first_seen`` falls after the last check is new,
and a live asset whose ``last_seen`` has gone stale has stopped answering.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx.db.models import Asset, Endpoint, Finding, FindingTier, Program, Severity
from reconx.notify.base import Notification, Urgency

__all__ = ["Change", "ChangeSet", "detect_changes", "build_notification"]

_URGENT_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@dataclass(frozen=True)
class Change:
    """One thing that is different since the last check."""

    kind: str
    subject: str
    detail: str
    urgency: Urgency = Urgency.INFO
    when: datetime | None = None

    def as_line(self) -> str:
        prefix = {
            "new_asset": "+",
            "asset_now_live": "*",
            "new_endpoint": ">",
            "new_finding": "!",
            "asset_stopped_answering": "-",
        }.get(self.kind, "·")
        return f"{prefix} {self.subject}" + (f" — {self.detail}" if self.detail else "")


@dataclass
class ChangeSet:
    """Everything that changed for one program."""

    program: Program
    since: datetime
    changes: list[Change]

    @property
    def any(self) -> bool:
        return bool(self.changes)

    @property
    def urgency(self) -> Urgency:
        if any(change.urgency is Urgency.URGENT for change in self.changes):
            return Urgency.URGENT
        if any(change.urgency is Urgency.NOTABLE for change in self.changes):
            return Urgency.NOTABLE
        return Urgency.INFO

    def of_kind(self, kind: str) -> list[Change]:
        return [change for change in self.changes if change.kind == kind]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for change in self.changes:
            out[change.kind] = out.get(change.kind, 0) + 1
        return out


async def detect_changes(
    session: AsyncSession,
    program: Program,
    since: datetime,
    *,
    stale_after: timedelta = timedelta(days=3),
    max_per_kind: int = 50,
) -> ChangeSet:
    """Work out what is new or gone for ``program`` since ``since``."""
    cutoff = _aware(since) or datetime.now(UTC) - timedelta(days=1)
    changes: list[Change] = []

    # --- new assets ------------------------------------------------------
    assets = (
        await session.execute(
            select(Asset).where(Asset.program_id == program.id).order_by(Asset.first_seen)
        )
    ).scalars().all()

    new_assets = [a for a in assets if (_aware(a.first_seen) or cutoff) > cutoff]
    for asset in new_assets[:max_per_kind]:
        detail_parts = []
        if asset.http_status:
            detail_parts.append(str(asset.http_status))
        if asset.title:
            detail_parts.append(asset.title[:60])
        if asset.technologies:
            detail_parts.append(", ".join(asset.technologies[:3]))
        changes.append(
            Change(
                kind="new_asset",
                subject=asset.host,
                detail=" · ".join(detail_parts),
                # A new asset on a wildcard program is the headline event.
                urgency=Urgency.NOTABLE,
                when=_aware(asset.first_seen),
            )
        )

    # --- assets that started answering -----------------------------------
    newly_live = [
        a
        for a in assets
        if a.is_live
        and a not in new_assets
        and (_aware(a.last_scanned_at) or cutoff) > cutoff
        and (_aware(a.first_seen) or cutoff) <= cutoff
    ]
    for asset in newly_live[:max_per_kind]:
        changes.append(
            Change(
                kind="asset_now_live",
                subject=asset.host,
                detail=f"now answering ({asset.http_status or '?'})",
                urgency=Urgency.NOTABLE,
                when=_aware(asset.last_scanned_at),
            )
        )

    # --- assets that stopped answering -----------------------------------
    now = datetime.now(UTC)
    for asset in assets:
        last_seen = _aware(asset.last_seen)
        if asset.is_live and last_seen and (now - last_seen) > stale_after:
            changes.append(
                Change(
                    kind="asset_stopped_answering",
                    subject=asset.host,
                    detail=f"last seen {last_seen:%Y-%m-%d}",
                    urgency=Urgency.INFO,
                    when=last_seen,
                )
            )

    # --- new endpoints ----------------------------------------------------
    endpoints = (
        await session.execute(
            select(Endpoint)
            .where(Endpoint.program_id == program.id)
            .order_by(Endpoint.interesting_score.desc())
        )
    ).scalars().all()
    new_endpoints = [e for e in endpoints if (_aware(e.first_seen) or cutoff) > cutoff]
    # Only the interesting ones are worth a message; the rest are in the report.
    for endpoint in [e for e in new_endpoints if e.interesting_score > 0][:max_per_kind]:
        changes.append(
            Change(
                kind="new_endpoint",
                subject=endpoint.url,
                detail=f"score {endpoint.interesting_score:.0f}, "
                f"status {endpoint.status or '?'}",
                urgency=Urgency.INFO,
                when=_aware(endpoint.first_seen),
            )
        )

    # --- new findings -----------------------------------------------------
    findings = (
        await session.execute(
            select(Finding)
            .where(
                Finding.program_id == program.id,
                Finding.tier.in_([FindingTier.CONFIRMED, FindingTier.PROBABLE]),
            )
            .order_by(Finding.priority.desc())
        )
    ).scalars().all()
    for finding in findings:
        if (_aware(finding.first_seen) or cutoff) <= cutoff:
            continue
        urgent = (
            finding.severity in _URGENT_SEVERITIES
            and finding.tier is FindingTier.CONFIRMED
        )
        changes.append(
            Change(
                kind="new_finding",
                subject=f"{finding.severity.value.upper()} {finding.title}",
                detail=f"{finding.tier.value}, confidence {finding.confidence}",
                urgency=Urgency.URGENT if urgent else Urgency.NOTABLE,
                when=_aware(finding.first_seen),
            )
        )

    return ChangeSet(program=program, since=cutoff, changes=changes)


def build_notification(changes: ChangeSet, *, max_lines: int = 25) -> Notification | None:
    """Turn a change set into a message, or None when nothing changed.

    Silence when nothing happened is a feature: a monitor that messages you
    every hour regardless gets muted, and then it is useless.
    """
    if not changes.any:
        return None

    counts = changes.counts()
    headline_parts: list[str] = []
    for kind, label in (
        ("new_finding", "finding"),
        ("new_asset", "new host"),
        ("asset_now_live", "host now live"),
        ("new_endpoint", "notable endpoint"),
        ("asset_stopped_answering", "host gone quiet"),
    ):
        count = counts.get(kind, 0)
        if count:
            headline_parts.append(f"{count} {label}{'s' if count != 1 else ''}")

    lines: list[str] = []
    # Findings first: they are why anyone reads this.
    for kind in (
        "new_finding",
        "new_asset",
        "asset_now_live",
        "new_endpoint",
        "asset_stopped_answering",
    ):
        group = changes.of_kind(kind)
        if not group:
            continue
        lines.append("")
        lines.append(f"**{kind.replace('_', ' ').title()}** ({len(group)})")
        for change in group[:max_lines]:
            lines.append(change.as_line())
        if len(group) > max_lines:
            lines.append(f"  ...and {len(group) - max_lines} more")

    return Notification(
        title=", ".join(headline_parts) or "changes detected",
        program=changes.program.name,
        urgency=changes.urgency,
        # Drop the leading blank that the first group header adds.
        lines=lines[1:] if lines and lines[0] == "" else lines,
        footer=(
            f"since {changes.since:%Y-%m-%d %H:%M UTC} · "
            f"reconx report {changes.program.slug}"
        ),
    )
