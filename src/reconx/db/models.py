"""Persistent model.

Long-running reconnaissance is only useful if it remembers. The diff engine
("this subdomain appeared four hours ago") and the verification engine ("this
host's normal 404 looks like *this*") both depend on history, so everything
discovered is stored rather than printed and forgotten.

Two conventions run through the schema:

* **Nothing is deleted.** Assets and findings carry ``first_seen`` /
  ``last_seen`` so disappearance is itself a signal.
* **Discards are kept.** A finding filtered out by the verification engine is
  stored with ``tier="discarded"`` and the reason, so the filter can be audited
  rather than trusted blindly.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Column, Index, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

__all__ = [
    "AssetKind",
    "FindingTier",
    "Severity",
    "RunStatus",
    "BaselineKind",
    "Program",
    "Asset",
    "Endpoint",
    "Finding",
    "Evidence",
    "Observation",
    "Baseline",
    "ScanRun",
    "StageRun",
    "ScheduleEntry",
    "AuditEntry",
]


def utcnow() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# enumerations
# ---------------------------------------------------------------------------


class AssetKind(StrEnum):
    DOMAIN = "domain"
    IP = "ip"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class FindingTier(StrEnum):
    """How much the verification engine trusts a finding."""

    CONFIRMED = "confirmed"        # independently re-proved, evidence attached
    PROBABLE = "probable"          # strong signal, not fully proved
    NEEDS_REVIEW = "needs_review"  # ambiguous, a human should look
    DISCARDED = "discarded"        # filtered out; reason recorded


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class BaselineKind(StrEnum):
    """The reference responses a host is compared against."""

    NOT_FOUND = "not_found"    # random path: learns soft-404 behaviour
    NORMAL = "normal"          # a known-good page
    ERROR = "error"            # deliberately malformed request
    WAF_BLOCK = "waf_block"    # observed block or challenge page
    WILDCARD = "wildcard"      # what a wildcard DNS catch-all serves


# ---------------------------------------------------------------------------
# core tables
# ---------------------------------------------------------------------------


class Program(SQLModel, table=True):
    """One authorized program, with the scope that authorizes it.

    The raw scope YAML is stored verbatim: if a question ever arises about what
    was in scope at the time of a scan, the answer is in the row rather than in
    someone's shell history.
    """

    __tablename__ = "program"

    id: int | None = Field(default=None, primary_key=True)
    slug: str = Field(index=True, unique=True, max_length=200)
    name: str
    platform: str | None = None
    program_url: str | None = None
    notes: str | None = Field(default=None, sa_column=Column(Text))

    scope_yaml: str = Field(sa_column=Column(Text, nullable=False))
    authorized_by: str
    authorization_date: date
    attestation: str = Field(sa_column=Column(Text, nullable=False))
    authorization_reference: str | None = None

    monitoring_enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class Asset(SQLModel, table=True):
    """A host discovered in scope: a domain, subdomain or IP."""

    __tablename__ = "asset"
    __table_args__ = (
        UniqueConstraint("program_id", "host", name="uq_asset_program_host"),
        Index("ix_asset_program_live", "program_id", "is_live"),
    )

    id: int | None = Field(default=None, primary_key=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    host: str = Field(index=True, max_length=253)
    kind: AssetKind = Field(default=AssetKind.DOMAIN)

    # How it was found. Multiple sources agreeing raises confidence.
    sources: list[str] = Field(default_factory=list, sa_column=Column(JSON))

    resolved_values: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    cname: str | None = None
    asn: str | None = None

    is_live: bool = Field(default=False)
    http_status: int | None = None
    scheme: str | None = None
    port: int | None = None
    title: str | None = None
    server: str | None = None
    technologies: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    content_length: int | None = None

    # Set when DNS answers are fully explained by a wildcard zone. Such an
    # asset is not reported until its HTTP fingerprint diverges from the
    # wildcard's, which is what keeps brute-force results honest.
    wildcard_suspect: bool = Field(default=False)
    wildcard_cleared_by: str | None = None

    fingerprint_sha256: str | None = None
    fingerprint_simhash: str | None = None

    tls_issuer: str | None = None
    tls_not_after: datetime | None = None
    tls_problem: str | None = None

    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    last_scanned_at: datetime | None = None


class Endpoint(SQLModel, table=True):
    """A URL worth remembering, with where it came from."""

    __tablename__ = "endpoint"
    __table_args__ = (
        UniqueConstraint("program_id", "url", "method", name="uq_endpoint_program_url_method"),
        Index("ix_endpoint_asset", "asset_id", "status"),
    )

    id: int | None = Field(default=None, primary_key=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    asset_id: int | None = Field(default=None, foreign_key="asset.id", index=True)

    url: str = Field(sa_column=Column(Text, nullable=False))
    method: str = Field(default="GET", max_length=10)
    source: str = Field(default="crawl", max_length=40)

    status: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    title: str | None = None

    parameters: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    reflected_parameters: list[str] = Field(default_factory=list, sa_column=Column(JSON))

    fingerprint_sha256: str | None = None
    fingerprint_simhash: str | None = None

    # True when this URL returns the host's not-found page despite a 200.
    is_soft_404: bool = Field(default=False)
    interesting_score: float = Field(default=0.0)

    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)


class Finding(SQLModel, table=True):
    """A candidate or confirmed issue, with the verification verdict attached."""

    __tablename__ = "finding"
    __table_args__ = (
        Index("ix_finding_program_tier", "program_id", "tier"),
        Index("ix_finding_dedup", "program_id", "dedup_key"),
    )

    id: int | None = Field(default=None, primary_key=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    asset_id: int | None = Field(default=None, foreign_key="asset.id", index=True)
    endpoint_id: int | None = Field(default=None, foreign_key="endpoint.id", index=True)
    scan_run_id: int | None = Field(default=None, foreign_key="scan_run.id", index=True)

    vuln_class: str = Field(index=True, max_length=60)
    title: str
    description: str | None = Field(default=None, sa_column=Column(Text))
    severity: Severity = Field(default=Severity.INFO)

    # --- verification verdict -------------------------------------------
    tier: FindingTier = Field(default=FindingTier.NEEDS_REVIEW, index=True)
    confidence: int = Field(default=0, ge=0, le=100)
    discard_reason: str | None = Field(default=None, sa_column=Column(Text))
    # Which independent oracles agreed, e.g. ["boolean_differential", "error_signature"]
    signals: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    reproduced_count: int = Field(default=0)
    attempt_count: int = Field(default=0)
    # True when this was measured in a state where results cannot be trusted:
    # the host was blocking or throttling, or the scan's session had expired. Both
    # produce the same problem for a reader, so they share a flag and the
    # description names the specific cause. Kept under the original name because
    # renaming a column costs a migration and buys nothing.
    tested_while_throttled: bool = Field(default=False)

    detector: str = Field(default="", max_length=120)
    dedup_key: str = Field(default="", index=True, max_length=200)
    # Populated when one issue is correlated across many hosts.
    affected_hosts: list[str] = Field(default_factory=list, sa_column=Column(JSON))

    priority: float = Field(default=0.0, index=True)
    recommendation: str | None = Field(default=None, sa_column=Column(Text))

    triage_status: str = Field(default="new", max_length=30)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    verified_at: datetime | None = None


class Evidence(SQLModel, table=True):
    """Proof for a finding. Without this a finding cannot be Confirmed."""

    __tablename__ = "evidence"

    id: int | None = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id", index=True)
    kind: str = Field(default="request_response", max_length=40)
    label: str | None = None

    request_method: str | None = Field(default=None, max_length=10)
    request_url: str | None = Field(default=None, sa_column=Column(Text))
    request_headers: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    request_body: str | None = Field(default=None, sa_column=Column(Text))

    response_status: int | None = None
    response_headers: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    response_excerpt: str | None = Field(default=None, sa_column=Column(Text))
    response_time_ms: float | None = None

    # A ready-to-run reproduction, so a report can be filed without guesswork.
    curl_command: str | None = Field(default=None, sa_column=Column(Text))
    note: str | None = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utcnow)


class Observation(SQLModel, table=True):
    """An information-gathering fact: WHOIS, DNS record, certificate, tech, ASN."""

    __tablename__ = "observation"
    __table_args__ = (
        Index("ix_observation_lookup", "program_id", "kind", "key"),
    )

    id: int | None = Field(default=None, primary_key=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    asset_id: int | None = Field(default=None, foreign_key="asset.id", index=True)

    kind: str = Field(max_length=40)
    key: str = Field(max_length=200)
    value: str = Field(sa_column=Column(Text))
    source: str = Field(default="", max_length=60)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)


class Baseline(SQLModel, table=True):
    """A reference response for a host.

    Captured *before* active testing so that findings can be compared against
    how the host normally behaves. This is the first line of defence against
    false positives.
    """

    __tablename__ = "baseline"
    __table_args__ = (
        Index("ix_baseline_host_kind", "program_id", "host", "kind"),
    )

    id: int | None = Field(default=None, primary_key=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    host: str = Field(index=True, max_length=253)
    kind: BaselineKind = Field(default=BaselineKind.NOT_FOUND)

    sample_url: str | None = Field(default=None, sa_column=Column(Text))
    status: int | None = None
    simhash: str | None = Field(default=None, max_length=32)
    sha256: str | None = Field(default=None, max_length=64)
    length_band: int | None = None
    body_length: int | None = None
    word_count: int | None = None
    title: str | None = None
    content_type: str | None = None
    header_names: list[str] = Field(default_factory=list, sa_column=Column(JSON))

    # Directory-scoped: a soft-404 page often differs per directory.
    path_scope: str = Field(default="/", max_length=500)
    created_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# run bookkeeping
# ---------------------------------------------------------------------------


class ScanRun(SQLModel, table=True):
    """One execution of the pipeline."""

    __tablename__ = "scan_run"

    id: int | None = Field(default=None, primary_key=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    status: RunStatus = Field(default=RunStatus.PENDING, index=True)
    trigger: str = Field(default="manual", max_length=30)

    stages_requested: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None

    requests_made: int = Field(default=0)
    dns_queries: int = Field(default=0)
    out_of_scope_blocked: int = Field(default=0)
    error: str | None = Field(default=None, sa_column=Column(Text))
    summary: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class StageRun(SQLModel, table=True):
    """One stage of one run. Carries the checkpoint that makes runs resumable."""

    __tablename__ = "stage_run"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "stage", name="uq_stage_run_unique"),
    )

    id: int | None = Field(default=None, primary_key=True)
    scan_run_id: int = Field(foreign_key="scan_run.id", index=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    stage: str = Field(max_length=60)
    status: RunStatus = Field(default=RunStatus.PENDING, index=True)

    started_at: datetime | None = None
    finished_at: datetime | None = None
    items_in: int = Field(default=0)
    items_out: int = Field(default=0)
    items_filtered: int = Field(default=0)
    filter_reasons: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    tools_used: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    error: str | None = Field(default=None, sa_column=Column(Text))
    checkpoint: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class ScheduleEntry(SQLModel, table=True):
    """Per-program, per-stage cadence for continuous operation."""

    __tablename__ = "schedule_entry"
    __table_args__ = (
        UniqueConstraint("program_id", "stage", name="uq_schedule_program_stage"),
    )

    id: int | None = Field(default=None, primary_key=True)
    program_id: int = Field(foreign_key="program.id", index=True)
    stage: str = Field(max_length=60)
    interval_seconds: int = Field(default=86400)
    enabled: bool = Field(default=True)
    last_run_at: datetime | None = None
    next_run_at: datetime | None = Field(default=None, index=True)
    last_status: RunStatus | None = None
    consecutive_failures: int = Field(default=0)


class AuditEntry(SQLModel, table=True):
    """One request, recorded. Includes refusals."""

    __tablename__ = "audit_entry"
    __table_args__ = (
        Index("ix_audit_program_time", "program_id", "timestamp"),
    )

    id: int | None = Field(default=None, primary_key=True)
    program_id: int | None = Field(default=None, foreign_key="program.id", index=True)
    scan_run_id: int | None = Field(default=None, foreign_key="scan_run.id", index=True)

    timestamp: datetime = Field(default_factory=utcnow, index=True)
    method: str = Field(default="GET", max_length=10)
    url: str = Field(sa_column=Column(Text, nullable=False))
    host: str = Field(default="", max_length=253)
    status: int | None = None
    duration_ms: float | None = None
    response_bytes: int | None = None
    error: str | None = Field(default=None, sa_column=Column(Text))
    matched_rule: str | None = None
    blocked: bool = Field(default=False)
    block_reason: str | None = Field(default=None, sa_column=Column(Text))
