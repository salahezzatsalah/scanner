"""The stage contract.

A stage is one step of the pipeline. Stages declare what they depend on and the
orchestrator runs them in dependency order, in parallel where the graph allows.

Every stage returns a :class:`StageResult` that reports not only what it found
but **what it discarded and why**. That accounting is what makes the
false-positive claim inspectable: a subdomain stage that turned 12,000
brute-force hits into 41 assets has to say that 11,890 were wildcard artifacts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from reconx.config import Settings
from reconx.net.dns import ScopedResolver
from reconx.net.http import ScopedHttpClient
from reconx.net.sources import SourceClient
from reconx.scope.guard import ScopeGuard
from reconx.scope.model import Scope
from reconx.tools.base import ToolNotAvailable, ToolRunner, ToolSpec, ToolStatus
from reconx.tools.registry import get_runner, get_spec

__all__ = ["StageContext", "StageResult", "Stage", "registrable_domain"]


class _DisabledRunner:
    """Stands in for a tool when external tools are switched off.

    Reports itself unavailable so stages take their pure-Python path. Used by
    ``--no-external-tools`` and by tests that must stay hermetic: a test that
    shells out to a real scanner is neither fast nor reproducible.
    """

    def __init__(self, spec: ToolSpec) -> None:
        self._spec = spec

    @property
    def spec(self) -> ToolSpec:
        return self._spec

    @property
    def available(self) -> bool:
        return False

    async def ensure_available(self) -> bool:
        return False

    @property
    def path(self) -> str | None:
        return None

    async def status(self) -> ToolStatus:
        return ToolStatus(
            spec=self._spec,
            available=False,
            error="external tools are disabled for this run",
        )

    async def run(self, *args, **kwargs):
        raise ToolNotAvailable(
            f"{self._spec.name} is disabled for this run; "
            f"{self._spec.fallback}"
        )


def registrable_domain(host: str) -> str:
    """The registrable domain for a host, e.g. ``a.b.example.co.uk`` -> ``example.co.uk``."""
    from reconx.scope.model import _extract  # local import: shares the offline suffix list

    parsed = _extract(host)
    if parsed.domain and parsed.suffix:
        return f"{parsed.domain}.{parsed.suffix}"
    return host


@dataclass
class StageContext:
    """Everything a stage is allowed to touch."""

    program_id: int
    scan_run_id: int
    scope: Scope
    guard: ScopeGuard
    http: ScopedHttpClient
    dns: ScopedResolver
    sources: SourceClient
    session: AsyncSession
    settings: Settings
    checkpoint: dict[str, Any] = field(default_factory=dict)
    # Set by earlier stages for later ones, e.g. subdomain candidates.
    shared: dict[str, Any] = field(default_factory=dict)
    # When false, every stage takes its pure-Python path. Useful for a
    # reproducible run, and required for hermetic tests.
    use_external_tools: bool = True

    def tool(self, name: str, **kwargs) -> ToolRunner | _DisabledRunner:
        """A scope-enforcing runner for a catalogued external tool.

        The operator's identity is passed to every runner, so traffic a tool sends
        to the target is attributable to the same person the audit log names.
        """
        if not self.use_external_tools:
            return _DisabledRunner(get_spec(name))
        kwargs.setdefault("user_agent", self.settings.user_agent)
        kwargs.setdefault("identity_header", self.settings.identity_header)
        return get_runner(name, self.guard, **kwargs)

    @property
    def target_domains(self) -> list[str]:
        """Registrable domains this scope covers, deduplicated.

        Wildcard roots plus the registrable domain of every named host, which is
        what WHOIS/RDAP and certificate transparency should be asked about.
        """
        seen: set[str] = set()
        out: list[str] = []
        for host in [*self.scope.wildcard_roots, *self.scope.seed_hosts]:
            domain = registrable_domain(host)
            if domain and domain not in seen:
                seen.add(domain)
                out.append(domain)
        return out


@dataclass
class StageResult:
    """What a stage did, including what it rejected."""

    stage: str
    items_in: int = 0
    items_out: int = 0
    items_filtered: int = 0
    filter_reasons: Counter = field(default_factory=Counter)
    tools_used: list[str] = field(default_factory=list)
    fallbacks_used: list[str] = field(default_factory=list)
    # Newly seen this run. This is what the diff engine turns into alerts.
    new_assets: list[str] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    new_findings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    checkpoint: dict[str, Any] = field(default_factory=dict)

    def filtered(self, reason: str, count: int = 1) -> None:
        """Record that ``count`` items were dropped for ``reason``."""
        self.items_filtered += count
        self.filter_reasons[reason] += count

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)

    def used_tool(self, name: str) -> None:
        if name not in self.tools_used:
            self.tools_used.append(name)

    def used_fallback(self, name: str) -> None:
        if name not in self.fallbacks_used:
            self.fallbacks_used.append(name)

    def as_dict(self) -> dict:
        return {
            "stage": self.stage,
            "items_in": self.items_in,
            "items_out": self.items_out,
            "items_filtered": self.items_filtered,
            "filter_reasons": dict(self.filter_reasons),
            "tools_used": list(self.tools_used),
            "fallbacks_used": list(self.fallbacks_used),
            "new_assets": list(self.new_assets),
            "new_endpoints": list(self.new_endpoints),
            "new_findings": list(self.new_findings),
            "notes": list(self.notes),
        }


class Stage(ABC):
    """Base class for pipeline stages."""

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    # Stage names that must complete first.
    requires: ClassVar[tuple[str, ...]] = ()
    # Stages that change target state are opt-in for a read-only run.
    active: ClassVar[bool] = False

    @abstractmethod
    async def run(self, ctx: StageContext) -> StageResult:
        """Execute the stage."""

    def __repr__(self) -> str:  # pragma: no cover - display only
        return f"<Stage {self.name}>"
