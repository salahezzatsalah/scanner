"""A realtime view of a running scan.

The orchestrator calls back with :class:`ProgressEvent` as stages start and
finish and every few seconds in between. This module turns that stream into a
Rich live table: which stage is running, how many requests have gone out, and
which findings have surfaced so far. Findings appear here as their stage
completes; per-verdict streaming inside a stage would need hooks threaded
through every verifier, which is a bigger change for a later pass.
"""

from __future__ import annotations

from rich.console import Group
from rich.live import Live
from rich.table import Table
from rich.text import Text

__all__ = ["LiveProgress"]

_RUNNING = "running"
_DONE = {"completed", "skipped", "failed"}

_STATUS_GLYPH = {
    "pending": ("○", "dim"),
    "running": ("◉", "cyan"),
    "completed": ("●", "green"),
    "skipped": ("○", "yellow"),
    "failed": ("●", "red"),
}


class LiveProgress:
    """Accumulates progress events and renders them as a live table."""

    def __init__(self) -> None:
        self._order: list[str] = []
        self._status: dict[str, str] = {}
        self._detail: dict[str, str] = {}
        self._requests = 0
        self._tool_requests = 0
        self._dns = 0
        self._findings: list[str] = []
        self._live: Live | None = None

    # -- event sink ------------------------------------------------------

    def __call__(self, event) -> None:
        kind = event.kind
        if kind == "run_started":
            for name in (event.detail or "").split(","):
                name = name.strip()
                if name and name not in self._order:
                    self._order.append(name)
                    self._status[name] = "pending"
        elif kind == "stage_started":
            self._remember(event.stage)
            self._status[event.stage] = _RUNNING
        elif kind == "stage_finished":
            self._remember(event.stage)
            self._status[event.stage] = event.status or "completed"
            self._detail[event.stage] = event.detail or ""
            self._ingest(event)
        elif kind == "heartbeat" or kind == "run_finished":
            self._ingest(event)
        self.refresh()

    def _remember(self, stage: str) -> None:
        if stage and stage not in self._order:
            self._order.append(stage)
            self._status[stage] = "pending"

    def _ingest(self, event) -> None:
        self._requests = max(self._requests, event.requests_made)
        self._tool_requests = max(self._tool_requests, event.tool_requests)
        self._dns = max(self._dns, event.dns_queries)
        for label in event.findings or []:
            if label not in self._findings:
                self._findings.append(label)

    # -- rendering ---------------------------------------------------------

    def start(self) -> None:
        if self._live is None:
            self._live = Live(self.render(), refresh_per_second=2, transient=False)
            self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None

    def refresh(self) -> None:
        if self._live is not None:
            self._live.update(self.render())

    def render(self) -> Group:
        table = Table(title="Scan progress", show_header=True)
        table.add_column("Stage", style="bold")
        table.add_column("State")
        table.add_column("Detail", overflow="fold")
        if not self._order:
            table.add_row("…", Text("waiting to start", style="dim"), "")
        for name in self._order:
            state = self._status.get(name, "pending")
            glyph, style = _STATUS_GLYPH.get(state, ("?", "dim"))
            table.add_row(name, Text(f"{glyph} {state}", style=style), self._detail.get(name, ""))
        totals = Text(
            f"requests: {self._requests} (+{self._tool_requests} tool)   "
            f"dns: {self._dns}   findings: {len(self._findings)}"
        )
        parts: list = [table, totals]
        for label in self._findings[-8:]:
            color = "red" if label.startswith("CONFIRMED") else "yellow"
            parts.append(Text(f"  {label}", style=color))
        return Group(*parts)
