"""Politeness controls.

ReconX should never be the reason a target degrades. Three mechanisms cooperate:

* a **per-host token bucket** capping sustained request rate,
* a **global concurrency semaphore** capping total requests in flight,
* a **per-host penalty box** so a host that signals distress (429, 503,
  connection resets) gets backed off automatically rather than hammered.

The penalty box is also the foundation of WAF-state awareness: work performed
while a host is throttling is unreliable, and the verification engine treats it
as such instead of reporting it.
"""

from __future__ import annotations

import asyncio
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

__all__ = ["TokenBucket", "HostRateLimiter", "HostState"]


class TokenBucket:
    """An asyncio token bucket.

    ``rate`` is tokens per second; ``capacity`` is the burst allowance and
    defaults to one second's worth (minimum 1).
    """

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._rate = float(rate)
        self._capacity = float(capacity) if capacity is not None else max(1.0, float(rate))
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    @property
    def rate(self) -> float:
        return self._rate

    async def acquire(self, tokens: float = 1.0) -> None:
        """Block until ``tokens`` are available, then consume them."""
        if tokens > self._capacity:
            tokens = self._capacity
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self._capacity, self._tokens + (now - self._updated) * self._rate
                )
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self._rate
            # Sleep outside the lock so other callers can still make progress.
            await asyncio.sleep(wait)


@dataclass
class HostState:
    """Per-host politeness state."""

    bucket: TokenBucket
    semaphore: asyncio.Semaphore
    not_before: float = 0.0
    penalties: int = 0
    consecutive_errors: int = 0
    requests: int = 0
    distress_signals: list[str] = field(default_factory=list)

    @property
    def throttled(self) -> bool:
        """True while the host is in the penalty box."""
        return time.monotonic() < self.not_before


class HostRateLimiter:
    """Coordinates rate, concurrency and backoff across hosts."""

    def __init__(
        self,
        *,
        rate_per_host: float = 5.0,
        max_concurrent_requests: int = 20,
        max_concurrent_per_host: int = 4,
        burst: float | None = None,
        jitter: float = 0.05,
    ) -> None:
        self._rate_per_host = rate_per_host
        self._max_per_host = max(1, max_concurrent_per_host)
        # A full second's worth of requests arriving at once is not polite, so
        # the default burst is capped at the per-host concurrency limit rather
        # than the rate. Callers can still opt into a larger burst explicitly.
        self._burst = (
            burst if burst is not None else max(1.0, min(float(rate_per_host), self._max_per_host))
        )
        self._global = asyncio.Semaphore(max(1, max_concurrent_requests))
        self._hosts: dict[str, HostState] = {}
        self._jitter = max(0.0, jitter)
        self._lock = asyncio.Lock()

    # -- state ------------------------------------------------------------

    async def _state(self, host: str) -> HostState:
        state = self._hosts.get(host)
        if state is not None:
            return state
        async with self._lock:
            state = self._hosts.get(host)
            if state is None:
                state = HostState(
                    bucket=TokenBucket(self._rate_per_host, self._burst),
                    semaphore=asyncio.Semaphore(self._max_per_host),
                )
                self._hosts[host] = state
            return state

    def state_for(self, host: str) -> HostState | None:
        """Current state for a host, without creating one."""
        return self._hosts.get(host)

    def is_throttled(self, host: str) -> bool:
        state = self._hosts.get(host)
        return bool(state and state.throttled)

    # -- backoff ----------------------------------------------------------

    def penalize(self, host: str, seconds: float, signal: str = "unspecified") -> float:
        """Put a host in the penalty box for at least ``seconds``.

        Repeated penalties compound exponentially (capped), because a host that
        keeps signalling distress needs progressively more room.
        """
        state = self._hosts.get(host)
        if state is None:
            state = HostState(
                bucket=TokenBucket(self._rate_per_host, self._burst),
                semaphore=asyncio.Semaphore(self._max_per_host),
            )
            self._hosts[host] = state

        state.penalties += 1
        backoff = min(seconds * (2 ** min(state.penalties - 1, 5)), 300.0)
        resume_at = time.monotonic() + backoff
        state.not_before = max(state.not_before, resume_at)
        if signal not in state.distress_signals:
            state.distress_signals.append(signal)
        return backoff

    def note_success(self, host: str) -> None:
        state = self._hosts.get(host)
        if state is not None:
            state.consecutive_errors = 0

    def note_error(self, host: str) -> int:
        state = self._hosts.get(host)
        if state is None:
            return 0
        state.consecutive_errors += 1
        return state.consecutive_errors

    # -- acquisition ------------------------------------------------------

    @asynccontextmanager
    async def slot(self, host: str):
        """Acquire permission to make one request to ``host``."""
        state = await self._state(host)

        # Respect any active penalty before queueing for a slot.
        while True:
            delay = state.not_before - time.monotonic()
            if delay <= 0:
                break
            await asyncio.sleep(min(delay, 5.0))

        async with self._global, state.semaphore:
            await state.bucket.acquire()
            if self._jitter:
                await asyncio.sleep(random.uniform(0, self._jitter))
            state.requests += 1
            yield state

    # -- reporting --------------------------------------------------------

    def snapshot(self) -> dict[str, dict]:
        """Per-host counters, for the audit trail and scan summaries."""
        return {
            host: {
                "requests": s.requests,
                "penalties": s.penalties,
                "throttled": s.throttled,
                "distress_signals": list(s.distress_signals),
            }
            for host, s in self._hosts.items()
        }
