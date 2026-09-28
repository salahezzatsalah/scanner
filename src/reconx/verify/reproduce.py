"""The reproducibility gate.

A signal observed once is not evidence. Networks jitter, caches warm, load
balancers route to different backends, and an application that errors under
concurrency errors again for reasons that have nothing to do with your payload.

So every candidate signal is re-tested several times on fresh connections with
jittered timing, and only a stable result survives. This is the cheapest and
most effective filter in the engine: it costs a handful of requests and removes
an entire class of finding that other scanners report on a single observation.
"""

from __future__ import annotations

import asyncio
import random
import statistics
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

__all__ = ["Attempt", "Reproduction", "reproduce", "timing_separation"]


@dataclass
class Attempt:
    """One re-test."""

    index: int
    observed: bool
    detail: str | None = None
    elapsed_ms: float | None = None
    error: str | None = None


@dataclass
class Reproduction:
    """The outcome of re-testing a signal."""

    attempts: list[Attempt] = field(default_factory=list)
    required: int = 3

    @property
    def total(self) -> int:
        return len(self.attempts)

    @property
    def successes(self) -> int:
        return sum(1 for attempt in self.attempts if attempt.observed)

    @property
    def errors(self) -> int:
        return sum(1 for attempt in self.attempts if attempt.error)

    @property
    def stable(self) -> bool:
        """True when the signal appeared at least ``required`` times."""
        return self.successes >= self.required

    @property
    def flaky(self) -> bool:
        """Seen sometimes but not reliably: the shape of a false positive."""
        return 0 < self.successes < self.required

    def explain(self) -> str:
        if self.stable:
            return f"reproduced {self.successes} of {self.total} attempts"
        if self.flaky:
            return (
                f"appeared in only {self.successes} of {self.total} attempts, below the "
                f"{self.required} required, so it is not reliably reproducible"
            )
        return f"did not reproduce in {self.total} attempts"

    def as_dict(self) -> dict:
        return {
            "attempts": self.total,
            "successes": self.successes,
            "required": self.required,
            "stable": self.stable,
            "errors": self.errors,
            "detail": [
                {"index": a.index, "observed": a.observed, "detail": a.detail,
                 "elapsed_ms": a.elapsed_ms, "error": a.error}
                for a in self.attempts
            ],
        }


async def reproduce(
    probe: Callable[[int], Awaitable[tuple[bool, str | None]]],
    *,
    attempts: int = 3,
    required: int = 3,
    jitter_seconds: float = 0.25,
    stop_early: bool = True,
) -> Reproduction:
    """Run ``probe`` repeatedly and report whether the signal is stable.

    ``probe`` receives the attempt index and returns ``(observed, detail)``.

    With ``stop_early``, testing stops as soon as the outcome is decided in
    either direction, which keeps the request cost down on the common cases: a
    signal that never reproduces, and one that reproduces every time.
    """
    result = Reproduction(required=required)

    for index in range(1, attempts + 1):
        if index > 1 and jitter_seconds > 0:
            # Fresh timing each attempt: a fixed interval can sit in step with
            # whatever periodic behaviour produced the original signal.
            await asyncio.sleep(random.uniform(jitter_seconds * 0.5, jitter_seconds * 1.5))

        try:
            observed, detail = await probe(index)
            result.attempts.append(Attempt(index=index, observed=observed, detail=detail))
        except Exception as exc:
            result.attempts.append(
                Attempt(index=index, observed=False, error=f"{type(exc).__name__}: {exc}")
            )

        if stop_early:
            remaining = attempts - index
            if result.successes >= required:
                break
            if result.successes + remaining < required:
                break

    return result


def timing_separation(
    baseline_samples: list[float], payload_samples: list[float], *, min_delay_ms: float
) -> tuple[bool, str]:
    """Decide whether a payload genuinely delayed the response.

    A single slow response proves nothing: ordinary variance produces those
    constantly, and treating one as time-based injection is the classic false
    positive. Confirmation requires that the *slowest* baseline sample is still
    faster than the *fastest* payload sample, and that the gap is at least the
    delay the payload asked for. Non-overlapping ranges plus the expected
    magnitude is a much stronger claim than a difference of means.
    """
    if len(baseline_samples) < 2 or len(payload_samples) < 2:
        return False, "not enough timing samples to separate signal from variance"

    slowest_baseline = max(baseline_samples)
    fastest_payload = min(payload_samples)
    gap = fastest_payload - slowest_baseline

    baseline_median = statistics.median(baseline_samples)
    payload_median = statistics.median(payload_samples)

    if fastest_payload <= slowest_baseline:
        return False, (
            f"timing ranges overlap (baseline up to {slowest_baseline:.0f}ms, payload "
            f"from {fastest_payload:.0f}ms), so the delay is indistinguishable from "
            "ordinary variance"
        )
    if gap < min_delay_ms * 0.6:
        return False, (
            f"the delay of {gap:.0f}ms is well short of the {min_delay_ms:.0f}ms the "
            "payload requested, so it is more likely load than injection"
        )
    return True, (
        f"every payload response ({fastest_payload:.0f}ms and up, median "
        f"{payload_median:.0f}ms) was slower than every baseline response (up to "
        f"{slowest_baseline:.0f}ms, median {baseline_median:.0f}ms), a gap of "
        f"{gap:.0f}ms against a requested {min_delay_ms:.0f}ms"
    )
