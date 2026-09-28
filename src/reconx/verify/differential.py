"""Payload versus a benign control: the primitive the whole engine rests on.

A signal seen under a payload proves nothing by itself. Pages carry SQL error
text in their templates, contain the string ``root:x:0:0`` because they are
documenting ``/etc/passwd``, echo whatever you send them, and redirect for
reasons that have nothing to do with the parameter you changed. Every one of
those is reported as a finding by scanners that look only at the payload
response.

What settles it is a **control**: a second request that is as close to the
payload as possible while being harmless. If the control produces the same
result, the payload did not cause it. If the payload produces it and the control
does not, something about the payload's *meaning* mattered.

This logic existed once, inside :mod:`reconx.verify.sqli`'s error oracle, where
no other class could use it. It is the same shape for path traversal, template
injection, command injection, open redirect and CORS, so it lives here.

Two primitives:

* :class:`DifferentialOracle` — payload against control, judged by a detector.
* :func:`boolean_differential` — a true case that matches the original page and
  a false case that does not, which is the strongest single signal available
  because it requires the application to respond to injected *logic*.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from reconx.net.fingerprint import ResponseFingerprint
from reconx.verify.base import (
    Evidence,
    FetchResult,
    OracleResult,
    OracleStrength,
    PreparedRequest,
)
from reconx.verify.reproduce import reproduce

__all__ = ["DifferentialOracle", "Detection", "boolean_differential"]


@dataclass(frozen=True)
class Detection:
    """Whether a detector saw its signal, and what it saw."""

    present: bool
    detail: str = ""


#: A detector inspects one response and says whether the signal is in it.
Detector = Callable[[FetchResult], Detection]

#: Anything that can perform a prepared request.
Fetcher = Callable[[PreparedRequest], Awaitable[FetchResult]]


class DifferentialOracle:
    """One oracle: a payload, a structurally similar control, and a detector.

    ``signal`` is a bare noun phrase naming what is being looked for ("database
    error", "file signature", "evaluated expression"), used to build reasons a
    reviewer can read without knowing the code.

    ``payload_label`` names the payload in the same register ("a syntax-breaking
    value", "a traversal sequence").
    """

    def __init__(
        self,
        fetcher: Fetcher,
        *,
        name: str,
        signal: str,
        detect: Detector,
        payload_label: str = "the payload",
        strength: OracleStrength = OracleStrength.STRONG,
        attempts: int = 3,
        required: int = 3,
        lone_reason: str = "",
    ) -> None:
        self._fetch = fetcher
        self._name = name
        self._signal = signal
        self._detect = detect
        self._payload_label = payload_label
        self._strength = strength
        self._attempts = attempts
        self._required = required
        self._lone_reason = lone_reason

    async def run(
        self,
        payload: PreparedRequest,
        control: PreparedRequest,
        *,
        evidence_label: str = "",
        collect: list[Evidence] | None = None,
    ) -> OracleResult:
        """Re-test the payload/control pair and report whether it holds."""
        last_snippet: list[str] = []

        async def probe(_index: int) -> tuple[bool, str | None]:
            payload_result = await self._fetch(payload)
            control_result = await self._fetch(control)

            if not payload_result.ok or not control_result.ok:
                failure = payload_result.error or control_result.error or "unknown"
                return False, f"a request failed ({failure})"

            payload_seen = self._detect(payload_result)
            control_seen = self._detect(control_result)

            if payload_seen.present and not control_seen.present:
                last_snippet[:] = [payload_result.text[:2000]]
                return True, payload_seen.detail or f"a {self._signal} appeared"
            if payload_seen.present and control_seen.present:
                return False, (
                    f"the benign control produced the same {self._signal}, so the "
                    "payload did not cause it"
                )
            return False, f"no {self._signal} appeared"

        outcome = await reproduce(
            probe, attempts=self._attempts, required=self._required
        )
        detail = (
            outcome.attempts[-1].detail if outcome.attempts and outcome.attempts[-1].detail
            else ""
        )

        if outcome.stable:
            if collect is not None:
                collect.append(
                    Evidence.comparison(
                        evidence_label or f"{self._signal} with a benign control",
                        payload=payload,
                        control=control,
                        note=detail,
                        snippet=last_snippet[0] if last_snippet else "",
                    )
                )
            return OracleResult(
                name=self._name,
                agreed=True,
                reason=(
                    f"{self._payload_label} produced a {self._signal} that the benign "
                    f"control did not ({detail}); {outcome.explain()}"
                ),
                detail={"observed": detail},
                reproduced=outcome.successes,
                attempts=outcome.total,
                strength=self._strength,
                lone_reason=self._lone_reason,
            )

        return OracleResult(
            name=self._name,
            agreed=False,
            reason=detail or f"no {self._signal} was produced",
            reproduced=outcome.successes,
            attempts=outcome.total,
            strength=self._strength,
        )


async def boolean_differential(
    fetcher: Fetcher,
    *,
    name: str = "boolean_differential",
    true_request: PreparedRequest,
    false_request: PreparedRequest,
    baseline: ResponseFingerprint,
    context: str,
    attempts: int = 3,
    required: int = 3,
    collect: list[Evidence] | None = None,
    agreed_reason: str = "",
    lone_reason: str = "",
) -> OracleResult:
    """A true condition that looks like the original, and a false one that does not.

    Both halves matter. "The response differed" proves nothing on its own,
    because dynamic content makes any two responses differ. Requiring the true
    case to *match the original page* as well is what turns a difference into
    evidence that the application evaluated the injected condition.
    """

    async def probe(_index: int) -> tuple[bool, str | None]:
        true_result = await fetcher(true_request)
        false_result = await fetcher(false_request)
        if not true_result.ok or not false_result.ok:
            failure = true_result.error or false_result.error or "unknown"
            return False, f"a request failed ({failure})"

        true_fp = true_result.response.fingerprint
        false_fp = false_result.response.fingerprint
        detail = (
            f"true/false similarity {true_fp.similarity(false_fp):.2f}, "
            f"true/original {true_fp.similarity(baseline):.2f}"
        )
        differ = not true_fp.looks_same_as(false_fp)
        true_like_original = true_fp.looks_same_as(baseline)
        return (differ and true_like_original), detail

    outcome = await reproduce(probe, attempts=attempts, required=required)

    if outcome.stable:
        if collect is not None:
            collect.append(
                Evidence.comparison(
                    f"boolean differential ({context})",
                    payload=true_request,
                    control=false_request,
                    roles=("true", "false"),
                    note=outcome.attempts[-1].detail or "",
                    context=context,
                )
            )
        return OracleResult(
            name=name,
            agreed=True,
            reason=agreed_reason
            or (
                f"a true condition in {context} returned the original page while a "
                f"false condition returned something different; {outcome.explain()}"
            ),
            detail={"context": context},
            reproduced=outcome.successes,
            attempts=outcome.total,
            strength=OracleStrength.DECISIVE,
            lone_reason=lone_reason,
        )

    return OracleResult(
        name=name,
        agreed=False,
        reason=(
            "no boolean pair produced the true-matches-original and false-differs "
            "pattern, so the page does not respond to injected logic"
        ),
        reproduced=outcome.successes,
        attempts=outcome.total,
        strength=OracleStrength.DECISIVE,
    )
