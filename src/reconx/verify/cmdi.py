"""Command injection verification.

The classic probe is ``; echo CANARY`` followed by a search for ``CANARY`` in the
response. It is wrong far more often than it is right, because any page that
echoes its input back contains the canary whether or not a command ran. That is
the single reason this class has such a bad reputation with triagers.

What is checkable is a value the request **never contained**: the shell computes
something, and the computed result appears. Operands are random per probe, so the
expected output cannot be reflected, only calculated.

Two independent oracles, because a target can have one mechanism and not the
other — a filter that strips ``$(`` leaves ``$((`` alone surprisingly often:

* ``arithmetic_expansion`` — ``$((4021*83))`` becomes the product. This spawns
  **no process at all**: the shell performs the arithmetic itself.
* ``command_substitution`` — ``$(expr 4021 \\* 83)`` and the backtick form become
  the same product through a different mechanism, running only ``expr``, which
  computes and exits.

An optional timing oracle uses ``sleep``, which is the only probe here that waits
and the only one worth having on a blind injection where nothing is echoed. It is
weak by construction and never confirms on its own, because ordinary load
imitates a delay too well.

**Read-only markers only, by design.** Nothing here writes a file, deletes
anything, opens a reverse shell, starts an interactive shell, reads a file, or
makes a network request. The commands used are shell arithmetic (no process),
``expr`` (computes and exits) and optionally ``sleep`` (waits and exits). The
finding is that the command string is under an attacker's control; demonstrating
what that control reaches is the researcher's decision on a program that permits
it, not something a scanner should do unasked.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from reconx.verify.base import (
    Evidence,
    FetchResult,
    OracleResult,
    OracleStrength,
    ParameterVerdict,
    ParameterVerifier,
    ParamTarget,
    decide_from_oracles,
)
from reconx.verify.differential import Detection, DifferentialOracle
from reconx.verify.reproduce import timing_separation

__all__ = ["SEPARATORS", "CmdiVerdict", "CmdiVerifier"]

# How the payload detaches from the surrounding command. Each is inert on its
# own; what follows it is arithmetic or expr.
SEPARATORS: tuple[tuple[str, str], ...] = (
    (";", "a semicolon, which ends the first command"),
    ("&&", "a logical and, which runs on success"),
    ("|", "a pipe, which runs regardless"),
    ("%0a", "an encoded newline, which some filters miss"),
    ("", "no separator, for a value substituted mid-argument"),
)

_TIMING_LONE_REASON = (
    "only the timing oracle agreed. A delay is too easily imitated by load for this "
    "to be reported on its own, so it needs a human look or a second signal"
)


@dataclass(frozen=True)
class Mechanism:
    """One way of making a shell compute, and the name of its oracle."""

    name: str
    #: Format string taking ``left`` and ``right``.
    template: str
    description: str
    strength: OracleStrength
    spawns_process: bool


MECHANISMS: tuple[Mechanism, ...] = (
    Mechanism(
        name="arithmetic_expansion",
        template="$(({left}*{right}))",
        description="shell arithmetic expansion, which spawns no process",
        strength=OracleStrength.DECISIVE,
        spawns_process=False,
    ),
    Mechanism(
        name="command_substitution",
        template="$(expr {left} \\* {right})",
        description="command substitution around expr, which computes and exits",
        strength=OracleStrength.DECISIVE,
        spawns_process=True,
    ),
    Mechanism(
        name="command_substitution",
        template="`expr {left} \\* {right}`",
        description="backtick substitution around expr, which computes and exits",
        strength=OracleStrength.DECISIVE,
        spawns_process=True,
    ),
)


def _operands() -> tuple[int, int, int]:
    """Operands whose product is not a substring of the payload."""
    while True:
        left = random.randint(1001, 9999)
        right = random.randint(11, 97)
        product = left * right
        if str(product) not in f"{left}{right}":
            return left, right, product


@dataclass
class CmdiVerdict(ParameterVerdict):
    """The verification outcome for one parameter reaching a command line."""

    separator: str = ""
    mechanisms: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.mechanisms is None:
            self.mechanisms = []

    def as_dict(self) -> dict:
        return {
            **super().as_dict(),
            "separator": self.separator,
            "mechanisms": list(self.mechanisms),
        }


class CmdiVerifier(ParameterVerifier):
    """Verifies that a parameter reaches a shell, using read-only probes only."""

    vuln_class = "command_injection"
    title = "Command injection"
    verdict_class = CmdiVerdict

    def __init__(
        self,
        http,
        *,
        attempts: int = 3,
        required: int = 3,
        enable_timing: bool = False,
        sleep_seconds: int = 4,
    ) -> None:
        super().__init__(http, attempts=attempts, required=required)
        # Off by default: it is the slowest probe here and the weakest evidence,
        # and the two computing oracles already cover everything that echoes.
        self._enable_timing = enable_timing
        self._sleep_seconds = sleep_seconds

    async def verify(
        self, target: ParamTarget | str, parameter: str | None = None
    ) -> CmdiVerdict:
        target = self.target_of(target, parameter)
        verdict: CmdiVerdict = self.new_verdict(target)  # type: ignore[assignment]

        original = await self.fetch(target.apply(target.current_value or "127.0.0.1"))
        if not original.ok:
            verdict.reason = (
                f"the original request could not be completed ({original.error})"
            )
            return verdict
        if self.gate_obstruction(verdict, original):
            return verdict

        base = target.current_value or "127.0.0.1"
        found_separator: str | None = None

        for mechanism in MECHANISMS:
            # Once a separator is known to work, only that one is tried again:
            # the separator is how the payload gets in, not evidence in itself.
            separators = (
                [(found_separator, "the separator already shown to work")]
                if found_separator is not None
                else list(SEPARATORS)
            )
            result = await self._mechanism_oracle(
                target, base, mechanism, separators, verdict
            )
            if result.agreed:
                found_separator = str(result.detail.get("separator", ""))
                verdict.separator = verdict.separator or found_separator
                verdict.mechanisms.append(mechanism.name)
                # Each oracle name counts once, so a second form of the same
                # mechanism is not a second vote.
                if mechanism.name in {o.name for o in verdict.oracles if o.agreed}:
                    continue
            elif mechanism.name in {o.name for o in verdict.oracles if o.agreed}:
                continue
            verdict.oracles.append(result)

        if self._enable_timing and found_separator is not None:
            verdict.oracles.append(
                await self._timing_oracle(target, base, found_separator, verdict)
            )

        verdict.apply(
            decide_from_oracles(
                verdict.oracles,
                fallback_reason=(
                    "no probe produced a value the shell would have had to compute, so "
                    "the parameter does not reach a command line"
                ),
            )
        )
        return verdict

    # -- the computing oracles --------------------------------------------

    async def _mechanism_oracle(
        self,
        target: ParamTarget,
        base: str,
        mechanism: Mechanism,
        separators: list[tuple[str, str]],
        verdict: CmdiVerdict,
    ) -> OracleResult:
        last: OracleResult | None = None

        for separator, separator_note in separators:
            left, right, product = _operands()
            expression = mechanism.template.format(left=left, right=right)
            payload = f"{base}{separator} {expression}".strip()
            # The control carries the same operands and operator as plain text,
            # so a page that echoes its input fails it. This is what rejects the
            # endpoint that prints the command line without running it.
            control = f"{base}{separator} {left}*{right}".strip()

            def detect(
                result: FetchResult,
                expected: str = str(product),
                shown: str = expression,
            ) -> Detection:
                if expected in result.text:
                    return Detection(
                        present=True, detail=f"{shown} became {expected}"
                    )
                if shown in result.text:
                    # The defining false positive for this class. The wording is
                    # deliberately free of the random operands so that three
                    # mechanisms failing this way say it once, not three times.
                    return Detection(
                        present=False,
                        detail=(
                            "the command string is echoed into the response with the "
                            "expansion unevaluated, so the page prints its input rather "
                            "than running it"
                        ),
                    )
                return Detection(present=False)

            oracle = DifferentialOracle(
                self.fetch,
                name=mechanism.name,
                signal="value the shell would have had to compute",
                detect=detect,
                payload_label=f"a probe using {mechanism.description}",
                strength=mechanism.strength,
                attempts=self._attempts,
                required=self._required,
                lone_reason=(
                    f"the parameter reaches a shell through {mechanism.description}, "
                    "which is command injection, but only one mechanism worked. Confirm "
                    "by hand and report with the computed value as proof"
                ),
            )
            result = await oracle.run(
                target.apply(payload, raw=separator == "%0a"),
                target.apply(control, raw=separator == "%0a"),
                evidence_label=f"{mechanism.name.replace('_', ' ')} via {separator_note}",
                collect=verdict.evidence,
            )
            if result.agreed:
                result.detail.update(
                    {
                        "separator": separator,
                        "mechanism": mechanism.description,
                        "spawns_process": mechanism.spawns_process,
                    }
                )
                return result
            last = result

        return last or OracleResult(
            name=mechanism.name,
            agreed=False,
            reason=f"no separator carried {mechanism.description}",
            strength=mechanism.strength,
        )

    # -- the weak oracle ---------------------------------------------------

    async def _timing_oracle(
        self, target: ParamTarget, base: str, separator: str, verdict: CmdiVerdict
    ) -> OracleResult:
        """A delay the payload asked for, separated from ordinary variance.

        The one probe here that runs a waiting command. ``sleep`` writes nothing,
        reads nothing and reaches nothing; it is included because it is the only
        oracle that works where output is discarded. It is weak by construction
        and never confirms alone.
        """
        baseline: list[float] = []
        for _ in range(3):
            _, elapsed = await self.timed_fetch(target.apply(base))
            if elapsed is not None:
                baseline.append(elapsed)
        if len(baseline) < 2:
            return OracleResult(
                name="time_differential",
                agreed=False,
                reason="could not establish a baseline response time",
                strength=OracleStrength.WEAK,
            )

        payload = f"{base}{separator} sleep {self._sleep_seconds}".strip()
        request = target.apply(payload, raw=separator == "%0a")
        samples: list[float] = []
        for _ in range(3):
            _, elapsed = await self.timed_fetch(request)
            if elapsed is not None:
                samples.append(elapsed)

        separated, explanation = timing_separation(
            baseline, samples, min_delay_ms=self._sleep_seconds * 1000
        )
        if separated:
            verdict.add(
                Evidence.comparison(
                    "time differential via sleep",
                    payload=request,
                    control=target.apply(base),
                    note=explanation,
                )
            )
            return OracleResult(
                name="time_differential",
                agreed=True,
                reason=f"a requested delay reproduced: {explanation}",
                reproduced=len(samples),
                attempts=len(samples),
                strength=OracleStrength.WEAK,
                lone_reason=_TIMING_LONE_REASON,
            )
        return OracleResult(
            name="time_differential",
            agreed=False,
            reason=explanation,
            strength=OracleStrength.WEAK,
        )
