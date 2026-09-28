"""SQL injection verification.

Detecting a *possible* injection is easy and mostly wrong. Three signals are
commonly used, and each fails on its own:

* an error message, which is often already on the page for unrelated reasons,
* a slow response, which ordinary load produces constantly,
* a difference between two responses, which dynamic content produces constantly.

So nothing here is reported on one signal. A finding reaches **Confirmed** only
when at least two independent oracles agree *and* each reproduces. A timing
signal alone never confirms, because network variance imitates it too well.

Every oracle is paired with a benign control chosen to be structurally similar
to the payload. If the control produces the same response as the payload, the
difference was not caused by injection. That comparison is
:mod:`reconx.verify.differential`, shared with every other class.

All payloads here are read-only detection probes: boolean comparisons, a
deliberate syntax error, and a delay function. Nothing modifies data, chains a
second statement, reads files, or touches the operating system.
"""

from __future__ import annotations

import re
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
    set_parameter,
)
from reconx.verify.differential import (
    Detection,
    DifferentialOracle,
    boolean_differential,
)
from reconx.verify.reproduce import timing_separation

__all__ = [
    "SqliVerdict",
    "SqliVerifier",
    "DBMS_ERROR_SIGNATURES",
    "OracleResult",
    "find_error_signature",
    "set_parameter",
]


# Error text that only a database driver emits. Deliberately specific: matching
# the bare word "error" would fire on most of the internet.
DBMS_ERROR_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("MySQL", r"you have an error in your sql syntax"),
    ("MySQL", r"warning:\s+mysqli?_"),
    ("MySQL", r"mysql_fetch_(?:array|assoc|row|object)"),
    ("MySQL", r"unknown column '[^']+' in 'field list'"),
    ("MySQL", r"\bmysqlnd\b.*\bcannot\b"),
    ("PostgreSQL", r"pg_(?:query|exec|connect)\(\)"),
    ("PostgreSQL", r"unterminated quoted string at or near"),
    ("PostgreSQL", r"syntax error at or near"),
    ("PostgreSQL", r"invalid input syntax for (?:type )?(?:integer|bigint|numeric)"),
    ("MSSQL", r"unclosed quotation mark after the character string"),
    ("MSSQL", r"incorrect syntax near"),
    ("MSSQL", r"microsoft (?:ole db|sql server)"),
    ("MSSQL", r"conversion failed when converting"),
    ("Oracle", r"\bora-\d{5}\b"),
    ("Oracle", r"quoted string not properly terminated"),
    ("Oracle", r"oracle\s+(?:odbc|jdbc)"),
    ("SQLite", r"sqlite3?::"),
    ("SQLite", r"sqlite_(?:error|exception)"),
    ("SQLite", r"unrecognized token:"),
    ("SQLite", r"no such column:"),
    ("generic", r"\bsql syntax\b.*\bnear\b"),
    ("generic", r"\bquery failed\b.*\bsyntax\b"),
)

_COMPILED_SIGNATURES = tuple(
    (name, re.compile(pattern, re.IGNORECASE)) for name, pattern in DBMS_ERROR_SIGNATURES
)

# Sleep expressions per dialect, used for the timing oracle.
_SLEEP_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("MySQL", "' AND SLEEP({seconds})-- "),
    ("MySQL", " AND SLEEP({seconds})"),
    ("PostgreSQL", "' AND pg_sleep({seconds})-- "),
    ("MSSQL", "'; WAITFOR DELAY '0:0:{seconds}'-- "),
)

# Boolean pairs: (true expression, false expression). Both are read-only.
_BOOLEAN_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("single-quote string context", "' AND '1'='1", "' AND '1'='2"),
    ("numeric context", " AND 1=1", " AND 1=2"),
    ("double-quote string context", '" AND "1"="1', '" AND "1"="2'),
    ("quote-close then comment", "' OR '1'='1'-- ", "' OR '1'='2'-- "),
)

_BOOLEAN_LONE_REASON = (
    "the page responds to injected boolean logic, which is a strong signal, but no "
    "second oracle agreed; verify by hand before reporting"
)
_ERROR_LONE_REASON = (
    "a database error appears under a syntax-breaking value and not under a benign "
    "control, but no second oracle agreed"
)
_TIMING_LONE_REASON = (
    "only the timing oracle agreed. A delay is too easily imitated by load for this "
    "to be reported on its own, so it needs a human look or a second signal"
)


def find_error_signature(body: bytes) -> tuple[str, str] | None:
    """Return ``(dbms, matched text)`` if a database error is present."""
    text = body[:200_000].decode("utf-8", errors="replace")
    for dbms, pattern in _COMPILED_SIGNATURES:
        match = pattern.search(text)
        if match:
            return dbms, match.group(0)[:160]
    return None


def _detect_error(result: FetchResult) -> Detection:
    found = find_error_signature(result.body)
    if found is None:
        return Detection(present=False)
    return Detection(present=True, detail=f"{found[0]}: {found[1]}")


@dataclass
class SqliVerdict(ParameterVerdict):
    """The verification outcome for one parameter."""

    dbms_hint: str | None = None

    def as_dict(self) -> dict:
        return {**super().as_dict(), "dbms_hint": self.dbms_hint}


class SqliVerifier(ParameterVerifier):
    """Verifies a candidate SQL injection against independent oracles."""

    vuln_class = "sqli"
    title = "SQL injection"
    verdict_class = SqliVerdict

    def __init__(
        self,
        http,
        *,
        attempts: int = 3,
        required: int = 3,
        sleep_seconds: int = 3,
        enable_timing: bool = True,
    ) -> None:
        super().__init__(http, attempts=attempts, required=required)
        self._sleep_seconds = sleep_seconds
        self._enable_timing = enable_timing

    # -- entry point -------------------------------------------------------

    async def verify(
        self, target: ParamTarget | str, parameter: str | None = None
    ) -> SqliVerdict:
        """Test one parameter and return a tiered verdict."""
        target = self.target_of(target, parameter)
        verdict: SqliVerdict = self.new_verdict(target)  # type: ignore[assignment]

        original = await self.fetch(target.apply(target.current_value or "1"))
        if not original.ok:
            verdict.reason = (
                f"the original request could not be completed ({original.error})"
            )
            return verdict

        if self.gate_obstruction(verdict, original):
            return verdict

        baseline_fingerprint = original.response.fingerprint

        # A database error already on the unmodified page makes the error oracle
        # meaningless, so it is checked before anything is injected.
        pre_existing = find_error_signature(original.body)

        verdict.oracles.append(
            await self._boolean_oracle(target, baseline_fingerprint, verdict)
        )
        verdict.oracles.append(await self._error_oracle(target, pre_existing, verdict))

        if self._enable_timing:
            verdict.oracles.append(await self._timing_oracle(target, verdict))

        verdict.apply(
            decide_from_oracles(
                verdict.oracles,
                fallback_reason="no oracle found evidence of injection",
            )
        )
        return verdict

    # -- oracles -----------------------------------------------------------

    async def _boolean_oracle(
        self, target: ParamTarget, baseline, verdict: SqliVerdict
    ) -> OracleResult:
        """A true condition should look like the original; a false one should not.

        This is the strongest single signal, because it requires the application
        to respond to the *logic* of the injected expression rather than merely
        to a malformed input.
        """
        current = target.current_value or "1"
        last: OracleResult | None = None

        for label, true_suffix, false_suffix in _BOOLEAN_PAIRS:
            result = await boolean_differential(
                self.fetch,
                true_request=target.apply(current + true_suffix),
                false_request=target.apply(current + false_suffix),
                baseline=baseline,
                context=label,
                attempts=self._attempts,
                required=self._required,
                collect=verdict.evidence,
                agreed_reason="",
                lone_reason=_BOOLEAN_LONE_REASON,
            )
            if result.agreed:
                return result
            last = result

        return last or OracleResult(
            name="boolean_differential",
            agreed=False,
            reason="no boolean pair could be tested",
            strength=OracleStrength.DECISIVE,
        )

    async def _error_oracle(
        self,
        target: ParamTarget,
        pre_existing: tuple[str, str] | None,
        verdict: SqliVerdict,
    ) -> OracleResult:
        """A database error that a benign control does not also produce.

        This is the oracle that most often produces false positives elsewhere,
        because pages carry SQL error text for unrelated reasons: a logged
        message, a code sample, a template. The control request is what settles
        it — and when the error is on the page *before* any payload, there is
        nothing to settle and the oracle stands down.
        """
        if pre_existing is not None:
            return OracleResult(
                name="error_signature",
                agreed=False,
                reason=(
                    f"a {pre_existing[0]} error string is already present in the "
                    f"unmodified page ({pre_existing[1]!r}), so its appearance under a "
                    "payload says nothing"
                ),
                detail={"pre_existing": pre_existing[1]},
            )

        current = target.current_value or "1"
        # The payload breaks SQL syntax. The control is the same length and
        # character class but harmless, so a length- or type-driven difference
        # cannot be mistaken for injection.
        oracle = DifferentialOracle(
            self.fetch,
            name="error_signature",
            signal="database error",
            detect=_detect_error,
            payload_label="a syntax-breaking value",
            strength=OracleStrength.STRONG,
            attempts=self._attempts,
            required=self._required,
            lone_reason=_ERROR_LONE_REASON,
        )
        result = await oracle.run(
            target.apply(current + "'"),
            target.apply(current + "x"),
            evidence_label="error signature with benign control",
            collect=verdict.evidence,
        )
        if result.agreed:
            observed = str(result.detail.get("observed") or "")
            if ":" in observed:
                verdict.dbms_hint = observed.split(":", 1)[0]
        return result

    async def _timing_oracle(
        self, target: ParamTarget, verdict: SqliVerdict
    ) -> OracleResult:
        """A delay the payload asked for, separated from ordinary variance.

        Never sufficient on its own. It is included because it is the only
        oracle that works on a blind injection, but it is the weakest and
        :func:`~reconx.verify.base.decide_from_oracles` treats it as such.
        """
        current = target.current_value or "1"

        baseline_samples: list[float] = []
        for _ in range(3):
            _, elapsed = await self.timed_fetch(target.apply(current))
            if elapsed is not None:
                baseline_samples.append(elapsed)

        if len(baseline_samples) < 2:
            return OracleResult(
                name="time_differential",
                agreed=False,
                reason="could not establish a baseline response time",
                strength=OracleStrength.WEAK,
            )

        min_delay_ms = self._sleep_seconds * 1000
        for dialect, template in _SLEEP_PAYLOADS:
            request = target.apply(
                current + template.format(seconds=self._sleep_seconds)
            )

            payload_samples: list[float] = []
            for _ in range(3):
                _, elapsed = await self.timed_fetch(request)
                if elapsed is not None:
                    payload_samples.append(elapsed)

            if len(payload_samples) < 2:
                continue

            separated, explanation = timing_separation(
                baseline_samples, payload_samples, min_delay_ms=min_delay_ms
            )
            if separated:
                verdict.dbms_hint = verdict.dbms_hint or dialect
                verdict.add(
                    Evidence.comparison(
                        f"time differential ({dialect})",
                        payload=request,
                        note=explanation,
                        dialect=dialect,
                    )
                )
                return OracleResult(
                    name="time_differential",
                    agreed=True,
                    reason=f"{dialect} delay reproduced: {explanation}",
                    detail={"dialect": dialect},
                    reproduced=len(payload_samples),
                    attempts=len(payload_samples),
                    strength=OracleStrength.WEAK,
                    lone_reason=_TIMING_LONE_REASON,
                )

        return OracleResult(
            name="time_differential",
            agreed=False,
            reason="no delay payload produced a response time separable from variance",
            strength=OracleStrength.WEAK,
        )
