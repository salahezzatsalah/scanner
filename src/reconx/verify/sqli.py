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
difference was not caused by injection.

All payloads here are read-only detection probes: boolean comparisons, a
deliberate syntax error, and a delay function. Nothing modifies data, chains a
second statement, reads files, or touches the operating system.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from reconx.db.models import FindingTier
from reconx.net.fingerprint import ResponseFingerprint
from reconx.verify.reproduce import reproduce, timing_separation
from reconx.verify.waf import WafState, classify_response

__all__ = ["SqliVerdict", "SqliVerifier", "DBMS_ERROR_SIGNATURES", "set_parameter"]


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


def set_parameter(url: str, name: str, value: str) -> str:
    """Return ``url`` with query parameter ``name`` set to ``value``."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = [(key, value if key == name else existing) for key, existing in pairs]
    if not any(key == name for key, _ in pairs):
        replaced.append((name, value))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(replaced, doseq=True), "")
    )


def find_error_signature(body: bytes) -> tuple[str, str] | None:
    """Return ``(dbms, matched text)`` if a database error is present."""
    text = body[:200_000].decode("utf-8", errors="replace")
    for dbms, pattern in _COMPILED_SIGNATURES:
        match = pattern.search(text)
        if match:
            return dbms, match.group(0)[:160]
    return None


@dataclass
class OracleResult:
    """One independent line of evidence."""

    name: str
    agreed: bool
    reason: str
    detail: dict = field(default_factory=dict)
    reproduced: int = 0
    attempts: int = 0


@dataclass
class SqliVerdict:
    """The verification outcome for one parameter."""

    url: str
    parameter: str
    tier: FindingTier
    confidence: int
    oracles: list[OracleResult] = field(default_factory=list)
    dbms_hint: str | None = None
    reason: str = ""
    evidence: list[dict] = field(default_factory=list)
    obstructed: bool = False

    @property
    def agreeing(self) -> list[str]:
        return [oracle.name for oracle in self.oracles if oracle.agreed]

    @property
    def vulnerable(self) -> bool:
        return self.tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE)

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "tier": self.tier.value,
            "confidence": self.confidence,
            "agreeing_oracles": self.agreeing,
            "dbms_hint": self.dbms_hint,
            "reason": self.reason,
            "obstructed": self.obstructed,
            "oracles": [
                {
                    "name": o.name, "agreed": o.agreed, "reason": o.reason,
                    "reproduced": f"{o.reproduced}/{o.attempts}",
                }
                for o in self.oracles
            ],
        }


class SqliVerifier:
    """Verifies a candidate SQL injection against independent oracles."""

    def __init__(
        self,
        http,
        *,
        attempts: int = 3,
        required: int = 3,
        sleep_seconds: int = 3,
        enable_timing: bool = True,
    ) -> None:
        self._http = http
        self._attempts = attempts
        self._required = required
        self._sleep_seconds = sleep_seconds
        self._enable_timing = enable_timing

    # -- entry point -------------------------------------------------------

    async def verify(self, url: str, parameter: str) -> SqliVerdict:
        """Test one query parameter and return a tiered verdict."""
        verdict = SqliVerdict(
            url=url, parameter=parameter, tier=FindingTier.DISCARDED, confidence=0
        )

        original = await self._fetch(url)
        if original is None:
            verdict.reason = "the original request could not be completed"
            return verdict

        obstruction = classify_response(
            status=original[0].status, headers=original[0].headers, body=original[0].body
        )
        if obstruction.state is not WafState.CLEAN:
            verdict.obstructed = True
            verdict.tier = FindingTier.NEEDS_REVIEW
            verdict.reason = (
                f"the host was {obstruction.state.value} before testing began, so no "
                "result from it can be trusted; re-test when it is responsive"
            )
            return verdict

        baseline_fingerprint = original[0].fingerprint

        # --- oracle 1: does the page already contain a database error? ----
        pre_existing = find_error_signature(original[0].body)

        boolean_oracle = await self._boolean_oracle(
            url, parameter, baseline_fingerprint, verdict
        )
        verdict.oracles.append(boolean_oracle)

        error_oracle = await self._error_oracle(url, parameter, pre_existing, verdict)
        verdict.oracles.append(error_oracle)

        if self._enable_timing:
            verdict.oracles.append(await self._timing_oracle(url, parameter, verdict))

        self._decide(verdict)
        return verdict

    # -- oracles -----------------------------------------------------------

    async def _boolean_oracle(
        self,
        url: str,
        parameter: str,
        baseline: ResponseFingerprint,
        verdict: SqliVerdict,
    ) -> OracleResult:
        """A true condition should look like the original; a false one should not.

        This is the strongest single signal, because it requires the application
        to respond to the *logic* of the injected expression rather than merely
        to a malformed input.
        """
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        current = next((value for key, value in pairs if key == parameter), "1")

        for label, true_suffix, false_suffix in _BOOLEAN_PAIRS:
            true_url = set_parameter(url, parameter, current + true_suffix)
            false_url = set_parameter(url, parameter, current + false_suffix)

            async def probe(_index: int, t=true_url, f=false_url) -> tuple[bool, str | None]:
                true_response = await self._fetch(t)
                false_response = await self._fetch(f)
                if true_response is None or false_response is None:
                    return False, "a request failed"
                true_fp = true_response[0].fingerprint
                false_fp = false_response[0].fingerprint

                # The pair must disagree with each other, and the true case must
                # match the original. Both halves matter: dynamic content makes
                # any two responses differ, so "differs" alone proves nothing.
                differ = not true_fp.looks_same_as(false_fp)
                true_like_original = true_fp.looks_same_as(baseline)
                if differ and true_like_original:
                    return True, (
                        f"true/false similarity {true_fp.similarity(false_fp):.2f}, "
                        f"true/original {true_fp.similarity(baseline):.2f}"
                    )
                return False, (
                    f"true/false similarity {true_fp.similarity(false_fp):.2f}, "
                    f"true/original {true_fp.similarity(baseline):.2f}"
                )

            outcome = await reproduce(
                probe, attempts=self._attempts, required=self._required
            )
            if outcome.stable:
                verdict.evidence.append(
                    {
                        "label": f"boolean differential ({label})",
                        "true_url": true_url,
                        "false_url": false_url,
                        "note": outcome.attempts[-1].detail,
                    }
                )
                return OracleResult(
                    name="boolean_differential",
                    agreed=True,
                    reason=(
                        f"a true condition in {label} returned the original page while a "
                        f"false condition returned something different; {outcome.explain()}"
                    ),
                    detail={"context": label},
                    reproduced=outcome.successes,
                    attempts=outcome.total,
                )

        return OracleResult(
            name="boolean_differential",
            agreed=False,
            reason=(
                "no boolean pair produced the true-matches-original and "
                "false-differs pattern, so the page does not respond to injected logic"
            ),
        )

    async def _error_oracle(
        self,
        url: str,
        parameter: str,
        pre_existing: tuple[str, str] | None,
        verdict: SqliVerdict,
    ) -> OracleResult:
        """A database error that a benign control does not also produce.

        This is the oracle that most often produces false positives elsewhere,
        because pages carry SQL error text for unrelated reasons: a logged
        message, a code sample, a template. The control request is what settles
        it.
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

        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        current = next((value for key, value in pairs if key == parameter), "1")

        # The payload breaks SQL syntax. The control is the same length and
        # character class but harmless, so a length- or type-driven difference
        # cannot be mistaken for injection.
        payload_url = set_parameter(url, parameter, current + "'")
        control_url = set_parameter(url, parameter, current + "x")

        async def probe(_index: int) -> tuple[bool, str | None]:
            payload = await self._fetch(payload_url)
            control = await self._fetch(control_url)
            if payload is None or control is None:
                return False, "a request failed"
            payload_error = find_error_signature(payload[0].body)
            control_error = find_error_signature(control[0].body)
            if payload_error and not control_error:
                return True, f"{payload_error[0]}: {payload_error[1]}"
            if payload_error and control_error:
                return False, "the benign control produced the same error"
            return False, "no database error appeared"

        outcome = await reproduce(probe, attempts=self._attempts, required=self._required)

        if outcome.stable:
            detail = outcome.attempts[-1].detail or ""
            dbms = detail.split(":", 1)[0] if ":" in detail else None
            if dbms:
                verdict.dbms_hint = dbms
            verdict.evidence.append(
                {
                    "label": "error signature with benign control",
                    "payload_url": payload_url,
                    "control_url": control_url,
                    "note": detail,
                }
            )
            return OracleResult(
                name="error_signature",
                agreed=True,
                reason=(
                    f"a syntax-breaking value produced a database error that the "
                    f"benign control did not ({detail}); {outcome.explain()}"
                ),
                detail={"dbms": dbms},
                reproduced=outcome.successes,
                attempts=outcome.total,
            )

        return OracleResult(
            name="error_signature",
            agreed=False,
            reason=(
                outcome.attempts[-1].detail
                if outcome.attempts and outcome.attempts[-1].detail
                else "no database error was produced"
            ),
            reproduced=outcome.successes,
            attempts=outcome.total,
        )

    async def _timing_oracle(
        self, url: str, parameter: str, verdict: SqliVerdict
    ) -> OracleResult:
        """A delay the payload asked for, separated from ordinary variance.

        Never sufficient on its own. It is included because it is the only
        oracle that works on a blind injection, but it is the weakest and is
        treated as such by :meth:`_decide`.
        """
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        current = next((value for key, value in pairs if key == parameter), "1")

        baseline_samples: list[float] = []
        for _ in range(3):
            timing = await self._timed_fetch(url)
            if timing is not None:
                baseline_samples.append(timing)

        if len(baseline_samples) < 2:
            return OracleResult(
                name="time_differential",
                agreed=False,
                reason="could not establish a baseline response time",
            )

        min_delay_ms = self._sleep_seconds * 1000
        for dialect, template in _SLEEP_PAYLOADS:
            payload = current + template.format(seconds=self._sleep_seconds)
            payload_url = set_parameter(url, parameter, payload)

            payload_samples: list[float] = []
            for _ in range(3):
                timing = await self._timed_fetch(payload_url)
                if timing is not None:
                    payload_samples.append(timing)

            if len(payload_samples) < 2:
                continue

            separated, explanation = timing_separation(
                baseline_samples, payload_samples, min_delay_ms=min_delay_ms
            )
            if separated:
                verdict.dbms_hint = verdict.dbms_hint or dialect
                verdict.evidence.append(
                    {
                        "label": f"time differential ({dialect})",
                        "payload_url": payload_url,
                        "note": explanation,
                    }
                )
                return OracleResult(
                    name="time_differential",
                    agreed=True,
                    reason=f"{dialect} delay reproduced: {explanation}",
                    detail={"dialect": dialect},
                    reproduced=len(payload_samples),
                    attempts=len(payload_samples),
                )

        return OracleResult(
            name="time_differential",
            agreed=False,
            reason="no delay payload produced a response time separable from variance",
        )

    # -- decision ----------------------------------------------------------

    def _decide(self, verdict: SqliVerdict) -> None:
        """Turn agreeing oracles into a tier.

        Two independent oracles agreeing is the bar for Confirmed. One strong
        oracle is Probable, which is worth a researcher's time but not worth
        submitting unverified. Timing alone is Needs review, never better.
        """
        agreed = [oracle for oracle in verdict.oracles if oracle.agreed]
        names = {oracle.name for oracle in agreed}

        if len(agreed) >= 2:
            verdict.tier = FindingTier.CONFIRMED
            verdict.confidence = 95 if "boolean_differential" in names else 88
            verdict.reason = (
                f"{len(agreed)} independent oracles agree ({', '.join(sorted(names))}), "
                "each reproduced across repeated attempts"
            )
            return

        if names == {"boolean_differential"}:
            verdict.tier = FindingTier.PROBABLE
            verdict.confidence = 70
            verdict.reason = (
                "the page responds to injected boolean logic, which is a strong "
                "signal, but no second oracle agreed; verify by hand before reporting"
            )
            return

        if names == {"error_signature"}:
            verdict.tier = FindingTier.PROBABLE
            verdict.confidence = 60
            verdict.reason = (
                "a database error appears under a syntax-breaking value and not under "
                "a benign control, but no second oracle agreed"
            )
            return

        if names == {"time_differential"}:
            verdict.tier = FindingTier.NEEDS_REVIEW
            verdict.confidence = 40
            verdict.reason = (
                "only the timing oracle agreed. A delay is too easily imitated by "
                "load for this to be reported on its own, so it needs a human look "
                "or a second signal"
            )
            return

        verdict.tier = FindingTier.DISCARDED
        verdict.confidence = 0
        verdict.reason = "; ".join(
            oracle.reason for oracle in verdict.oracles if not oracle.agreed
        ) or "no oracle found evidence of injection"

    # -- transport ---------------------------------------------------------

    async def _fetch(self, url: str):
        try:
            response = await self._http.get(url)
        except Exception:
            return None
        return (response,)

    async def _timed_fetch(self, url: str) -> float | None:
        started = time.monotonic()
        try:
            await self._http.get(url)
        except Exception:
            return None
        return (time.monotonic() - started) * 1000
