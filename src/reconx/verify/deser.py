"""Insecure deserialization verification.

A parameter that is deserialized without integrity checking lets an attacker
craft the object graph: property injection in PHP, gadget chains in Java,
``__reduce__`` in Python's pickle. The impact is routinely remote code
execution, which is exactly why this verifier must never attempt it.

So nothing here tries to execute anything. The probes are malformed or
well-formed * inert* serialized values, and what is checked is twofold:

* ``format_differential`` — a well-formed serialized object is accepted (the
  response looks like the original page) while a corrupt one is rejected.
  A page that does not parse the parameter treats both identically, so only
  an endpoint that actually deserializes distinguishes them. This observes
  acceptance behaviour, not error text.
* ``deserialization_error`` — the corrupt value produces an error naming a
  real deserializer (``UnpicklingError``, ``StreamCorruptedException``,
  ``__PHP_Incomplete_Class`` ...), while a well-formed control does not and
  the unmodified page does not contain it either. Error text alone is the
  classic false positive — documentation pages quote these strings — which is
  why the baseline is checked before any payload and the control must stay
  clean.

Both oracles agreeing is Confirmed. Either alone is Probable at best.

**Payload conduct.** No gadget, no ``__reduce__``, no ``system``/``exec``/``eval``
string appears in any probe: the corrupt values are truncated or random bytes
that fail *before* any object is built. Demonstrating what a working gadget
reaches is the researcher's decision on a program that permits it.
"""

from __future__ import annotations

import base64
import pickle
import re
from dataclasses import dataclass

from reconx.verify.base import (
    FetchResult,
    OracleResult,
    OracleStrength,
    ParameterVerdict,
    ParameterVerifier,
    ParamTarget,
    decide_from_oracles,
)
from reconx.verify.differential import (
    Detection,
    DifferentialOracle,
    boolean_differential,
)

__all__ = [
    "DeserVerdict",
    "DeserVerifier",
    "DESER_ERROR_SIGNATURES",
    "VALID_PICKLES",
    "find_deser_signature",
]


# Error text that only a deserializer emits. Deliberately specific: matching a
# bare "error" or "exception" would fire on most of the internet.
DESER_ERROR_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("Python pickle", r"unpicklingerror"),
    ("Python pickle", r"invalid load key"),
    ("Python pickle", r"could not find MARK"),
    ("Python pickle", r"pickle data was truncated"),
    ("Python pickle", r"_pickle\."),
    ("Java", r"StreamCorruptedException"),
    ("Java", r"InvalidClassException"),
    ("Java", r"OptionalDataException"),
    ("Java", r"NotSerializableException"),
    ("Java", r"java\.io\.(?:IOException|EOFException).*stream"),
    ("PHP", r"__PHP_Incomplete_Class"),
    ("PHP", r"unserialize\(\):?\s*error at offset"),
    ("PHP", r"Error at offset \d+ of \d+ bytes"),
    (".NET", r"SerializationException"),
    (".NET", r"BinaryFormatter"),
    (".NET", r"LosFormatter"),
    ("Ruby", r"incompatible marshal"),
    ("Ruby", r"Marshal\.load"),
)

_COMPILED_SIGNATURES = tuple(
    (name, re.compile(pattern, re.IGNORECASE)) for name, pattern in DESER_ERROR_SIGNATURES
)

# Well-formed, inert serialized values. ``pickle.dumps(None)`` is ``Ti4.`` and
# ``pickle.dumps({})`` is ``fXQu``: they decode to objects with no behaviour.
# Computed at runtime rather than pasted, so the constants cannot drift from
# what the runtime actually emits.
VALID_PICKLES: tuple[str, ...] = (
    base64.b64encode(pickle.dumps(None)).decode(),
    base64.b64encode(pickle.dumps({})).decode(),
)

# Corrupt inputs: truncated streams and random bytes. They fail during parsing,
# before any object is built, so nothing here can execute.
# The first pair doubles as the format oracle's false case, so it is the same
# length as the well-formed control: on a page that merely echoes its input,
# asymmetric lengths alone would read as a differential. ``eHh4`` decodes to
# ``xxx``, which fails with ``invalid load key, 'x'``.
CORRUPT_VALUES: tuple[tuple[str, str], ...] = (
    ("malformed pickle", "eHh4"),
    ("truncated pickle", base64.b64encode(b"zzz-not-pickle!!").decode()),
    ("truncated Java stream", "rO0ABQ=="),
    ("truncated PHP object", "O:8:"),
)

# Tokens that must never appear in a probe: anything that could execute or that
# names an execution primitive. A test asserts the tables above stay clean.
_FORBIDDEN_TOKENS = (
    "system", "exec", "eval", "popen", "subprocess", "__reduce__",
    "__import__", "os.", "rce", "shell", "wget", "curl ",
)


def find_deser_signature(body: bytes) -> tuple[str, str] | None:
    """Return ``(engine, matched text)`` if a deserializer error is present."""
    text = body[:200_000].decode("utf-8", errors="replace")
    for engine, pattern in _COMPILED_SIGNATURES:
        match = pattern.search(text)
        if match:
            return engine, match.group(0)[:160]
    return None


def _detect_deser_error(result: FetchResult) -> Detection:
    found = find_deser_signature(result.body)
    if found is None:
        return Detection(present=False)
    return Detection(present=True, detail=f"{found[0]}: {found[1]}")


_FORMAT_LONE_REASON = (
    "the endpoint accepts a well-formed serialized object and rejects a corrupt "
    "one, which means it parses the parameter, but no deserializer named itself "
    "in an error; verify by hand before reporting"
)
_ERROR_LONE_REASON = (
    "a deserializer error appears under a malformed serialized value and not "
    "under a well-formed control, but nothing showed the endpoint accepts "
    "well-formed objects"
)


@dataclass
class DeserVerdict(ParameterVerdict):
    """The verification outcome for one parameter reaching a deserializer."""

    engine_hint: str | None = None

    def as_dict(self) -> dict:
        return {**super().as_dict(), "engine_hint": self.engine_hint}


class DeserVerifier(ParameterVerifier):
    """Verifies that a parameter is deserialized, without executing anything."""

    vuln_class = "deserialization"
    title = "Insecure deserialization"
    verdict_class = DeserVerdict

    async def verify(
        self, target: ParamTarget | str, parameter: str | None = None
    ) -> DeserVerdict:
        """Test one parameter and return a tiered verdict."""
        target = self.target_of(target, parameter)
        verdict: DeserVerdict = self.new_verdict(target)  # type: ignore[assignment]

        original = await self.fetch(target.apply(target.current_value or VALID_PICKLES[0]))
        if not original.ok:
            verdict.reason = (
                f"the original request could not be completed ({original.error})"
            )
            return verdict

        if self.gate_obstruction(verdict, original):
            return verdict

        baseline_fingerprint = original.response.fingerprint

        # A deserializer error already on the unmodified page makes the error
        # oracle meaningless, so it is checked before anything is injected.
        pre_existing = find_deser_signature(original.body)

        verdict.oracles.append(
            await self._format_oracle(target, baseline_fingerprint, verdict)
        )
        verdict.oracles.append(await self._error_oracle(target, pre_existing, verdict))

        verdict.apply(
            decide_from_oracles(
                verdict.oracles,
                fallback_reason="no oracle found evidence of deserialization",
            )
        )
        return verdict

    # -- oracles -----------------------------------------------------------

    async def _format_oracle(
        self, target: ParamTarget, baseline, verdict: DeserVerdict
    ) -> OracleResult:
        """A well-formed object should look like the original; a corrupt one
        should not. An endpoint that never parses the parameter answers both
        identically, which is what rejects ordinary pages."""
        return await boolean_differential(
            self.fetch,
            name="format_differential",
            true_request=target.apply(VALID_PICKLES[0]),
            false_request=target.apply(CORRUPT_VALUES[0][1]),
            baseline=baseline,
            context="serialized object handling",
            attempts=self._attempts,
            required=self._required,
            collect=verdict.evidence,
            agreed_reason="",
            lone_reason=_FORMAT_LONE_REASON,
        )

    async def _error_oracle(
        self,
        target: ParamTarget,
        pre_existing: tuple[str, str] | None,
        verdict: DeserVerdict,
    ) -> OracleResult:
        """A deserializer error the well-formed control does not produce.

        When the error text is on the page before any payload — documentation,
        a code sample, a template — the oracle stands down instead of firing,
        because its appearance under a payload would say nothing.
        """
        if pre_existing is not None:
            return OracleResult(
                name="deserialization_error",
                agreed=False,
                reason=(
                    f"a {pre_existing[0]} error string is already present in the "
                    f"unmodified page ({pre_existing[1]!r}), so its appearance under a "
                    "payload says nothing"
                ),
                detail={"pre_existing": pre_existing[1]},
            )

        last: OracleResult | None = None
        for label, corrupt in CORRUPT_VALUES:
            oracle = DifferentialOracle(
                self.fetch,
                name="deserialization_error",
                signal="deserializer error",
                detect=_detect_deser_error,
                payload_label=f"a corrupt serialized value ({label})",
                strength=OracleStrength.STRONG,
                attempts=self._attempts,
                required=self._required,
                lone_reason=_ERROR_LONE_REASON,
            )
            result = await oracle.run(
                target.apply(corrupt),
                target.apply(VALID_PICKLES[0]),
                evidence_label=f"deserializer error under {label}",
                collect=verdict.evidence,
            )
            if result.agreed:
                observed = str(result.detail.get("observed") or "")
                if ":" in observed:
                    verdict.engine_hint = observed.split(":", 1)[0]
                return result
            last = result

        return last or OracleResult(
            name="deserialization_error",
            agreed=False,
            reason="no corrupt serialized value produced a deserializer error",
            strength=OracleStrength.STRONG,
        )
