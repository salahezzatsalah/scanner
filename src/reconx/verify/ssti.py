"""Server-side template injection verification.

The signal that matters is **evaluation**: the server computed something. That is
easy to state and easy to get wrong, because the usual probe is ``{{7*7}}`` and
the usual mistake is reporting any page where the braces come back, or where the
digits ``49`` appear somewhere.

Two things make it checkable:

* **The expected value must not be in the request.** Operands are random per
  probe, so the product is a number the payload never contained. Reflection
  cannot produce it; only arithmetic can.
* **The control must not produce it.** The same operands and the same operator
  sent *without* the delimiters is the control. If the value appears in both, the
  page is echoing input, not evaluating it.

Two independent oracles, which is what separates this from a single observation
seen twice:

* ``expression_evaluated`` — an arithmetic expression yields its product.
* ``dialect_identified`` — a second expression whose result is *specific to a
  template dialect* yields that dialect's answer: ``{{4*'7'}}`` is ``7777`` in
  Jinja2 and Twig, an error elsewhere, and ``${7*7}`` is ``49`` in expression
  language but inert in Jinja2. This is independent because it tests a different
  expression type and a different parser path, and it names the engine, which is
  what turns the finding into a report a triager can act on.

Every expression here is pure arithmetic or string repetition. Nothing reads an
object graph, reaches for a class hierarchy, imports a module, or attempts a
sandbox escape. The finding is that the template engine evaluates attacker input;
demonstrating how far that reaches is the researcher's decision, on a program
that permits it.
"""

from __future__ import annotations

import random
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
from reconx.verify.differential import Detection, DifferentialOracle

__all__ = ["TEMPLATE_DIALECTS", "SstiVerdict", "SstiVerifier"]


@dataclass(frozen=True)
class TemplateDialect:
    """One template syntax, and expressions that identify it."""

    name: str
    #: Wraps an expression, e.g. ``"{{%s}}"``.
    wrapper: str
    engines: str
    #: An expression form only this family evaluates, as a format string taking
    #: a count and a digit, and the function producing what it should yield.
    fingerprint: str = ""
    fingerprint_note: str = ""


TEMPLATE_DIALECTS: tuple[TemplateDialect, ...] = (
    TemplateDialect(
        name="curly-brace",
        wrapper="{{%s}}",
        engines="Jinja2, Twig, Nunjucks, Handlebars-with-helpers",
        fingerprint="{{%(count)d*'%(digit)s'}}",
        fingerprint_note="string repetition, which Jinja2 and Twig answer and others reject",
    ),
    TemplateDialect(
        name="dollar-brace",
        wrapper="${%s}",
        engines="expression language (Java), Velocity, Thymeleaf, JavaScript templates",
        fingerprint="${'%(digit)s'.repeat(%(count)d)}",
        fingerprint_note="a JavaScript string method, which only that family exposes",
    ),
    TemplateDialect(
        name="hash-brace",
        wrapper="#{%s}",
        engines="Ruby interpolation, JSF, Thymeleaf",
    ),
    TemplateDialect(
        name="angle-percent",
        wrapper="<%%= %s %%>",
        engines="ERB, EJS, JSP",
    ),
    TemplateDialect(
        name="smarty",
        wrapper="{%s}",
        engines="Smarty, Mako",
    ),
)


@dataclass
class SstiVerdict(ParameterVerdict):
    """The verification outcome for one parameter in a template context."""

    dialect: str = ""
    engines: str = ""

    def as_dict(self) -> dict:
        return {**super().as_dict(), "dialect": self.dialect, "engines": self.engines}


def _operands() -> tuple[int, int, int]:
    """Two operands whose product appears nowhere in the request.

    Both are chosen so the product has more digits than either operand, which
    rules out the product being a substring of the payload.
    """
    while True:
        left = random.randint(1001, 9999)
        right = random.randint(11, 97)
        product = left * right
        if str(product) not in (str(left) + str(right)):
            return left, right, product


class SstiVerifier(ParameterVerifier):
    """Verifies that a parameter is evaluated as a template rather than printed."""

    vuln_class = "template_injection"
    title = "Server-side template injection"
    verdict_class = SstiVerdict

    async def verify(
        self, target: ParamTarget | str, parameter: str | None = None
    ) -> SstiVerdict:
        target = self.target_of(target, parameter)
        verdict: SstiVerdict = self.new_verdict(target)  # type: ignore[assignment]

        original = await self.fetch(target.apply(target.current_value or "reconx"))
        if not original.ok:
            verdict.reason = (
                f"the original request could not be completed ({original.error})"
            )
            return verdict
        if self.gate_obstruction(verdict, original):
            return verdict

        dialect = await self._find_dialect(target, verdict)
        if dialect is None:
            verdict.apply(
                decide_from_oracles(
                    verdict.oracles,
                    fallback_reason=(
                        "no template syntax was evaluated: the value is printed as data, "
                        "not parsed as a template"
                    ),
                )
            )
            return verdict

        verdict.dialect = dialect.name
        verdict.engines = dialect.engines
        verdict.oracles.append(await self._fingerprint_oracle(target, dialect, verdict))

        verdict.apply(decide_from_oracles(verdict.oracles))
        if verdict.vulnerable:
            verdict.reason += (
                f". The syntax is {dialect.name}, which is used by {dialect.engines}"
            )
        return verdict

    # -- oracle 1: is anything evaluated at all? ---------------------------

    async def _find_dialect(
        self, target: ParamTarget, verdict: SstiVerdict
    ) -> TemplateDialect | None:
        """Try each syntax until one computes. The first hit is the oracle."""
        last: OracleResult | None = None

        for dialect in TEMPLATE_DIALECTS:
            left, right, product = _operands()
            expression = f"{left}*{right}"
            payload = dialect.wrapper % expression

            def detect(
                result: FetchResult,
                expected: str = str(product),
                shown: str = expression,
                sent: str = payload,
                syntax: str = dialect.name,
            ) -> Detection:
                if expected in result.text:
                    return Detection(
                        present=True,
                        detail=f"the expression {shown} was replaced by {expected}",
                    )
                # The common false positive: the delimiters come back intact. A
                # scanner that reports "template syntax is reflected" fires here;
                # nothing was evaluated, so it is data, not a template.
                if sent in result.text:
                    return Detection(
                        present=False,
                        detail=(
                            f"the {syntax} delimiters are reflected into the page "
                            f"untouched ({sent!r}), so the value is printed as data "
                            "rather than parsed as a template"
                        ),
                    )
                return Detection(present=False)

            oracle = DifferentialOracle(
                self.fetch,
                name="expression_evaluated",
                signal="computed value the request never contained",
                detect=detect,
                payload_label=f"a {dialect.name} arithmetic expression",
                strength=OracleStrength.DECISIVE,
                attempts=self._attempts,
                required=self._required,
                lone_reason=(
                    "the server evaluates arithmetic in this parameter, which is "
                    "template injection, but the engine could not be identified from a "
                    "second expression. Report it, and say which engine you suspect"
                ),
            )
            result = await oracle.run(
                target.apply(payload),
                # The control carries the same operands and operator with no
                # delimiters, so a page that merely echoes digits fails it.
                target.apply(expression),
                evidence_label=f"{dialect.name} arithmetic with an undelimited control",
                collect=verdict.evidence,
            )
            if result.agreed:
                result.detail.update({"dialect": dialect.name, "expression": expression})
                verdict.oracles.append(result)
                return dialect
            last = result

        if last is not None:
            verdict.oracles.append(last)
        return None

    # -- oracle 2: which engine? -------------------------------------------

    async def _fingerprint_oracle(
        self, target: ParamTarget, dialect: TemplateDialect, verdict: SstiVerdict
    ) -> OracleResult:
        """A second expression whose answer is specific to one engine family.

        Independent of the first: a different expression type, a different parser
        path, and a different expected value. An application that evaluates
        arithmetic through an accident of formatting will not also perform string
        repetition.
        """
        if not dialect.fingerprint:
            return OracleResult(
                name="dialect_identified",
                agreed=False,
                reason=(
                    f"the {dialect.name} syntax evaluates arithmetic, but ReconX has no "
                    "engine-specific expression for it, so the engine is unidentified"
                ),
                strength=OracleStrength.STRONG,
            )

        count = random.randint(4, 9)
        digit = str(random.randint(2, 9))
        expected = digit * count
        payload = dialect.fingerprint % {"count": count, "digit": digit}

        def detect(result: FetchResult) -> Detection:
            if expected in result.text:
                return Detection(
                    present=True, detail=f"{dialect.fingerprint_note} produced {expected}"
                )
            return Detection(present=False)

        oracle = DifferentialOracle(
            self.fetch,
            name="dialect_identified",
            signal="engine-specific expression result",
            detect=detect,
            payload_label=f"a {dialect.name} {dialect.fingerprint_note.split(',')[0]} expression",
            strength=OracleStrength.STRONG,
            attempts=self._attempts,
            required=self._required,
        )
        result = await oracle.run(
            target.apply(payload),
            # Control: the same characters with the delimiters removed.
            target.apply(payload.strip("{}$#<>%= ")),
            evidence_label=f"{dialect.name} engine fingerprint",
            collect=verdict.evidence,
        )
        result.detail.update({"dialect": dialect.name, "engines": dialect.engines})
        return result
