"""CORS misconfiguration verification.

Almost everything reported as a CORS bug is not one. ``Access-Control-Allow-Origin: *``
is how a public API is *supposed* to be configured, and browsers already refuse
to send credentials to a wildcard origin, so reporting it costs credibility and
teaches a triager to close your reports unread.

What is actually a vulnerability is narrower: the response **reflects whatever
origin asked** and **allows credentials with it**. Together those mean any website
can make an authenticated request as the visitor and read the answer. Either one
alone is nothing.

So two independent oracles must both agree, and each has its own control:

* ``origin_reflected`` — an arbitrary attacker-controlled origin comes back in
  ``Access-Control-Allow-Origin`` verbatim. The control is a second, differently
  shaped origin: reflecting both is reflection, while a fixed allowlisted value
  that happens to match one of them is not.
* ``credentials_allowed`` — ``Access-Control-Allow-Credentials: true`` is sent
  alongside that reflected origin. The control is a request with no ``Origin`` at
  all, which shows the header is a response to the origin rather than a constant.

Two subtler variants are checked because they are the ones real applications get
wrong: an origin built from the target's own domain as a *prefix* or *suffix*
(``target.com.evil.example``, ``eviltarget.com``), which a naive substring
allowlist accepts. These are reported as the same class with the matching rule
named, because the fix is different: it is the comparison, not the reflection.

Nothing here sends credentials. The probes are unauthenticated, and the finding
rests on what the target *promises* it would allow.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

from reconx.db.models import FindingTier
from reconx.verify.base import (
    Evidence,
    FetchResult,
    OracleResult,
    OracleStrength,
    ParameterVerdict,
    ParameterVerifier,
    ParamTarget,
    PreparedRequest,
    decide_from_oracles,
)

__all__ = ["CorsVerdict", "CorsVerifier", "attacker_origins"]

_ACAO = "access-control-allow-origin"
_ACAC = "access-control-allow-credentials"


def attacker_origins(target_host: str) -> list[tuple[str, str]]:
    """Origins to try, paired with the flaw each one would reveal.

    Order matters: the plain arbitrary origin comes first, because if that is
    reflected there is no point reasoning about allowlist bypasses.
    """
    token = secrets.token_hex(4)
    bare = target_host.split(":")[0]
    return [
        (f"https://rx{token}.example.com", "any origin is reflected"),
        (
            f"https://{bare}.rx{token}.example.com",
            "an allowlist matching the target domain as a prefix accepts it",
        ),
        (
            f"https://rx{token}{bare}",
            "an allowlist matching the target domain as a suffix accepts it",
        ),
        (
            "null",
            "the null origin is allowed, which a sandboxed iframe or a local file "
            "can send",
        ),
    ]


@dataclass
class CorsVerdict(ParameterVerdict):
    """The verification outcome for one URL's cross-origin policy."""

    reflected_origin: str | None = None
    allows_credentials: bool = False
    matching_rule: str = ""
    wildcard_only: bool = False

    def as_dict(self) -> dict:
        return {
            **super().as_dict(),
            "reflected_origin": self.reflected_origin,
            "allows_credentials": self.allows_credentials,
            "matching_rule": self.matching_rule,
            "wildcard_only": self.wildcard_only,
        }


class CorsVerifier(ParameterVerifier):
    """Verifies that a response both reflects an arbitrary origin and allows credentials."""

    vuln_class = "cors_misconfiguration"
    title = "CORS misconfiguration"
    verdict_class = CorsVerdict

    async def verify(
        self, target: ParamTarget | str, parameter: str | None = None
    ) -> CorsVerdict:
        """``target`` is a URL. The parameter argument is accepted and unused.

        CORS is a property of a response, not of a parameter, so the signature
        matches the other verifiers only so the stage can treat them alike.
        """
        target = self.target_of(target, parameter or "")
        verdict: CorsVerdict = self.new_verdict(target)  # type: ignore[assignment]
        url = target.url
        host = urlsplit(url).hostname or ""

        # Baseline: what does the response look like with no Origin at all? This
        # is the control for the credentials oracle.
        plain = await self.fetch(PreparedRequest(url=url))
        if not plain.ok:
            verdict.reason = f"the request could not be completed ({plain.error})"
            return verdict
        if self.gate_obstruction(verdict, plain):
            return verdict

        plain_acao = plain.header(_ACAO).strip()
        if not plain_acao:
            # Ask once with an origin before deciding there is no CORS policy at
            # all: plenty of endpoints emit the header only when asked to.
            pass

        reflected: tuple[str, str, FetchResult] | None = None
        wildcard_seen = False

        for origin, rule in attacker_origins(host):
            probed = await self.fetch(
                PreparedRequest(url=url, headers={"Origin": origin})
            )
            if not probed.ok:
                continue
            allowed = probed.header(_ACAO).strip()
            if allowed == "*":
                wildcard_seen = True
                continue
            if allowed and allowed.rstrip("/") == origin.rstrip("/"):
                reflected = (origin, rule, probed)
                break

        if reflected is None:
            verdict.wildcard_only = wildcard_seen
            verdict.tier = FindingTier.DISCARDED
            verdict.confidence = 0
            verdict.reason = (
                "the endpoint answers every origin with the wildcard '*', which browsers "
                "already refuse to send credentials to. That is the intended "
                "configuration for a public API, not a finding"
                if wildcard_seen
                else (
                    "no origin sent was reflected in Access-Control-Allow-Origin, so "
                    "the policy is not attacker-controlled"
                )
            )
            verdict.oracles.append(
                OracleResult(
                    name="origin_reflected",
                    agreed=False,
                    reason=verdict.reason,
                    strength=OracleStrength.DECISIVE,
                )
            )
            return verdict

        origin, rule, probed = reflected
        verdict.reflected_origin = origin
        verdict.matching_rule = rule

        # --- oracle 1: is the reflection real, or did one value coincide? ---
        second_origin = f"https://rx{secrets.token_hex(4)}.example.net"
        second = await self.fetch(PreparedRequest(url=url, headers={"Origin": second_origin}))
        second_reflected = (
            second.ok and second.header(_ACAO).strip().rstrip("/") == second_origin
        )
        verdict.oracles.append(
            OracleResult(
                name="origin_reflected",
                agreed=bool(second_reflected),
                reason=(
                    f"two unrelated origins were both reflected verbatim ({origin} and "
                    f"{second_origin}), so the value is copied from the request rather "
                    f"than matched against a list; {rule}"
                    if second_reflected
                    else (
                        f"{origin} was allowed but a second unrelated origin "
                        f"({second_origin}) was not, so the policy is a list rather "
                        "than a reflection. Check whether the allowed value is one an "
                        "attacker can obtain"
                    )
                ),
                detail={"rule": rule},
                strength=OracleStrength.DECISIVE,
                lone_reason=(
                    "an arbitrary origin is reflected, but credentials are not allowed "
                    "with it, so a cross-origin reader gets only what an unauthenticated "
                    "request would already return. Report it only if the data itself is "
                    "sensitive"
                ),
            )
        )

        # --- oracle 2: would the browser send credentials? ------------------
        credentials = probed.header(_ACAC).strip().lower() == "true"
        baseline_credentials = plain.header(_ACAC).strip().lower() == "true"
        verdict.allows_credentials = credentials
        verdict.oracles.append(
            OracleResult(
                name="credentials_allowed",
                agreed=credentials,
                reason=(
                    "Access-Control-Allow-Credentials: true accompanies the reflected "
                    "origin, so a browser will send the visitor's cookies and let the "
                    "attacking page read the response"
                    + (
                        ""
                        if baseline_credentials
                        else " (and the header is absent without an Origin, so it is a "
                        "response to the origin rather than a constant)"
                    )
                    if credentials
                    else (
                        "credentials are not allowed, so a cross-origin page can read "
                        "only what it could already fetch unauthenticated"
                    )
                ),
                strength=OracleStrength.STRONG,
            )
        )

        verdict.add(
            Evidence.comparison(
                "reflected origin with credentials",
                payload=probed.request,
                control=plain.request,
                roles=("with attacker origin", "without an origin"),
                note=(
                    f"Access-Control-Allow-Origin: {probed.header(_ACAO)}; "
                    f"Access-Control-Allow-Credentials: {probed.header(_ACAC) or 'absent'}"
                ),
                matching_rule=rule,
                response_status=probed.status,
            )
        )

        verdict.apply(
            decide_from_oracles(
                verdict.oracles,
                fallback_reason="the cross-origin policy is not attacker-controlled",
            )
        )
        return verdict
