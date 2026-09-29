"""Open redirect verification.

An open redirect is trivially easy to claim and routinely wrong. Three things
get reported as one:

* a parameter that *contains* a URL, which proves nothing,
* a redirect to somewhere on the target's own site, which is the feature,
* a redirect that the application's own allowlist actually blocked, where the
  scanner read a reflected value out of the response body and called it a hop.

So the question asked here is narrow and checkable: **did the response tell the
browser to go to a host we named, when a benign value would have kept it on the
target's own host?**

Two independent oracles, because applications filter one and not the other far
more often than they filter both:

* ``absolute_location`` — an absolute ``https://sentinel/`` value lands in the
  ``Location`` header.
* ``scheme_relative_location`` — a protocol-relative ``//sentinel/`` value does
  too. Its control is the same string with one slash, which stays on the target.

The sentinel host is in the ``.invalid`` top-level domain, which RFC 2606
reserves and DNS can never resolve, and redirects are not followed while this
runs. So the host we claim to be redirected to is never contacted: the finding
rests on what the target *said*, which is all an open redirect is.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from reconx.verify.base import (
    FetchResult,
    OracleStrength,
    ParameterVerdict,
    ParameterVerifier,
    ParamTarget,
    decide_from_oracles,
)
from reconx.verify.differential import Detection, DifferentialOracle

__all__ = ["SENTINEL_SUFFIX", "RedirectVerdict", "RedirectVerifier", "sentinel_host"]

#: Reserved by RFC 2606: no resolver will ever return an address for it, so a
#: redirect we claim to have induced can never become a request to a real host.
SENTINEL_SUFFIX = "redirect-check.invalid"

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
#: Values a control uses. Same shape as the payload, on the target's own site.
_CONTROL_PATHS = ("/account", "/")


def sentinel_host() -> str:
    """A fresh unresolvable host, so two parallel scans cannot confuse each other."""
    return f"rx{secrets.token_hex(4)}.{SENTINEL_SUFFIX}"


def redirect_target(result: FetchResult) -> str | None:
    """Where this response sends a browser, if anywhere.

    Only the ``Location`` header counts. A URL that merely appears in the body is
    not a redirect, and treating it as one is the most common way this class is
    false-positived.
    """
    if result.response is None or result.status not in _REDIRECT_STATUSES:
        return None
    location = result.header("location")
    if not location:
        return None
    return urljoin(result.request.url, location)


@dataclass
class RedirectVerdict(ParameterVerdict):
    """The verification outcome for one redirect parameter."""


class RedirectVerifier(ParameterVerifier):
    """Verifies that a parameter controls where the target sends a browser."""

    vuln_class = "open_redirect"
    title = "Open redirect"
    verdict_class = RedirectVerdict

    async def verify(
        self, target: ParamTarget | str, parameter: str | None = None
    ) -> RedirectVerdict:
        target = self.target_of(target, parameter)
        verdict: RedirectVerdict = self.new_verdict(target)  # type: ignore[assignment]
        host = sentinel_host()

        original = await self.fetch(
            target.apply(target.current_value or _CONTROL_PATHS[0], follow_redirects=False)
        )
        if not original.ok:
            verdict.reason = (
                f"the original request could not be completed ({original.error})"
            )
            return verdict
        if self.gate_obstruction(verdict, original):
            return verdict

        own_host = (urlsplit(target.url).hostname or "").lower()

        def lands_on_sentinel(result: FetchResult) -> Detection:
            destination = redirect_target(result)
            if destination is None:
                # The single most common false positive in this class: the value
                # is printed into the page, and a scanner that searches the whole
                # response for its sentinel calls that a redirect.
                if host in result.text:
                    return Detection(
                        present=False,
                        detail=(
                            "the value is reflected into the response body but no "
                            "Location header points at it, so nothing redirects"
                        ),
                    )
                return Detection(present=False)
            reached = (urlsplit(destination).hostname or "").lower()
            if reached == host:
                return Detection(
                    present=True, detail=f"HTTP {result.status} -> {destination}"
                )
            if reached and reached != own_host:
                # Off-site, but not where we asked. Worth saying so rather than
                # reporting it: a fixed third-party hop is not this bug.
                return Detection(
                    present=False,
                    detail=(
                        f"the response redirects to {reached}, which is off-site but "
                        "not the host the parameter named, so the parameter does not "
                        "control the destination"
                    ),
                )
            return Detection(present=False)

        for name, payload_value, control_value, strength in (
            (
                "absolute_location",
                f"https://{host}/reconx",
                _CONTROL_PATHS[0],
                OracleStrength.DECISIVE,
            ),
            (
                "scheme_relative_location",
                f"//{host}/reconx",
                f"/{host}/reconx",
                OracleStrength.STRONG,
            ),
        ):
            oracle = DifferentialOracle(
                self.fetch,
                name=name,
                signal="redirect to the host the parameter named",
                detect=lands_on_sentinel,
                payload_label=(
                    "an absolute off-site URL"
                    if name == "absolute_location"
                    else "a protocol-relative off-site URL"
                ),
                strength=strength,
                attempts=self._attempts,
                required=self._required,
                lone_reason=(
                    "the parameter sends a browser to a host we named, but only in one "
                    "of the two forms tested, so confirm by hand which values the "
                    "application accepts before reporting"
                ),
            )
            verdict.oracles.append(
                await oracle.run(
                    target.apply(payload_value, follow_redirects=False),
                    target.apply(control_value, follow_redirects=False),
                    evidence_label=f"{name.replace('_', ' ')} with an on-site control",
                    collect=verdict.evidence,
                )
            )

        verdict.apply(
            decide_from_oracles(
                verdict.oracles,
                fallback_reason=(
                    "the parameter does not control where the response sends a browser"
                ),
            )
        )
        if verdict.vulnerable:
            verdict.reason += (
                f". The destination host {host} is in the reserved .invalid domain and "
                "was never contacted; the finding is what the target said, not where "
                "the scanner went"
            )
        return verdict
