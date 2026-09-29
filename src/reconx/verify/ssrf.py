"""Server-side request forgery verification.

SSRF is the class most often claimed on the weakest evidence. A parameter that
*looks* like a URL is not a finding, an error message mentioning a connection is
not a finding, and a slow response to an internal address is not a finding — that
last one is how scanners "discover" SSRF on every timeout.

What settles it is that the server made a request it was told to make. Two
independent oracles observe that from opposite sides:

* ``callback_received`` — **out-of-band.** A listener we run receives a request
  whose path carries a token unique to that probe. Nothing but the payload could
  have produced that token. Its control is a benign in-scope URL: if the listener
  is contacted while the control is in flight, the egress was not caused by the
  parameter.
* ``fetched_body_returned`` — **in-band.** The listener answers with a unique
  marker string, and that marker appears in the target's own response. This is a
  separate fact from being contacted: a blind SSRF has the first without the
  second, and a response-reflecting fetch proxy can have the second without the
  egress ever leaving the host.

Needing both is what keeps the class honest. Confirmed means the request was
observed arriving *and* its answer came back out.

Two things are guarded against explicitly, because the test fixture produced the
first one and it is the kind of mistake that makes a scanner untrustworthy:

* **Redirects are not followed while this runs.** An open-redirect endpoint
  answers a probe with ``Location:`` pointing at the listener. Follow that hop and
  the listener records a request, and the response carries the listener's marker,
  and both oracles "agree" -- on the scanner's own traffic. So the probe stops at
  the first response, which is the only one the *server* produced.
* **A callback carrying ReconX's own user agent is discarded.** Defence in depth
  for the same mistake, and the reason it is discarded is reported rather than the
  finding being silently dropped.

The listener is :class:`~reconx.verify.collaborator.LocalCollaborator`: it binds
loopback, it is off unless enabled, and it never contacts a third-party
interaction service, because doing so would publish the target's hostnames to
someone who is not in the program. The consequence is stated in that module and
repeated here: against a remote target the listener has to be reachable from that
target, which means an address you control. Without one the callback oracle does
not agree and this verifier reports what it can prove rather than guessing.

Nothing here scans internal ranges, enumerates cloud metadata endpoints, or reads
what an internal service returns. The probe proves the server can be told where
to go. Where that leads is the researcher's decision on a program that permits it.
"""

from __future__ import annotations

from dataclasses import dataclass

from reconx.db.models import FindingTier
from reconx.verify.base import (
    Evidence,
    OracleResult,
    OracleStrength,
    ParameterVerdict,
    ParameterVerifier,
    ParamTarget,
    decide_from_oracles,
)
from reconx.verify.collaborator import LocalCollaborator

__all__ = ["SsrfVerdict", "SsrfVerifier"]


@dataclass
class SsrfVerdict(ParameterVerdict):
    """The verification outcome for one URL-taking parameter."""

    callback_url: str = ""
    interactions: int = 0
    collaborator_loopback_only: bool = False

    def as_dict(self) -> dict:
        return {
            **super().as_dict(),
            "callback_url": self.callback_url,
            "interactions": self.interactions,
            "collaborator_loopback_only": self.collaborator_loopback_only,
        }


class SsrfVerifier(ParameterVerifier):
    """Verifies that a parameter makes the server issue a request we can observe."""

    vuln_class = "ssrf"
    title = "Server-side request forgery"
    verdict_class = SsrfVerdict

    def __init__(
        self,
        http,
        collaborator: LocalCollaborator,
        *,
        attempts: int = 3,
        required: int = 2,
        callback_timeout: float = 6.0,
        own_user_agent: str = "",
    ) -> None:
        super().__init__(http, attempts=attempts, required=required)
        self._collaborator = collaborator
        self._callback_timeout = callback_timeout
        # Whatever this scanner sends as its user agent. A callback carrying it
        # came from us, not from the target.
        self._own_user_agent = own_user_agent or self._detect_user_agent(http)

    @staticmethod
    def _detect_user_agent(http) -> str:
        settings = getattr(http, "settings", None) or getattr(http, "_settings", None)
        return str(getattr(settings, "user_agent", "") or "ReconX")

    async def verify(
        self, target: ParamTarget | str, parameter: str | None = None
    ) -> SsrfVerdict:
        target = self.target_of(target, parameter)
        verdict: SsrfVerdict = self.new_verdict(target)  # type: ignore[assignment]
        verdict.collaborator_loopback_only = self._collaborator.is_loopback_only

        if not self._collaborator.running:
            verdict.tier = FindingTier.NEEDS_REVIEW
            verdict.reason = (
                "the callback listener is not running, so a server-side request could "
                "not be observed. Enable the collaborator to test this parameter"
            )
            return verdict

        original = await self.fetch(
            target.apply(target.current_value or "/", follow_redirects=False)
        )
        if not original.ok:
            verdict.reason = (
                f"the original request could not be completed ({original.error})"
            )
            return verdict
        if self.gate_obstruction(verdict, original):
            return verdict

        # --- the control goes first ---------------------------------------
        # A benign in-scope URL. If the listener hears anything while this is the
        # only value in flight, the egress is not caused by the parameter and
        # nothing below means anything.
        control_token = self._collaborator.new_token()
        control_request = target.apply(
            target.current_value or "/", follow_redirects=False
        )
        await self.fetch(control_request)
        stray = await self._collaborator.wait_for(
            control_token, timeout=0.5, exclude_user_agents=self._excluded()
        )

        # --- oracle 1: did the listener hear from the target? -------------
        token = self._collaborator.new_token()
        callback_url = self._collaborator.url_for(token)
        verdict.callback_url = callback_url
        # Not following redirects is the whole point here: see the module
        # docstring. A hop we walk ourselves would satisfy both oracles.
        payload_request = target.apply(callback_url, follow_redirects=False)

        payload_result = await self.fetch(payload_request)
        hits = await self._collaborator.wait_for(
            token,
            timeout=self._callback_timeout,
            exclude_user_agents=self._excluded(),
        )
        own = [
            item
            for item in self._collaborator.received(token)
            if item not in hits
        ]
        verdict.interactions = len(hits)

        verdict.oracles.append(
            OracleResult(
                name="callback_received",
                agreed=bool(hits) and not stray,
                reason=(
                    f"the listener received {len(hits)} request(s) carrying the token "
                    f"{token}, from {hits[0].peer or 'the target'}, which only this "
                    "probe's payload contained; the benign control produced none"
                    if hits and not stray
                    else (
                        "the listener was contacted while the benign control was in "
                        "flight, so the egress is not attributable to this parameter"
                        if stray
                        else (
                            "the only requests that reached the listener carried "
                            "ReconX's own user agent, so they were the scanner "
                            "following a redirect rather than the server fetching "
                            "anything. That is an open redirect, not an SSRF"
                            if own
                            else self._no_callback_reason(target.url)
                        )
                    )
                ),
                detail={"token": token, "interactions": len(hits)},
                reproduced=len(hits),
                attempts=1,
                strength=OracleStrength.DECISIVE,
                lone_reason=(
                    "the server made a request to a host named in this parameter, which "
                    "is server-side request forgery, but its answer did not come back in "
                    "the response, so it is blind. Report it with the callback log as "
                    "proof and establish what internal hosts it can reach"
                ),
            )
        )

        # --- oracle 2: did the fetched body come back out? ----------------
        marker = self._collaborator.marker
        marker_returned = marker in payload_result.text
        control_has_marker = marker in original.text
        verdict.oracles.append(
            OracleResult(
                name="fetched_body_returned",
                agreed=marker_returned and not control_has_marker,
                reason=(
                    "the listener's unique marker appears in the target's own response, "
                    "so the server not only issued the request but returned what came "
                    "back, which makes internal services readable through this parameter"
                    if marker_returned and not control_has_marker
                    else (
                        "the marker is present in the unmodified response too, so its "
                        "appearance proves nothing"
                        if control_has_marker
                        else "the response does not contain what the listener served, so "
                        "any request the server made is blind"
                    )
                ),
                detail={"marker": marker},
                strength=OracleStrength.STRONG,
                lone_reason=(
                    "the response carries content from a host this parameter named, but "
                    "the listener recorded no request, so the fetch may be cached or "
                    "proxied elsewhere. Verify by hand before reporting"
                ),
            )
        )

        verdict.add(
            Evidence.comparison(
                "server-side request to a listener we control",
                payload=payload_request,
                control=control_request,
                note=(
                    f"{len(hits)} interaction(s) on {callback_url}"
                    + (
                        f"; first from {hits[0].peer}, {hits[0].method} {hits[0].path}"
                        if hits
                        else "; no interaction recorded"
                    )
                ),
                snippet=payload_result.text[:2000],
                callback_url=callback_url,
                response_status=payload_result.status,
            )
        )

        verdict.apply(
            decide_from_oracles(
                verdict.oracles,
                fallback_reason=(
                    "the parameter did not cause the server to issue a request that "
                    "could be observed"
                ),
            )
        )
        return verdict

    def _excluded(self) -> tuple[str, ...]:
        """User agents whose callbacks are ours rather than the target's."""
        return tuple(filter(None, (self._own_user_agent, "ReconX")))

    def _no_callback_reason(self, target_url: str) -> str:
        """Say why nothing arrived, distinguishing "did not" from "could not".

        The distinction matters: a loopback listener that a remote target could
        never have reached has proved nothing, and saying so is the difference
        between a clean result and an untested one. When the target is itself on
        this machine the caveat does not apply, so it is not offered.
        """
        from urllib.parse import urlsplit

        target_host = (urlsplit(target_url).hostname or "").lower()
        target_is_local = target_host in {"127.0.0.1", "localhost", "::1"} or (
            target_host.startswith("127.")
        )
        if self._collaborator.is_loopback_only and not target_is_local:
            return (
                "no request reached the listener. It is bound to loopback, so only a "
                "target on this machine could have reached it: against a remote target "
                "this oracle cannot agree until the collaborator has an address that "
                "target can reach. This is not evidence that the parameter is safe"
            )
        return (
            "no request reached the listener within the callback window, so the server "
            "did not fetch the URL the parameter named"
        )
