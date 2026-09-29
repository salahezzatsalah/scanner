"""Parameter discovery and reflection mapping.

Parameters are where the interesting bugs are, so this stage builds the list the
vulnerability stage will actually test, and does the cheap work that makes that
testing affordable.

Two jobs:

* **Discovery.** Collect the parameters an endpoint declares in its query string
  and forms, then, when it declares none, try a list of common names and keep
  the ones the application visibly reacts to.
* **Reflection mapping.** Send a unique canary through each parameter and record
  whether it comes back. This is a single request per parameter and it lets the
  XSS verifier skip everything that is not reflected, which is most of it.

Reflection alone is never reported as a finding. It is a filter that makes the
expensive verification tractable, and :mod:`reconx.verify.xss` still has to
prove a reflection can escape its context and execute.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from sqlmodel import select

from reconx.db.models import Endpoint
from reconx.db.store import upsert_endpoint
from reconx.stages.base import Stage, StageContext, StageResult
from reconx.stages.wordlists import COMMON_PARAMETER_NAMES, resolve_wordlist
from reconx.verify.base import set_parameter, try_fetch
from reconx.verify.waf import WafState, classify_response

__all__ = ["ParamStage"]


@dataclass
class ParamProfile:
    """What is known about one parameter on one endpoint."""

    url: str
    name: str
    declared: bool = False
    reflected: bool = False
    changes_response: bool = False
    notes: list[str] = field(default_factory=list)


class ParamStage(Stage):
    name = "params"
    description = "Parameter discovery and reflection mapping"
    requires = ("content",)
    active = True

    def __init__(
        self,
        *,
        wordlist_path: str | None = None,
        guess_hidden: bool = True,
        max_endpoints: int = 200,
        max_guessed_per_endpoint: int = 40,
    ) -> None:
        self._wordlist_path = wordlist_path
        self._guess_hidden = guess_hidden
        self._max_endpoints = max_endpoints
        self._max_guessed = max_guessed_per_endpoint

    async def run(self, ctx: StageContext) -> StageResult:
        result = StageResult(stage=self.name)
        endpoints = await self._candidate_endpoints(ctx)
        result.items_in = len(endpoints)

        if not endpoints:
            result.note("no endpoints to profile; run the content stage first")
            return result

        if len(endpoints) > self._max_endpoints:
            result.note(
                f"profiling the {self._max_endpoints} most interesting of "
                f"{len(endpoints)} endpoints"
            )
            endpoints = endpoints[: self._max_endpoints]

        profiles: list[ParamProfile] = []
        for endpoint in endpoints:
            profiles.extend(await self._profile_endpoint(ctx, endpoint, result))

        reflected = [profile for profile in profiles if profile.reflected]
        interactive = [profile for profile in profiles if profile.changes_response]

        # Hand the vulnerability stage a ready-made work list.
        ctx.shared["parameters"] = [
            {
                "url": profile.url,
                "name": profile.name,
                "reflected": profile.reflected,
                "changes_response": profile.changes_response,
            }
            for profile in profiles
        ]

        result.items_out = len(profiles)
        result.note(
            f"profiled {len(profiles)} parameter(s): {len(reflected)} reflect their "
            f"value, {len(interactive)} change the response"
        )
        if reflected:
            result.note(
                "reflection is a filter, not a finding: each one still has to prove "
                "it can escape its context and execute"
            )
        result.checkpoint = {"endpoints_profiled": [e.url for e in endpoints]}
        return result

    # -- input -------------------------------------------------------------

    async def _candidate_endpoints(self, ctx: StageContext) -> list[Endpoint]:
        rows = await ctx.session.execute(
            select(Endpoint)
            .where(Endpoint.program_id == ctx.program_id)
            .order_by(Endpoint.interesting_score.desc())
        )
        return [
            endpoint
            for endpoint in rows.scalars().all()
            if ctx.guard.decide_url(endpoint.url).allowed
        ]

    # -- per endpoint ------------------------------------------------------

    async def _profile_endpoint(
        self, ctx: StageContext, endpoint: Endpoint, result: StageResult
    ) -> list[ParamProfile]:
        declared = {name for name, _ in parse_qsl(urlsplit(endpoint.url).query)}
        declared.update(endpoint.parameters or [])

        baseline = await self._get(ctx, endpoint.url)
        if baseline is None:
            result.filtered("unreachable")
            return []

        obstruction = classify_response(
            status=baseline.status, headers=baseline.headers, body=baseline.body
        )
        if obstruction.state is not WafState.CLEAN:
            result.filtered(f"host_{obstruction.state.value}")
            return []

        profiles: list[ParamProfile] = []

        for name in sorted(declared):
            profile = ParamProfile(url=endpoint.url, name=name, declared=True)
            await self._test_parameter(ctx, profile, baseline)
            profiles.append(profile)

        # Only guess when the endpoint declares nothing: guessing on top of a
        # known parameter list is mostly wasted requests.
        if self._guess_hidden and not declared:
            names, note = resolve_wordlist(self._wordlist_path, COMMON_PARAMETER_NAMES)
            if note and note not in result.notes:
                result.note(f"parameter wordlist: {note}")
            for name in names[: self._max_guessed]:
                profile = ParamProfile(url=endpoint.url, name=name, declared=False)
                await self._test_parameter(ctx, profile, baseline)
                if profile.reflected or profile.changes_response:
                    profiles.append(profile)
                else:
                    result.filtered("parameter_ignored")

        if profiles:
            await upsert_endpoint(
                ctx.session,
                ctx.program_id,
                endpoint.url,
                method=endpoint.method,
                parameters=sorted({profile.name for profile in profiles}),
                reflected_parameters=sorted(
                    {profile.name for profile in profiles if profile.reflected}
                )
                or None,
            )
        return profiles

    async def _test_parameter(
        self, ctx: StageContext, profile: ParamProfile, baseline
    ) -> None:
        """One request: does the value come back, and does the page change?"""
        canary = f"rx{secrets.token_hex(5)}zz"
        probe_url = set_parameter(profile.url, profile.name, canary)

        response = await self._get(ctx, probe_url)
        if response is None:
            profile.notes.append("probe request failed")
            return

        if canary in response.text:
            profile.reflected = True
        if not response.fingerprint.looks_same_as(baseline.fingerprint):
            profile.changes_response = True

    # -- transport ---------------------------------------------------------

    async def _get(self, ctx: StageContext, url: str):
        result = await try_fetch(ctx.http, url)
        return result.response
