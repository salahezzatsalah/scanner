"""The shared foundation every verifier is built on.

Before this module existed, the verifier "pattern" was convention: each class
happened to expose ``verify()``, happened to return an object with ``tier`` and
``confidence``, and happened to carry a private ``_fetch`` helper that swallowed
every exception. Six copies of that helper had drifted apart, evidence was an
untyped dictionary whose keys were informally agreed, and the rule for turning
signals into a tier lived inside :mod:`reconx.verify.sqli` where nothing else
could reach it.

That is a poor place to add six more vulnerability classes from, so the shape is
fixed here instead:

* :class:`ParamTarget` names *what* is being tested — the parameter, and whether
  it lives in the query string, a form body, a JSON body, a header or a cookie.
  Everything before this module could only test query parameters.
* :class:`FetchResult` distinguishes "the request failed" from "there was no
  signal". Conflating the two is how a scanner reports a network blip as a clean
  result, or discards a real bug because one probe timed out.
* :class:`Evidence` is typed, so the fields that prove a finding — the control
  request, the false case, the characters that survived — reach the database
  instead of being dropped by a dictionary lookup that did not know about them.
* :func:`decide_from_oracles` is the verification standard in one place. Two
  independent oracles agreeing is Confirmed. One decisive oracle is Probable.
  One weak oracle, such as timing, is Needs review and never better.

Nothing here performs a request without going through the caller's
:class:`~reconx.net.http.ScopedHttpClient`, which is the only component allowed
to reach the network and which enforces scope on every hop.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from reconx.db.models import FindingTier
from reconx.verify.waf import WafState, WafVerdict, classify_response

if TYPE_CHECKING:  # pragma: no cover - typing only
    from reconx.net.http import ScopedResponse

__all__ = [
    "Evidence",
    "EvidenceRequest",
    "FetchResult",
    "OracleResult",
    "OracleStrength",
    "ParamLocation",
    "ParamTarget",
    "ParameterVerdict",
    "ParameterVerifier",
    "PreparedRequest",
    "Verdict",
    "Verifier",
    "decide_from_oracles",
    "set_parameter",
    "try_fetch",
]


# ---------------------------------------------------------------------------
# what is being tested
# ---------------------------------------------------------------------------


class ParamLocation(StrEnum):
    """Where a parameter lives in a request.

    Only ``QUERY`` was reachable before: every verifier rewrote the query string
    directly, so a form field or a JSON body field could be *discovered* and then
    never tested. Several vulnerability classes live mostly in bodies, so the
    location is part of the target rather than an assumption.
    """

    QUERY = "query"
    FORM = "form_body"
    JSON = "json_body"
    HEADER = "header"
    COOKIE = "cookie"


@dataclass(frozen=True)
class PreparedRequest:
    """A request ready to hand to the scoped client.

    Deliberately inert: it holds no client and cannot send itself, so building
    one is never accidentally a request.
    """

    method: str = "GET"
    url: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)
    data: Mapping[str, str] | None = None
    json_body: Any = None

    def kwargs(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.headers:
            out["headers"] = dict(self.headers)
        if self.data is not None:
            out["data"] = dict(self.data)
        if self.json_body is not None:
            out["json"] = self.json_body
        return out

    def body_text(self) -> str | None:
        """The request body as text, for evidence and reproduction commands."""
        if self.data is not None:
            return urlencode(sorted(self.data.items()), doseq=True)
        if self.json_body is not None:
            import json as _json

            return _json.dumps(self.json_body, sort_keys=True)
        return None


def set_parameter(url: str, name: str, value: str) -> str:
    """Return ``url`` with query parameter ``name`` set to ``value``.

    Appends the parameter when the URL does not already carry it, so a guessed
    name can be tested on an endpoint that declares nothing.
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = [(key, value if key == name else existing) for key, existing in pairs]
    if not any(key == name for key, _ in pairs):
        replaced.append((name, value))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(replaced, doseq=True), "")
    )


@dataclass(frozen=True)
class ParamTarget:
    """One parameter on one endpoint, and how to send a value through it."""

    url: str
    name: str
    location: ParamLocation = ParamLocation.QUERY
    method: str = ""
    original: str = ""
    siblings: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def coerce(cls, target: ParamTarget | str, name: str | None = None) -> ParamTarget:
        """Accept either a target or the older ``(url, parameter)`` pair."""
        if isinstance(target, ParamTarget):
            return target
        return cls(url=target, name=name or "")

    @property
    def http_method(self) -> str:
        """The method to use, defaulting by location rather than always GET."""
        if self.method:
            return self.method.upper()
        return "GET" if self.location is ParamLocation.QUERY else "POST"

    @property
    def current_value(self) -> str:
        """The value already present, used to build structurally similar probes."""
        if self.original:
            return self.original
        if self.location is ParamLocation.QUERY:
            pairs = parse_qsl(urlsplit(self.url).query, keep_blank_values=True)
            for key, value in pairs:
                if key == self.name:
                    return value
        return ""

    def describe(self) -> str:
        where = self.location.value.replace("_", " ")
        return f"{self.name!r} in the {where}"

    def apply(self, value: str, *, headers: Mapping[str, str] | None = None) -> PreparedRequest:
        """Build the request that puts ``value`` into this parameter."""
        merged = dict(headers or {})
        method = self.http_method

        if self.location is ParamLocation.QUERY:
            return PreparedRequest(
                method=method, url=set_parameter(self.url, self.name, value), headers=merged
            )
        if self.location is ParamLocation.FORM:
            return PreparedRequest(
                method=method,
                url=self.url,
                headers=merged,
                data={**self.siblings, self.name: value},
            )
        if self.location is ParamLocation.JSON:
            return PreparedRequest(
                method=method,
                url=self.url,
                headers=merged,
                json_body={**self.siblings, self.name: value},
            )
        if self.location is ParamLocation.HEADER:
            merged[self.name] = value
            return PreparedRequest(method=method, url=self.url, headers=merged)

        # Cookie: merge into any cookie header the caller already set rather than
        # replacing it, so session context survives.
        existing = next(
            (v for k, v in merged.items() if k.lower() == "cookie"), ""
        )
        jar = "; ".join(filter(None, [existing, f"{self.name}={value}"]))
        for key in [k for k in merged if k.lower() == "cookie"]:
            del merged[key]
        merged["Cookie"] = jar
        return PreparedRequest(method=method, url=self.url, headers=merged)


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FetchResult:
    """The outcome of one request, including the ways it can fail.

    A verifier must be able to tell "the application answered and showed no
    signal" from "the request never completed". Reporting the second as the
    first invents clean results; reporting it as a signal invents findings. The
    six private fetch helpers this replaces all returned ``None`` for both.
    """

    request: PreparedRequest
    response: ScopedResponse | None = None
    error: str | None = None
    elapsed_ms: float | None = None

    @property
    def ok(self) -> bool:
        return self.response is not None

    def __bool__(self) -> bool:
        return self.ok

    @property
    def text(self) -> str:
        return self.response.text if self.response is not None else ""

    @property
    def body(self) -> bytes:
        return self.response.body if self.response is not None else b""

    @property
    def status(self) -> int | None:
        return self.response.status if self.response is not None else None

    def header(self, name: str, default: str = "") -> str:
        return self.response.header(name, default) if self.response is not None else default

    def obstruction(self) -> WafVerdict:
        """What this response says about the host's willingness to be tested."""
        if self.response is None:
            return WafVerdict(WafState.CLEAN)
        return classify_response(
            status=self.response.status,
            headers=self.response.headers,
            body=self.response.body,
        )


async def try_fetch(http, request: PreparedRequest | str) -> FetchResult:
    """Perform one request through the scoped client, recording any failure.

    The one fetch helper in the codebase. There were six near-identical private
    copies before this, each returning ``None`` on any exception, so a timeout, a
    TLS failure, a refused connection and a genuinely empty result were
    indistinguishable to every caller.
    """
    prepared = PreparedRequest(url=request) if isinstance(request, str) else request
    started = time.monotonic()
    try:
        response = await http.request(prepared.method, prepared.url, **prepared.kwargs())
    except Exception as exc:
        return FetchResult(
            request=prepared,
            error=f"{type(exc).__name__}: {exc}",
            elapsed_ms=(time.monotonic() - started) * 1000,
        )
    return FetchResult(
        request=prepared,
        response=response,
        elapsed_ms=(time.monotonic() - started) * 1000,
    )


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceRequest:
    """One request that a piece of evidence rests on.

    Evidence is usually a *comparison*, so it takes more than one request to
    show: the payload and the benign control, or the true case and the false one.
    Each is recorded, so a reviewer can re-run both halves rather than being
    handed one URL and asked to trust the conclusion.
    """

    role: str = "payload"
    method: str = "GET"
    url: str = ""
    body: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    status: int | None = None

    @classmethod
    def of(
        cls, request: PreparedRequest, *, role: str = "payload", status: int | None = None
    ) -> EvidenceRequest:
        return cls(
            role=role,
            method=request.method,
            url=request.url,
            body=request.body_text(),
            headers=dict(request.headers),
            status=status,
        )


@dataclass
class Evidence:
    """Typed proof for a finding.

    Replaces the untyped dictionary that ``stages/vulns.py`` consumed with
    ``item.get(...)``: any key the stage did not happen to know about was
    silently dropped, which is how ``control_url``, ``false_url`` and
    ``surviving_chars`` never reached the database.
    """

    label: str
    note: str = ""
    snippet: str = ""
    context: str = ""
    requests: list[EvidenceRequest] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def comparison(
        cls,
        label: str,
        *,
        payload: PreparedRequest | None = None,
        control: PreparedRequest | None = None,
        roles: tuple[str, str] = ("payload", "control"),
        note: str = "",
        snippet: str = "",
        context: str = "",
        **detail: Any,
    ) -> Evidence:
        """Evidence built from a payload request and the control it is judged against."""
        requests: list[EvidenceRequest] = []
        if payload is not None:
            requests.append(EvidenceRequest.of(payload, role=roles[0]))
        if control is not None:
            requests.append(EvidenceRequest.of(control, role=roles[1]))
        return cls(
            label=label,
            note=note,
            snippet=snippet,
            context=context,
            requests=requests,
            detail={key: value for key, value in detail.items() if value not in (None, (), [])},
        )

    @property
    def primary(self) -> EvidenceRequest | None:
        return self.requests[0] if self.requests else None

    @property
    def primary_url(self) -> str | None:
        return self.primary.url if self.primary else None

    def rendered_note(self) -> str:
        """The note plus any detail, as one line a reviewer can read."""
        parts = [self.note] if self.note else []
        for key, value in sorted(self.detail.items()):
            if isinstance(value, (list, tuple)):
                rendered = ", ".join(repr(item) for item in value)
            else:
                rendered = str(value)
            parts.append(f"{key.replace('_', ' ')}: {rendered}")
        return "; ".join(parts)

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "note": self.rendered_note(),
            "snippet": self.snippet,
            "context": self.context,
            "detail": dict(self.detail),
            "requests": [
                {
                    "role": item.role,
                    "method": item.method,
                    "url": item.url,
                    "body": item.body,
                    "status": item.status,
                }
                for item in self.requests
            ],
        }


# ---------------------------------------------------------------------------
# oracles and the decision rule
# ---------------------------------------------------------------------------


class OracleStrength(StrEnum):
    """How much one oracle is worth on its own.

    The distinction exists because oracles are not interchangeable. A page that
    responds to the *logic* of an injected boolean is doing something only
    injection explains. A slow response is something ordinary load explains
    constantly. Treating those as equal evidence is the mistake that fills
    reports with time-based false positives.
    """

    DECISIVE = "decisive"
    STRONG = "strong"
    WEAK = "weak"


@dataclass
class OracleResult:
    """One independent line of evidence."""

    name: str
    agreed: bool
    reason: str
    detail: dict = field(default_factory=dict)
    reproduced: int = 0
    attempts: int = 0
    strength: OracleStrength = OracleStrength.STRONG
    lone_reason: str = ""

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "agreed": self.agreed,
            "reason": self.reason,
            "strength": self.strength.value,
            "reproduced": f"{self.reproduced}/{self.attempts}",
        }


@dataclass(frozen=True)
class Decision:
    """A tier, a confidence and the sentence that justifies both."""

    tier: FindingTier
    confidence: int
    reason: str


def decide_from_oracles(
    oracles: list[OracleResult], *, fallback_reason: str = ""
) -> Decision:
    """Turn agreeing oracles into a tier. The verification standard, in one place.

    The rule, which every vulnerability class in ReconX shares:

    * **Two or more independent oracles agree** — Confirmed. Independence is the
      point: two views of the same signal is one oracle wearing two hats, and
      the verifiers are responsible for not offering those.
    * **One decisive oracle** — Probable. Worth a researcher's time, not worth
      submitting unverified.
    * **One strong oracle** — Probable, at lower confidence.
    * **One weak oracle** — Needs review, never better. A timing signal alone
      falls here, because network variance imitates it too well.
    * **None** — Discarded, and the reasons the oracles gave are kept so the
      filter itself can be audited rather than trusted.
    """
    agreed = [oracle for oracle in oracles if oracle.agreed]
    names = sorted({oracle.name for oracle in agreed})

    if len(agreed) >= 2:
        decisive = any(oracle.strength is OracleStrength.DECISIVE for oracle in agreed)
        return Decision(
            tier=FindingTier.CONFIRMED,
            confidence=95 if decisive else 88,
            reason=(
                f"{len(agreed)} independent oracles agree ({', '.join(names)}), "
                "each reproduced across repeated attempts"
            ),
        )

    if len(agreed) == 1:
        only = agreed[0]
        if only.strength is OracleStrength.WEAK:
            return Decision(
                tier=FindingTier.NEEDS_REVIEW,
                confidence=40,
                reason=only.lone_reason
                or (
                    f"only the {only.name} oracle agreed, and it is too easily imitated "
                    "by ordinary behaviour to be reported on its own, so it needs a "
                    "human look or a second signal"
                ),
            )
        confidence = 70 if only.strength is OracleStrength.DECISIVE else 60
        return Decision(
            tier=FindingTier.PROBABLE,
            confidence=confidence,
            reason=only.lone_reason
            or (
                f"the {only.name} oracle agreed and reproduced, but no second oracle "
                "did; verify by hand before reporting"
            ),
        )

    disagreements = "; ".join(
        oracle.reason for oracle in oracles if not oracle.agreed and oracle.reason
    )
    return Decision(
        tier=FindingTier.DISCARDED,
        confidence=0,
        reason=disagreements or fallback_reason or "no oracle found evidence of the issue",
    )


# ---------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------


@dataclass
class Verdict:
    """What a verifier concluded, and everything needed to check it.

    Every field here is one the reporting layer already duck-typed. Making them
    a declared base means a new vulnerability class cannot forget one.
    """

    tier: FindingTier = FindingTier.DISCARDED
    confidence: int = 0
    reason: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    obstructed: bool = False
    oracles: list[OracleResult] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)

    @property
    def agreeing(self) -> list[str]:
        """The oracles that agreed, which is what a report cites."""
        return [oracle.name for oracle in self.oracles if oracle.agreed]

    @property
    def vulnerable(self) -> bool:
        return self.tier in (FindingTier.CONFIRMED, FindingTier.PROBABLE)

    def add(self, evidence: Evidence) -> Evidence:
        self.evidence.append(evidence)
        return evidence

    def apply(self, decision: Decision) -> None:
        self.tier = decision.tier
        self.confidence = decision.confidence
        self.reason = decision.reason
        if not self.signals:
            self.signals = self.agreeing

    def as_dict(self) -> dict:
        return {
            "tier": self.tier.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "obstructed": self.obstructed,
            "signals": list(self.signals),
            "agreeing_oracles": self.agreeing,
            "oracles": [oracle.as_dict() for oracle in self.oracles],
        }


@dataclass
class ParameterVerdict(Verdict):
    """A verdict about one parameter on one endpoint."""

    url: str = ""
    parameter: str = ""
    method: str = "GET"
    location: ParamLocation = ParamLocation.QUERY

    def as_dict(self) -> dict:
        return {
            **super().as_dict(),
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "location": self.location.value,
        }


# ---------------------------------------------------------------------------
# the verifier base
# ---------------------------------------------------------------------------


class Verifier(ABC):
    """Common shape and shared transport for every verifier.

    Subclasses get one fetch helper that records failures instead of hiding
    them, one WAF gate, and one decision function. What they must supply is the
    part that is actually specific to a vulnerability class: which oracles to
    run.
    """

    #: The ``vuln_class`` a finding from this verifier is filed under.
    vuln_class: ClassVar[str] = ""
    #: A short human label used in titles.
    title: ClassVar[str] = ""

    def __init__(self, http, *, attempts: int = 3, required: int = 3) -> None:
        self._http = http
        self._attempts = max(1, attempts)
        self._required = max(1, min(required, max(1, attempts)))

    @abstractmethod
    async def verify(self, *args, **kwargs) -> Verdict:
        """Test one candidate and return a tiered verdict."""

    # -- transport ---------------------------------------------------------

    async def fetch(self, request: PreparedRequest | str) -> FetchResult:
        """Perform one request, recording failure rather than swallowing it."""
        return await try_fetch(self._http, request)

    async def timed_fetch(self, request: PreparedRequest | str) -> tuple[FetchResult, float | None]:
        """Fetch and report how long it took, for the timing oracle.

        The elapsed time is measured around the whole call, so a failed request
        contributes no sample rather than a misleadingly fast one.
        """
        result = await self.fetch(request)
        return result, (result.elapsed_ms if result.ok else None)

    # -- the shared obstruction gate ---------------------------------------

    def gate_obstruction(self, verdict: Verdict, result: FetchResult) -> bool:
        """Stop if the host is not in a state where any result means anything.

        A host that is blocking, challenging or throttling answers differently,
        and everything measured during that window is unreliable — including the
        results that look clean. So the verdict becomes Needs review with the
        state named, and the work is re-queued rather than reported.

        Returns True when the caller should stop.
        """
        obstruction = result.obstruction()
        if obstruction.state is WafState.CLEAN:
            return False
        verdict.obstructed = True
        verdict.tier = FindingTier.NEEDS_REVIEW
        verdict.confidence = 0
        verdict.reason = (
            f"the host was {obstruction.state.value} while it was being tested, so no "
            "result from it can be trusted; re-test when it is responsive"
        )
        return True


class ParameterVerifier(Verifier):
    """A verifier that tests one parameter at a time.

    Accepts either a :class:`ParamTarget` or the older ``(url, parameter)`` pair,
    so existing callers keep working while new ones can reach form, JSON, header
    and cookie parameters.
    """

    verdict_class: ClassVar[type[ParameterVerdict]] = ParameterVerdict

    def new_verdict(self, target: ParamTarget) -> ParameterVerdict:
        return self.verdict_class(
            url=target.url,
            parameter=target.name,
            method=target.http_method,
            location=target.location,
        )

    def target_of(
        self, target: ParamTarget | str, parameter: str | None = None
    ) -> ParamTarget:
        return ParamTarget.coerce(target, parameter)
