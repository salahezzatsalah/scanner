"""Verification: the part that decides what is true.

Detection proposes; this package disposes. Every candidate a detector produces
passes through here before it can become a reported finding, and the standard it
has to meet is the same for every vulnerability class:

* two **independent** oracles must agree, each reproduced across repeated
  attempts, before anything reaches Confirmed,
* every oracle is paired with a benign **control**, so a signal the control also
  produces is attributed to the application rather than to the payload,
* a **timing** signal alone never confirms, because ordinary load imitates it,
* work done while a host was blocking, challenging or throttling is Needs review
  rather than a result, because nothing measured in that window is trustworthy,
* a discarded candidate keeps the reason it was discarded, so the filter can be
  audited instead of trusted.

:mod:`reconx.verify.base` fixes that shape in code. A new class implements its
oracles and inherits the standard.
"""

from reconx.verify.base import (
    Evidence,
    EvidenceRequest,
    FetchResult,
    OracleResult,
    OracleStrength,
    ParameterVerdict,
    ParameterVerifier,
    ParamLocation,
    ParamTarget,
    PreparedRequest,
    Verdict,
    Verifier,
    decide_from_oracles,
    set_parameter,
    try_fetch,
)
from reconx.verify.differential import (
    Detection,
    DifferentialOracle,
    boolean_differential,
)

__all__ = [
    "Detection",
    "DifferentialOracle",
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
    "boolean_differential",
    "decide_from_oracles",
    "set_parameter",
    "try_fetch",
]
