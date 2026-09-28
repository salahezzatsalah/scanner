"""Response fingerprinting.

Deciding "is this page really different from the host's normal error page?" is
the question behind most false positives. An exact hash is useless for it,
because real pages carry CSRF tokens, timestamps and request IDs that change on
every fetch. So responses are reduced to a fuzzy fingerprint:

* digits are collapsed to ``#`` so IDs and timestamps stop causing divergence,
* the body is tokenized and reduced to a 64-bit **simhash**, which compares by
  Hamming distance rather than equality,
* structural signals (status, length band, word and line counts, title,
  content type, header names) are kept alongside it.

This is what lets :mod:`reconx.verify` distinguish a genuine finding from the
host's soft-404 page, a WAF block page, or a wildcard DNS catch-all.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

__all__ = ["ResponseFingerprint", "fingerprint_response", "simhash", "hamming_distance"]

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_TOKEN_RE = re.compile(r"[a-z]{2,}")
_DIGITS_RE = re.compile(r"\d+")
_SIMHASH_BITS = 64


def _stable_hash(token: str) -> int:
    """Process-stable 64-bit hash. ``hash()`` is randomized per process."""
    return int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")


def simhash(tokens: list[str], bits: int = _SIMHASH_BITS) -> int:
    """Weighted simhash over a token list."""
    if not tokens:
        return 0
    weights: dict[str, int] = {}
    for token in tokens:
        weights[token] = weights.get(token, 0) + 1

    vector = [0] * bits
    for token, weight in weights.items():
        digest = _stable_hash(token)
        for index in range(bits):
            if (digest >> index) & 1:
                vector[index] += weight
            else:
                vector[index] -= weight

    value = 0
    for index in range(bits):
        if vector[index] > 0:
            value |= 1 << index
    return value


def hamming_distance(left: int, right: int) -> int:
    return bin(left ^ right).count("1")


def _decode(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def _visible_text(body: bytes) -> str:
    """Strip markup so comparison looks at what a user would see."""
    text = _decode(body)
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    text = _TAG_RE.sub(" ", text)
    return text


def _tokens(body: bytes) -> list[str]:
    text = _visible_text(body).lower()
    # Collapse digit runs so IDs, timestamps and counters do not create noise.
    text = _DIGITS_RE.sub("#", text)
    return _TOKEN_RE.findall(text)


def _length_band(length: int) -> int:
    """Bucket a length so small dynamic variation lands in the same band."""
    if length <= 0:
        return 0
    if length < 512:
        return length // 32
    if length < 8192:
        return 16 + length // 256
    return 64 + length // 4096


@dataclass(frozen=True)
class ResponseFingerprint:
    """A fuzzy, comparable summary of one HTTP response."""

    status: int
    body_length: int
    body_sha256: str
    simhash_value: int
    length_band: int
    word_count: int
    line_count: int
    title: str | None = None
    content_type: str = ""
    header_names: tuple[str, ...] = field(default_factory=tuple)
    redirect_location: str | None = None

    # -- comparison -------------------------------------------------------

    def similarity(self, other: ResponseFingerprint) -> float:
        """0.0 to 1.0. Combines body simhash with structural agreement."""
        if self.body_sha256 == other.body_sha256:
            return 1.0

        distance = hamming_distance(self.simhash_value, other.simhash_value)
        body_score = 1.0 - (distance / _SIMHASH_BITS)

        structural = 0.0
        checks = 0
        for mine, theirs in (
            (self.status, other.status),
            (self.length_band, other.length_band),
            (self.title, other.title),
            (self.content_type, other.content_type),
            (self.header_names, other.header_names),
        ):
            checks += 1
            if mine == theirs:
                structural += 1.0
        structural /= checks or 1

        # The body dominates; structure breaks ties.
        return round((body_score * 0.75) + (structural * 0.25), 4)

    def looks_same_as(self, other: ResponseFingerprint, threshold: float = 0.92) -> bool:
        """True when two responses are the same page for practical purposes.

        A differing status code is treated as a real difference regardless of
        body similarity: a 200 and a 403 with identical bodies are not the
        same outcome.
        """
        if self.status != other.status:
            return False
        return self.similarity(other) >= threshold

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "body_length": self.body_length,
            "body_sha256": self.body_sha256,
            "simhash": f"{self.simhash_value:016x}",
            "length_band": self.length_band,
            "word_count": self.word_count,
            "line_count": self.line_count,
            "title": self.title,
            "content_type": self.content_type,
            "redirect_location": self.redirect_location,
        }


def fingerprint_response(
    *,
    status: int,
    body: bytes,
    headers: dict[str, str] | None = None,
) -> ResponseFingerprint:
    """Build a :class:`ResponseFingerprint` from raw response parts."""
    headers = headers or {}
    lowered = {k.lower(): v for k, v in headers.items()}

    title = None
    match = _TITLE_RE.search(body)
    if match:
        candidate = _decode(match.group(1)).strip()
        candidate = re.sub(r"\s+", " ", candidate)
        title = candidate[:200] or None

    tokens = _tokens(body)
    content_type = lowered.get("content-type", "").split(";")[0].strip()

    return ResponseFingerprint(
        status=status,
        body_length=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        simhash_value=simhash(tokens),
        length_band=_length_band(len(body)),
        word_count=len(tokens),
        line_count=body.count(b"\n") + 1,
        title=title,
        content_type=content_type,
        # Header *names* only: values carry per-request noise.
        header_names=tuple(sorted(lowered.keys())),
        redirect_location=lowered.get("location"),
    )
