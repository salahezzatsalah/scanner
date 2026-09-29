"""Reproduction commands.

A finding without a reproduction is a finding you cannot report. Every confirmed
finding carries a ``curl`` command that reproduces it, built here so the format
is consistent and safely quoted.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Mapping

__all__ = ["curl_command", "http_request_text", "redact", "SESSION_PLACEHOLDER"]

#: What a redacted session becomes in a stored reproduction. Deliberately an
#: instruction rather than a row of asterisks: whoever runs the command needs to
#: know a session is required, not just that something was removed.
SESSION_PLACEHOLDER = "$YOUR_SESSION"


def redact(text: str | None, secrets: Iterable[str] = ()) -> str | None:
    """Replace every secret in ``text`` with :data:`SESSION_PLACEHOLDER`.

    Evidence rows and reproduction commands are shared with programs, and a
    session cookie in one is a credential handed to a third party. Redaction
    happens on the way *into* storage rather than on the way out, so there is no
    path by which an unredacted copy exists to be leaked later.

    Substrings are replaced longest-first, so redacting a whole ``Cookie`` header
    does not leave a bare token behind from a shorter overlapping match.
    """
    if not text:
        return text
    out = text
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        out = out.replace(secret, SESSION_PLACEHOLDER)
    return out

# Headers that change per request or leak local state; they add noise to a
# reproduction without changing its behaviour.
_SKIP_HEADERS = frozenset(
    {"host", "content-length", "connection", "accept-encoding", "cookie"}
)


def curl_command(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: str | None = None,
    include_cookies: bool = False,
    insecure: bool = True,
) -> str:
    """Build a runnable ``curl`` command.

    ``insecure`` defaults to true because scan targets routinely have
    certificate problems, and a reproduction that fails on the certificate
    rather than demonstrating the finding is useless to a triager.

    ``include_cookies`` keeps a ``Cookie`` header that would otherwise be
    stripped. Reproductions drop it by default so a report never carries a
    session token by accident, but a finding whose payload *is* a cookie does not
    reproduce without it -- see ``ParamLocation.COOKIE`` -- so the evidence writer
    in :mod:`reconx.stages.vulns` sets it. Review a reproduction before pasting it
    into a report either way.
    """
    parts = ["curl", "-sS", "-i"]
    if insecure:
        parts.append("-k")
    if method.upper() != "GET":
        parts += ["-X", method.upper()]

    for name, value in (headers or {}).items():
        lowered = name.lower()
        if lowered in _SKIP_HEADERS and not (include_cookies and lowered == "cookie"):
            continue
        parts += ["-H", f"{name}: {value}"]

    if body:
        parts += ["--data-raw", body]

    parts.append(url)
    return " ".join(shlex.quote(part) if " " in part or '"' in part else part for part in parts)


def http_request_text(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: str | None = None,
) -> str:
    """Render a raw HTTP request, for pasting into a report or a proxy."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {parts.netloc}"]
    for name, value in (headers or {}).items():
        if name.lower() != "host":
            lines.append(f"{name}: {value}")
    if body:
        lines += ["", body]
    return "\n".join(lines)
