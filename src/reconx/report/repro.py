"""Reproduction commands.

A finding without a reproduction is a finding you cannot report. Every confirmed
finding carries a ``curl`` command that reproduces it, built here so the format
is consistent and safely quoted.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping

__all__ = ["curl_command", "http_request_text"]

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
