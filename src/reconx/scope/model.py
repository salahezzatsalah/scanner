"""Scope definition and matching rules.

A scope is the contract between you and the program you are testing. ReconX
treats it as a hard boundary rather than a hint: :class:`Scope` is parsed from
YAML, every entry becomes a :class:`ScopeRule`, and
:mod:`reconx.scope.guard` refuses to emit traffic that no in-scope rule matches.

Supported rule syntax (usable in both ``in_scope`` and ``out_of_scope``):

===========================  ==================================================
``api.acme.io``              exact host
``*.acme.com``               the apex *and* every subdomain (bug bounty
                             convention for a wildcard program)
``.acme.com``                same as ``*.acme.com``
``203.0.113.5``              single IP (v4 or v6)
``203.0.113.0/24``           CIDR range
``https://acme.com/api/*``   host plus a path prefix
``re:^prod-\\d+\\.acme\\.com$``  explicit regex, for awkward cases
===========================  ==================================================

Out-of-scope rules always win over in-scope rules.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import date
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import tldextract
import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

# Offline suffix list: never reach out to the network just to parse a scope file.
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

__all__ = [
    "Authorization",
    "Scope",
    "ScopeLimits",
    "ScopeRule",
    "ScopeParseError",
    "normalize_host",
    "split_host_port",
    "parse_rule",
    "load_scope",
]


class ScopeParseError(ValueError):
    """A scope file or scope rule could not be understood."""


# ---------------------------------------------------------------------------
# host normalization helpers
# ---------------------------------------------------------------------------


def split_host_port(value: str) -> tuple[str, int | None]:
    """Split ``host[:port]`` handling bracketed IPv6 literals.

    ``"[::1]:8080"`` -> ``("::1", 8080)``; ``"::1"`` -> ``("::1", None)``.
    """
    raw = value.strip()
    if raw.startswith("["):
        closing = raw.find("]")
        if closing == -1:
            raise ScopeParseError(f"unterminated IPv6 literal: {value!r}")
        host = raw[1:closing]
        remainder = raw[closing + 1 :]
        if remainder.startswith(":") and remainder[1:].isdigit():
            return host, int(remainder[1:])
        return host, None

    if raw.count(":") == 1:
        head, _, tail = raw.partition(":")
        if tail.isdigit():
            return head, int(tail)
    # Zero colons (plain host) or many colons (bare IPv6) — no port present.
    return raw, None


def normalize_host(value: str) -> str:
    """Lower-case, strip a trailing root dot and any port, and IDNA-encode.

    Raises :class:`ScopeParseError` for input that is not a usable host.
    """
    if value is None:
        raise ScopeParseError("host is required")
    host, _ = split_host_port(str(value))
    host = host.strip().strip(".").lower()
    if not host:
        raise ScopeParseError(f"empty host in {value!r}")

    # An IP literal needs no IDNA handling.
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    if any(ord(ch) > 127 for ch in host):
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeParseError(f"cannot IDNA-encode host {value!r}: {exc}") from exc

    _validate_hostname(host, value)
    return host


# Underscores are permitted: real DNS carries names like ``_dmarc`` and
# ``_acme-challenge``, and recon needs to handle them.
_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")


def _validate_hostname(host: str, original: str) -> None:
    """Reject anything that is not a plausible DNS name.

    Garbage in means garbage requests out, so it is caught at the boundary
    rather than being denied later for a misleading reason.
    """
    if len(host) > 253:
        raise ScopeParseError(f"host is longer than 253 characters: {original!r}")
    labels = host.split(".")
    for label in labels:
        if not label:
            raise ScopeParseError(f"host has an empty label: {original!r}")
        if len(label) > 63:
            raise ScopeParseError(f"host label longer than 63 characters: {original!r}")
        if not _LABEL_RE.match(label):
            raise ScopeParseError(
                f"host contains characters that are not valid in a DNS name: {original!r}"
            )


def _as_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

RuleKind = Literal["exact", "wildcard", "ip", "cidr", "url", "regex"]


class ScopeRule(BaseModel):
    """A single parsed scope entry."""

    raw: str
    kind: RuleKind
    host: str | None = None
    path_prefix: str | None = None
    network: str | None = None
    pattern: str | None = None

    model_config = {"frozen": True}

    # -- matching ---------------------------------------------------------

    def matches_host(self, host: str) -> bool:
        """Host-level match, used for DNS and port-level decisions.

        A URL rule matches at host level so that resolving and probing the host
        is permitted; the path restriction is applied by :meth:`matches_url`.
        """
        if self.kind == "regex":
            return re.search(self.pattern or "", host) is not None

        if self.kind in {"ip", "cidr"}:
            ip = _as_ip(host)
            if ip is None:
                return False
            if self.kind == "ip":
                return str(ip) == self.host
            return ip in ipaddress.ip_network(self.network or "", strict=False)

        if self.host is None:
            return False

        # An IP target never matches a domain rule.
        if _as_ip(host) is not None and _as_ip(self.host) is None:
            return False

        if self.kind == "wildcard":
            return host == self.host or host.endswith("." + self.host)
        return host == self.host

    def matches_url(self, host: str, path: str) -> bool:
        """Full match including the path prefix for URL-scoped rules."""
        if not self.matches_host(host):
            return False
        if self.kind != "url" or not self.path_prefix:
            return True
        normalized = path or "/"
        prefix = self.path_prefix
        if prefix.endswith("/"):
            return normalized.startswith(prefix) or normalized == prefix.rstrip("/")
        return normalized == prefix or normalized.startswith(prefix + "/")

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.raw


def parse_rule(raw: str) -> ScopeRule:
    """Parse one scope entry into a :class:`ScopeRule`."""
    if raw is None:
        raise ScopeParseError("scope entry cannot be null")
    entry = str(raw).strip()
    if not entry:
        raise ScopeParseError("scope entry cannot be empty")

    # --- explicit regex ------------------------------------------------
    if entry.startswith("re:"):
        pattern = entry[3:]
        if not pattern:
            raise ScopeParseError(f"empty regex in {raw!r}")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ScopeParseError(f"invalid regex in {raw!r}: {exc}") from exc
        return ScopeRule(raw=entry, kind="regex", pattern=pattern)

    # --- URL with a path ------------------------------------------------
    if "://" in entry:
        parts = urlsplit(entry)
        if not parts.hostname:
            raise ScopeParseError(f"URL scope entry has no host: {raw!r}")
        host = normalize_host(parts.hostname)
        path = parts.path or ""
        if path in ("", "/"):
            # No meaningful path restriction: treat as a host rule.
            return _host_rule(entry, host)
        # A trailing "/*" means "this prefix and everything under it".
        if path.endswith("/*") or path.endswith("*"):
            path = path[:-1]
        return ScopeRule(raw=entry, kind="url", host=host, path_prefix=path or "/")

    # --- CIDR ------------------------------------------------------------
    if "/" in entry:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ScopeParseError(f"not a valid CIDR range: {raw!r} ({exc})") from exc
        return ScopeRule(raw=entry, kind="cidr", network=str(network))

    # --- wildcard --------------------------------------------------------
    if entry.startswith("*."):
        base = normalize_host(entry[2:])
        _reject_overbroad_wildcard(entry, base)
        return ScopeRule(raw=entry, kind="wildcard", host=base)
    if entry.startswith("."):
        base = normalize_host(entry[1:])
        _reject_overbroad_wildcard(entry, base)
        return ScopeRule(raw=entry, kind="wildcard", host=base)
    if "*" in entry:
        raise ScopeParseError(
            f"wildcards are only supported as a leading label (*.example.com): {raw!r}"
        )

    return _host_rule(entry, normalize_host(entry))


def _host_rule(raw: str, host: str) -> ScopeRule:
    if _as_ip(host) is not None:
        return ScopeRule(raw=raw, kind="ip", host=host)
    return ScopeRule(raw=raw, kind="exact", host=host)


def _reject_overbroad_wildcard(raw: str, base: str) -> None:
    """Refuse ``*.com``, ``*.co.uk``, ``*.github.io`` and friends.

    A wildcard whose base is itself a public suffix would authorize an enormous
    slice of the internet that the program does not own. That is never what a
    scope means, so it is a parse error rather than something to discover at
    request time.
    """
    if _as_ip(base) is not None:
        raise ScopeParseError(f"wildcard over an IP address is not meaningful: {raw!r}")
    if not base:
        raise ScopeParseError(f"wildcard has no base domain: {raw!r}")

    suffix = _extract(base).suffix
    if suffix == base:
        raise ScopeParseError(
            f"refusing wildcard {raw!r}: {base!r} is a public suffix, so this would put "
            "every domain under it in scope. List the specific hosts you are authorized "
            "for, or use an explicit regex rule (re:...) if you really mean a pattern."
        )


# ---------------------------------------------------------------------------
# scope document
# ---------------------------------------------------------------------------


class Authorization(BaseModel):
    """Who authorized this testing, and their attestation.

    Required. ReconX will not run without it, because a scan you cannot
    account for is a scan you should not be running.
    """

    authorized_by: str = Field(min_length=1)
    date: date
    attestation: str = Field(min_length=1)
    reference: str | None = None

    @field_validator("authorized_by", "attestation")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank")
        return v.strip()


class ScopeLimits(BaseModel):
    """Per-program overrides for politeness settings.

    Programs often state a maximum request rate. Put it here and it wins over
    the global configuration.
    """

    requests_per_second_per_host: float | None = Field(default=None, gt=0)
    max_concurrent_requests: int | None = Field(default=None, ge=1)
    max_concurrent_hosts: int | None = Field(default=None, ge=1)
    max_requests_per_scan: int | None = Field(default=None, ge=1)


class Scope(BaseModel):
    """A parsed, validated program scope."""

    program: str = Field(min_length=1)
    platform: str | None = None
    program_url: str | None = None
    notes: str | None = None
    authorization: Authorization
    in_scope: list[str] = Field(min_length=1)
    out_of_scope: list[str] = Field(default_factory=list)
    limits: ScopeLimits = Field(default_factory=ScopeLimits)

    # Populated in the validator below.
    in_scope_rules: list[ScopeRule] = Field(default_factory=list, exclude=True)
    out_of_scope_rules: list[ScopeRule] = Field(default_factory=list, exclude=True)

    @model_validator(mode="after")
    def _compile_rules(self) -> Scope:
        errors: list[str] = []
        compiled_in: list[ScopeRule] = []
        compiled_out: list[ScopeRule] = []

        for entry in self.in_scope:
            try:
                compiled_in.append(parse_rule(entry))
            except ScopeParseError as exc:
                errors.append(f"in_scope[{entry!r}]: {exc}")
        for entry in self.out_of_scope:
            try:
                compiled_out.append(parse_rule(entry))
            except ScopeParseError as exc:
                errors.append(f"out_of_scope[{entry!r}]: {exc}")

        if errors:
            raise ValueError("invalid scope rules:\n  - " + "\n  - ".join(errors))

        object.__setattr__(self, "in_scope_rules", compiled_in)
        object.__setattr__(self, "out_of_scope_rules", compiled_out)
        return self

    @property
    def slug(self) -> str:
        """Filesystem- and CLI-friendly identifier derived from the name."""
        base = re.sub(r"[^a-z0-9]+", "-", self.program.lower()).strip("-")
        return base or "program"

    @property
    def wildcard_roots(self) -> list[str]:
        """Registrable roots that need subdomain enumeration."""
        return [r.host for r in self.in_scope_rules if r.kind == "wildcard" and r.host]

    @property
    def seed_hosts(self) -> list[str]:
        """Concrete hosts named directly in the scope."""
        return [r.host for r in self.in_scope_rules if r.kind in {"exact", "url"} and r.host]

    @property
    def seed_networks(self) -> list[str]:
        """IP ranges and single IPs named directly in the scope."""
        out: list[str] = []
        for rule in self.in_scope_rules:
            if rule.kind == "cidr" and rule.network:
                out.append(rule.network)
            elif rule.kind == "ip" and rule.host:
                out.append(rule.host)
        return out


def load_scope(path: str | Path) -> Scope:
    """Load and validate a scope from a YAML file."""
    file_path = Path(path)
    if not file_path.is_file():
        raise ScopeParseError(f"scope file not found: {file_path}")
    try:
        raw: Any = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScopeParseError(f"{file_path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScopeParseError(f"{file_path} must contain a YAML mapping at the top level")
    try:
        return Scope.model_validate(raw)
    except Exception as exc:
        raise ScopeParseError(f"{file_path} is not a valid scope: {exc}") from exc
