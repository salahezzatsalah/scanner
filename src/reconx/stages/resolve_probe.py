"""Liveness probing and response deduplication.

Turns a list of hostnames into a picture of what is actually serving: status,
title, server, detected technology, TLS detail, and which hosts are serving the
*same* application.

That last part matters more than it sounds. A large estate routinely has dozens
of names pointing at one load balancer. Without collapsing them, every later
stage does the same work dozens of times and every finding is reported dozens of
times. Grouping by response fingerprint here is what makes the finding
correlation in the verification engine possible.

ProjectDiscovery's httpx is used when installed, because it does technology and
TLS detection well. Its requests are folded into the audit trail so the record
of what was touched stays complete. Without it, the built-in scoped client
probes directly.
"""

from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from datetime import UTC, datetime

from sqlmodel import select

from reconx.db.models import Asset, AssetKind
from reconx.db.store import record_observation, upsert_asset
from reconx.stages.base import Stage, StageContext, StageResult
from reconx.tools.base import ToolNotAvailable

__all__ = ["ResolveProbeStage"]


def _asset_kind(host: str) -> AssetKind:
    """Classify a probe target as an address or a name."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return AssetKind.DOMAIN
    return AssetKind.IP


def _parse_tls_not_after(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = str(raw).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class ResolveProbeStage(Stage):
    name = "resolve_probe"
    description = "HTTP liveness probing, technology detection, and response dedup"
    requires = ("subdomains",)
    active = True

    def __init__(
        self,
        *,
        ports: tuple[int, ...] = (443, 80),
        max_cidr_expansion: int = 1024,
    ) -> None:
        self._ports = ports
        self._max_cidr_expansion = max_cidr_expansion
        self._oversized_ranges: list[str] = []

    async def run(self, ctx: StageContext) -> StageResult:
        result = StageResult(stage=self.name)
        self._oversized_ranges = []
        hosts = await self._hosts_to_probe(ctx)
        result.items_in = len(hosts)
        for warning in self._oversized_ranges:
            result.note(warning)

        if not hosts:
            result.note(
                "nothing in scope to probe: no hosts were discovered and the scope "
                "names no addresses directly"
            )
            return result

        runner = ctx.tool("httpx")
        if await runner.ensure_available():
            probed = await self._probe_with_httpx(ctx, runner, hosts, result)
            if probed is None:
                probed = await self._probe_builtin(ctx, hosts, result)
        else:
            result.used_fallback(
                "probing with the built-in client; installing ProjectDiscovery "
                "httpx adds technology and TLS detection"
            )
            probed = await self._probe_builtin(ctx, hosts, result)

        await self._deduplicate(ctx, probed, result)

        result.items_out = len(probed)
        live_hosts = sorted(probed)
        ctx.shared["live_hosts"] = live_hosts
        result.checkpoint = {"probed": live_hosts}
        return result

    # -- input -------------------------------------------------------------

    async def _hosts_to_probe(self, ctx: StageContext) -> list[str]:
        """Everything in scope that could be serving: hosts and addresses.

        Draws on the subdomain stage's output, previously discovered assets, and
        the addresses named directly in the scope. That last part matters: a
        program scoped only to ``203.0.113.0/24`` has no hostnames at all, and
        probing nothing would be a silent failure.
        """
        candidates: list[str] = []
        seen: set[str] = set()

        def add(host: str) -> None:
            if host and host not in seen and ctx.guard.decide_host(host).allowed:
                seen.add(host)
                candidates.append(host)

        for host in ctx.shared.get("subdomain_hosts") or []:
            add(host)

        rows = await ctx.session.execute(
            select(Asset).where(Asset.program_id == ctx.program_id)
        )
        for asset in rows.scalars().all():
            add(asset.host)

        for host in self._scope_addresses(ctx):
            add(host)

        return candidates

    def _scope_addresses(self, ctx: StageContext) -> list[str]:
        """Addresses named in the scope, expanding small CIDR ranges.

        Expansion is capped: a /24 is 256 addresses and worth probing, a /8 is
        16 million and is not. An oversized range is reported rather than
        silently truncated or silently skipped.
        """
        out: list[str] = []
        for entry in ctx.scope.seed_networks:
            if "/" not in entry:
                out.append(entry)
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if network.num_addresses == 1:
                out.append(str(network.network_address))
                continue
            if network.num_addresses > self._max_cidr_expansion:
                self._oversized_ranges.append(
                    f"{entry} holds {network.num_addresses} addresses, above the "
                    f"{self._max_cidr_expansion} probe limit; narrow the scope entry "
                    "or raise --max-cidr-hosts to cover it"
                )
                continue
            out.extend(str(address) for address in network.hosts())
        return out

    # -- probing via httpx -------------------------------------------------

    async def _probe_with_httpx(
        self, ctx: StageContext, runner, hosts: list[str], result: StageResult
    ) -> dict[str, dict] | None:
        rate = int(
            ctx.guard.effective_limit(
                "requests_per_second_per_host", ctx.settings.requests_per_second_per_host
            )
        )
        args = [
            "-silent", "-json", "-no-color",
            "-status-code", "-title", "-web-server", "-content-length",
            "-tech-detect", "-tls-grab", "-follow-redirects",
            "-timeout", str(int(ctx.settings.http_timeout_seconds)),
            "-rate-limit", str(max(1, rate)),
            "-retries", "1",
        ]
        try:
            outcome = await runner.run(args, stdin_targets=hosts, timeout=1800.0)
        except ToolNotAvailable:
            return None
        if not outcome.ok and not outcome.lines:
            result.note(f"httpx failed, falling back: {outcome.stderr.strip()[:140]}")
            return None

        result.used_tool("httpx")
        probed: dict[str, dict] = {}

        for line in outcome.lines:
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = str(row.get("input") or row.get("host") or "").lower().rstrip(".")
            host = host.split(":")[0]
            if not host:
                continue
            # httpx follows redirects itself, so re-check where it ended up.
            final_url = str(row.get("url") or "")
            if final_url and not ctx.guard.decide_url(final_url).allowed:
                result.filtered("redirected_out_of_scope")
                continue

            tls = row.get("tls") or {}
            record = {
                "host": host,
                "url": final_url,
                "status": row.get("status_code"),
                "title": row.get("title"),
                "server": row.get("webserver"),
                "content_length": row.get("content_length"),
                "technologies": row.get("tech") or [],
                "scheme": row.get("scheme"),
                "port": int(row["port"]) if str(row.get("port", "")).isdigit() else None,
                "body_hash": (row.get("hash") or {}).get("body_sha256"),
                "tls_issuer": (tls.get("issuer_org") or [None])[0]
                if isinstance(tls.get("issuer_org"), list)
                else tls.get("issuer_cn"),
                "tls_not_after": _parse_tls_not_after(tls.get("not_after")),
            }
            probed[host] = record

            # Keep the audit trail complete even though httpx made the request.
            ctx.http.record_external_request(
                method="GET",
                url=final_url or f"https://{host}/",
                host=host,
                status=record["status"],
                duration_ms=float(row.get("response_time_ms") or 0.0),
                response_bytes=int(record["content_length"] or 0),
                via="httpx",
            )

        await self._persist(ctx, probed, result)
        return probed

    # -- probing via the built-in client -----------------------------------

    async def _probe_builtin(
        self, ctx: StageContext, hosts: list[str], result: StageResult
    ) -> dict[str, dict]:
        probed: dict[str, dict] = {}

        for host in hosts:
            for port in self._ports:
                scheme = "https" if port == 443 else "http"
                url = f"{scheme}://{host}/" if port in (80, 443) else f"{scheme}://{host}:{port}/"
                try:
                    response = await ctx.http.get(url)
                except Exception:
                    continue

                fingerprint = response.fingerprint
                probed[host] = {
                    "host": host,
                    "url": response.url,
                    "status": response.status,
                    "title": fingerprint.title,
                    "server": response.header("server") or None,
                    "content_length": fingerprint.body_length,
                    "technologies": self._guess_technologies(response),
                    "scheme": scheme,
                    "port": port,
                    "body_hash": fingerprint.body_sha256,
                    "simhash": f"{fingerprint.simhash_value:016x}",
                    "tls_issuer": None,
                    "tls_not_after": None,
                }
                break  # first scheme that answers wins

        result.note(f"{len(probed)} of {len(hosts)} hosts answered over HTTP")
        await self._persist(ctx, probed, result)
        return probed

    @staticmethod
    def _guess_technologies(response) -> list[str]:
        """Cheap technology hints from headers, for the no-httpx path."""
        found: list[str] = []
        header_hints = {
            "x-powered-by": None,
            "server": None,
            "x-generator": None,
            "x-aspnet-version": "ASP.NET",
            "x-drupal-cache": "Drupal",
            "x-shopify-stage": "Shopify",
        }
        for header, label in header_hints.items():
            value = response.header(header)
            if value:
                found.append(label or value)
        body = response.body[:4096].lower()
        for marker, label in (
            (b"wp-content", "WordPress"),
            (b"/_next/", "Next.js"),
            (b"__nuxt", "Nuxt"),
            (b"ng-version", "Angular"),
            (b"react", "React"),
            (b"csrfmiddlewaretoken", "Django"),
            (b"laravel_session", "Laravel"),
        ):
            if marker in body and label not in found:
                found.append(label)
        return found

    # -- persistence and dedup ---------------------------------------------

    async def _persist(
        self, ctx: StageContext, probed: dict[str, dict], result: StageResult
    ) -> None:
        for host, record in probed.items():
            _, is_new = await upsert_asset(
                ctx.session,
                ctx.program_id,
                host,
                kind=_asset_kind(host),
                sources=["resolve_probe"],
                is_live=True,
                http_status=record.get("status"),
                scheme=record.get("scheme"),
                port=record.get("port"),
                title=record.get("title"),
                server=record.get("server"),
                technologies=record.get("technologies") or None,
                content_length=record.get("content_length"),
                fingerprint_sha256=record.get("body_hash"),
                fingerprint_simhash=record.get("simhash"),
                tls_issuer=record.get("tls_issuer"),
                tls_not_after=record.get("tls_not_after"),
                last_scanned_at=datetime.now(UTC),
            )
            if is_new:
                result.new_assets.append(host)

            for technology in record.get("technologies") or []:
                await record_observation(
                    ctx.session, ctx.program_id, kind="technology",
                    key=host, value=str(technology), source="resolve_probe",
                )

    async def _deduplicate(
        self, ctx: StageContext, probed: dict[str, dict], result: StageResult
    ) -> None:
        """Group hosts serving identical content.

        Recorded rather than discarded: all the names are real and in scope, but
        later stages and the report should treat them as one application.
        """
        groups: dict[str, list[str]] = defaultdict(list)
        for host, record in probed.items():
            key = record.get("body_hash") or record.get("simhash")
            if key:
                groups[str(key)].append(host)

        clusters = {key: sorted(hosts) for key, hosts in groups.items() if len(hosts) > 1}
        if not clusters:
            return

        collapsed = sum(len(hosts) - 1 for hosts in clusters.values())
        for key, hosts in clusters.items():
            await record_observation(
                ctx.session,
                ctx.program_id,
                kind="duplicate_group",
                key=key[:64],
                value=", ".join(hosts),
                source="resolve_probe",
            )
        result.note(
            f"{len(probed)} live hosts collapse to "
            f"{len(probed) - collapsed} distinct applications "
            f"({len(clusters)} group(s) of identical responses)"
        )
        ctx.shared["duplicate_groups"] = clusters
