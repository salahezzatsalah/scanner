"""Passive information gathering.

Asks public registries and resolvers about the scope without touching the
target's own infrastructure beyond DNS:

* **RDAP** for domain registration detail (registrar, key dates, status flags,
  nameservers). RDAP rather than legacy WHOIS because it returns structured
  JSON instead of free text that needs per-registrar scraping.
* **DNS records** across A, AAAA, CNAME, MX, NS, TXT, SOA and CAA.
* **IP attribution** for every resolved address: RDAP network data, plus ASN
  and announced prefix via Team Cymru's TXT records over DNS-over-HTTPS.

Every source is optional. One being down or rate-limiting produces a note in
the stage result, never a failed run.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from reconx.db.models import AssetKind
from reconx.db.store import record_observation, upsert_asset
from reconx.net.dns import RECORD_TYPES
from reconx.stages.base import Stage, StageContext, StageResult

__all__ = ["PassiveReconStage"]

_RDAP_DOMAIN = "https://rdap.org/domain/{domain}"
_RDAP_IP = "https://rdap.org/ip/{address}"
_DOH_RESOLVE = "https://dns.google/resolve"
_CYMRU_ORIGIN = "origin.asn.cymru.com"
_CYMRU_ORIGIN6 = "origin6.asn.cymru.com"


def _vcard_name(entity: dict[str, Any]) -> str | None:
    """Pull the display name out of an RDAP entity's jCard."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return str(item[3])
    return None


def _cymru_reverse(address: str) -> tuple[str, str] | None:
    """Build the Team Cymru origin-lookup name for an IP.

    ``1.2.3.4`` becomes ``4.3.2.1.origin.asn.cymru.com``. IPv6 uses nibble
    reversal against ``origin6``.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv4Address):
        reversed_octets = ".".join(reversed(parsed.exploded.split(".")))
        return f"{reversed_octets}.{_CYMRU_ORIGIN}", "ipv4"
    nibbles = ".".join(reversed(parsed.exploded.replace(":", "")))
    return f"{nibbles}.{_CYMRU_ORIGIN6}", "ipv6"


class PassiveReconStage(Stage):
    name = "passive_recon"
    description = "WHOIS/RDAP registration data, DNS records, and IP/ASN attribution"
    requires = ()
    active = False

    async def run(self, ctx: StageContext) -> StageResult:
        result = StageResult(stage=self.name)
        domains = ctx.target_domains
        seed_hosts = list(dict.fromkeys([*domains, *ctx.scope.seed_hosts]))
        result.items_in = len(seed_hosts)

        if not seed_hosts:
            result.note("scope named no domains to profile")
            return result

        await self._registration_data(ctx, domains, result)
        addresses = await self._dns_records(ctx, seed_hosts, result)
        await self._ip_attribution(ctx, addresses, result)

        result.items_out = len(seed_hosts)
        result.checkpoint = {"profiled_domains": domains}
        return result

    # -- RDAP -------------------------------------------------------------

    async def _registration_data(
        self, ctx: StageContext, domains: list[str], result: StageResult
    ) -> None:
        for domain in domains:
            response = await ctx.sources.try_get(
                _RDAP_DOMAIN.format(domain=domain), source="rdap"
            )
            if response is None:
                result.note(f"RDAP lookup for {domain} was unavailable")
                continue
            try:
                payload = response.json()
            except ValueError:
                result.note(f"RDAP returned unparseable data for {domain}")
                continue

            facts: list[tuple[str, str]] = []

            for event in payload.get("events") or []:
                action = event.get("eventAction")
                when = event.get("eventDate")
                if action and when:
                    facts.append((f"event:{action}", str(when)))

            for entity in payload.get("entities") or []:
                roles = entity.get("roles") or []
                name = _vcard_name(entity) or entity.get("handle")
                if name:
                    for role in roles:
                        facts.append((f"entity:{role}", str(name)))

            for nameserver in payload.get("nameservers") or []:
                ldh = nameserver.get("ldhName")
                if ldh:
                    facts.append(("nameserver", str(ldh).lower().rstrip(".")))

            for flag in payload.get("status") or []:
                facts.append(("status", str(flag)))

            if secure := payload.get("secureDNS"):
                facts.append(("dnssec", str(bool(secure.get("delegationSigned")))))

            for key, value in facts:
                await record_observation(
                    ctx.session,
                    ctx.program_id,
                    kind="registration",
                    key=f"{domain}:{key}",
                    value=value,
                    source="rdap.org",
                )
            if facts:
                result.note(f"recorded {len(facts)} registration facts for {domain}")

    # -- DNS ---------------------------------------------------------------

    async def _dns_records(
        self, ctx: StageContext, hosts: list[str], result: StageResult
    ) -> set[str]:
        """Collect record sets, create assets, and return every resolved IP."""
        addresses: set[str] = set()

        for host in hosts:
            records = await ctx.dns.records(host, RECORD_TYPES)
            resolved: list[str] = []
            cname: str | None = None

            for rdtype, answer in records.items():
                if answer.out_of_scope:
                    result.filtered("out_of_scope")
                    continue
                for value in answer.values:
                    await record_observation(
                        ctx.session,
                        ctx.program_id,
                        kind="dns",
                        key=f"{host}:{rdtype}",
                        value=value,
                        source="dns",
                    )
                    if rdtype in {"A", "AAAA"}:
                        resolved.append(value)
                        addresses.add(value)
                    elif rdtype == "CNAME" and cname is None:
                        cname = value

            if resolved or cname or any(a.resolved for a in records.values()):
                _, is_new = await upsert_asset(
                    ctx.session,
                    ctx.program_id,
                    host,
                    kind=AssetKind.DOMAIN,
                    sources=["passive_recon:dns"],
                    resolved_values=resolved or None,
                    cname=cname,
                )
                if is_new:
                    result.new_assets.append(host)

        result.note(f"collected DNS records for {len(hosts)} hosts")
        return addresses

    # -- IP attribution ----------------------------------------------------

    async def _ip_attribution(
        self, ctx: StageContext, addresses: set[str], result: StageResult
    ) -> None:
        if not addresses:
            return

        for address in sorted(addresses):
            # The IP is only an asset of its own if the scope actually covers it.
            if ctx.guard.decide_host(address).allowed:
                _, is_new = await upsert_asset(
                    ctx.session,
                    ctx.program_id,
                    address,
                    kind=AssetKind.IP,
                    sources=["passive_recon:dns"],
                )
                if is_new:
                    result.new_assets.append(address)

            await self._rdap_ip(ctx, address, result)
            await self._asn(ctx, address, result)

    async def _rdap_ip(self, ctx: StageContext, address: str, result: StageResult) -> None:
        response = await ctx.sources.try_get(
            _RDAP_IP.format(address=address), source="rdap"
        )
        if response is None:
            return
        try:
            payload = response.json()
        except ValueError:
            return

        for key in ("name", "handle", "country", "type"):
            value = payload.get(key)
            if value:
                await record_observation(
                    ctx.session,
                    ctx.program_id,
                    kind="netblock",
                    key=f"{address}:{key}",
                    value=str(value),
                    source="rdap.org",
                )
        start, end = payload.get("startAddress"), payload.get("endAddress")
        if start and end:
            await record_observation(
                ctx.session,
                ctx.program_id,
                kind="netblock",
                key=f"{address}:range",
                value=f"{start} - {end}",
                source="rdap.org",
            )

    async def _asn(self, ctx: StageContext, address: str, result: StageResult) -> None:
        """ASN and announced prefix via Team Cymru over DNS-over-HTTPS.

        DoH is used because the Cymru lookup host is not in the program scope,
        so it cannot go through the scoped resolver. dns.google is an
        allowlisted intelligence source.
        """
        lookup = _cymru_reverse(address)
        if lookup is None:
            return
        name, _family = lookup

        response = await ctx.sources.try_get(
            _DOH_RESOLVE, params={"name": name, "type": "TXT"}, source="cymru-doh"
        )
        if response is None:
            return
        try:
            payload = response.json()
        except ValueError:
            return

        for answer in payload.get("Answer") or []:
            raw = str(answer.get("data", "")).strip('"')
            # Format: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
            parts = [part.strip() for part in raw.split("|")]
            if len(parts) < 2 or not parts[0]:
                continue
            asn = parts[0].split()[0]
            await record_observation(
                ctx.session, ctx.program_id, kind="asn",
                key=f"{address}:asn", value=f"AS{asn}", source="cymru",
            )
            await record_observation(
                ctx.session, ctx.program_id, kind="asn",
                key=f"{address}:prefix", value=parts[1], source="cymru",
            )
            if len(parts) > 2 and parts[2]:
                await record_observation(
                    ctx.session, ctx.program_id, kind="asn",
                    key=f"{address}:country", value=parts[2], source="cymru",
                )
            result.note(f"{address} announced by AS{asn}")
            break
