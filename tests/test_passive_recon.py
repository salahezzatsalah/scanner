"""Tests for passive information gathering.

This module was 300 lines of network parsing with no direct tests, which is the
worst combination in the codebase: every other module I have exercised by hand
turned up a bug, and this one had never been exercised at all.

The parsing is the risk. RDAP returns registrar names buried in jCard arrays,
Team Cymru answers with a pipe-separated string inside a TXT record, and reverse
DNS returns names that a third party chose and that this scanner has no
authorization to test. All three are checked here against recorded responses,
with :mod:`respx`, so nothing here touches the network.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import pytest
import respx
from sqlalchemy import select

from reconx.config import Settings
from reconx.db.models import Asset, Observation
from reconx.net.dns import DnsAnswer
from reconx.net.http import ScopedHttpClient
from reconx.net.sources import SourceClient
from reconx.scope.guard import ScopeGuard
from reconx.stages.base import StageContext
from reconx.stages.passive_recon import (
    PassiveReconStage,
    _cymru_reverse,
    _vcard_name,
)
from tests.conftest import make_scope


def fast_settings(**overrides) -> Settings:
    payload = {
        "requests_per_second_per_host": 500.0,
        "http_timeout_seconds": 5.0,
        "max_retries": 0,
        "dns_timeout_seconds": 1.0,
    }
    payload.update(overrides)
    return Settings(**payload)


# ---------------------------------------------------------------------------
# a resolver that answers from a table, so no test touches DNS
# ---------------------------------------------------------------------------


@dataclass
class FakeResolver:
    """A ScopedResolver stand-in driven by a lookup table."""

    forward: dict[tuple[str, str], tuple[str, ...]]
    ptr: dict[str, tuple[str, ...]]
    guard: ScopeGuard | None = None
    reverse_calls: int = 0

    async def resolve(self, host: str, rdtype: str = "A") -> DnsAnswer:
        return DnsAnswer(
            host=host, rdtype=rdtype, values=self.forward.get((host, rdtype), ())
        )

    async def records(self, host: str, rdtypes) -> dict[str, DnsAnswer]:
        return {rdtype: await self.resolve(host, rdtype) for rdtype in rdtypes}

    async def reverse(self, address: str) -> DnsAnswer:
        self.reverse_calls += 1
        return DnsAnswer(host=address, rdtype="PTR", values=self.ptr.get(address, ()))

    async def reverse_many(self, addresses) -> list[DnsAnswer]:
        return [await self.reverse(address) for address in addresses]


async def make_context(
    program,
    session,
    scope,
    *,
    forward=None,
    ptr=None,
) -> tuple[StageContext, FakeResolver]:
    guard = ScopeGuard(scope)
    resolver = FakeResolver(forward=forward or {}, ptr=ptr or {}, guard=guard)
    settings = fast_settings()
    context = StageContext(
        program_id=program.id,
        scan_run_id=1,
        scope=scope,
        guard=guard,
        http=ScopedHttpClient(guard, settings=settings),
        dns=resolver,  # type: ignore[arg-type]
        sources=SourceClient(settings=settings),
        session=session,
        settings=settings,
        use_external_tools=False,
    )
    return context, resolver


async def observations(session, program, kind: str | None = None) -> dict[str, str]:
    rows = await session.execute(
        select(Observation).where(Observation.program_id == program.id)
    )
    items = rows.scalars().all()
    return {
        item.key: item.value
        for item in items
        if kind is None or item.kind == kind
    }


# ---------------------------------------------------------------------------
# the pure parsers
# ---------------------------------------------------------------------------


def test_a_registrar_name_is_pulled_out_of_the_jcard_array() -> None:
    """RDAP buries the display name three levels into a nested array."""
    entity = {
        "handle": "292",
        "roles": ["registrar"],
        "vcardArray": [
            "vcard",
            [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "MarkMonitor Inc."],
                ["email", {}, "text", "abuse@markmonitor.com"],
            ],
        ],
    }
    assert _vcard_name(entity) == "MarkMonitor Inc."


@pytest.mark.parametrize(
    "entity",
    [
        {},
        {"vcardArray": "not a list"},
        {"vcardArray": ["vcard"]},
        {"vcardArray": ["vcard", [["version", {}, "text", "4.0"]]]},
        {"vcardArray": ["vcard", [["fn", {}, "text"]]]},
    ],
)
def test_a_malformed_jcard_returns_none_rather_than_raising(entity: dict) -> None:
    """RDAP output varies by registry, so the parser must not assume a shape."""
    assert _vcard_name(entity) is None


def test_the_cymru_lookup_name_reverses_an_ipv4_address() -> None:
    name, family = _cymru_reverse("8.8.4.4")
    assert name == "4.4.8.8.origin.asn.cymru.com"
    assert family == "ipv4"


def test_the_cymru_lookup_name_reverses_ipv6_by_nibble() -> None:
    name, family = _cymru_reverse("2001:4860:4860::8888")
    assert family == "ipv6"
    assert name.endswith(".origin6.asn.cymru.com")
    # 32 nibbles, each its own label, in reverse order.
    labels = name.removesuffix(".origin6.asn.cymru.com").split(".")
    assert len(labels) == 32
    assert labels[0] == "8"
    assert "".join(reversed(labels)) == "20014860486000000000000000008888"


@pytest.mark.parametrize("value", ["not-an-ip", "", "999.1.1.1", "example.com"])
def test_a_non_address_has_no_cymru_lookup(value: str) -> None:
    assert _cymru_reverse(value) is None


# ---------------------------------------------------------------------------
# RDAP for a domain
# ---------------------------------------------------------------------------

RDAP_DOMAIN = {
    "events": [
        {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"},
        {"eventAction": "last changed"},
    ],
    "entities": [
        {
            "roles": ["registrar", "abuse"],
            "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]],
        },
        {"roles": ["technical"], "handle": "TECH-1"},
        {"roles": ["billing"]},
    ],
    "nameservers": [
        {"ldhName": "NS1.EXAMPLE.COM."},
        {"ldhName": "ns2.example.com"},
        {},
    ],
    "status": ["client delete prohibited", "server transfer prohibited"],
    "secureDNS": {"delegationSigned": True},
}


@respx.mock
async def test_registration_facts_are_recorded_from_rdap(program, db_session) -> None:
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=RDAP_DOMAIN)
    )
    scope = make_scope(in_scope=["example.com"], out_of_scope=[])
    ctx, _ = await make_context(program, db_session, scope)

    result = await PassiveReconStage(max_reverse_lookups=0).run(ctx)
    facts = await observations(db_session, program, "registration")

    assert facts["example.com:event:registration"] == "1997-09-15T04:00:00Z"
    assert facts["example.com:event:expiration"] == "2028-09-14T04:00:00Z"
    # An event with no date is not a fact.
    assert "example.com:event:last changed" not in facts
    # One entity with two roles is recorded under each.
    assert facts["example.com:entity:registrar"] == "MarkMonitor Inc."
    assert facts["example.com:entity:abuse"] == "MarkMonitor Inc."
    # A handle stands in when there is no display name.
    assert facts["example.com:entity:technical"] == "TECH-1"
    # An entity with neither is skipped rather than recorded as empty.
    assert "example.com:entity:billing" not in facts
    # Nameservers are normalised: lower case, no trailing dot.
    assert facts["example.com:nameserver"] in {"ns1.example.com", "ns2.example.com"}
    assert facts["example.com:dnssec"] == "True"
    assert any("registration facts" in note for note in result.notes)


@respx.mock
async def test_an_unavailable_rdap_source_is_a_note_not_a_failure(
    program, db_session
) -> None:
    """One source being down must never fail a run."""
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(503, text="try later")
    )
    scope = make_scope(in_scope=["example.com"], out_of_scope=[])
    ctx, _ = await make_context(program, db_session, scope)

    result = await PassiveReconStage(max_reverse_lookups=0).run(ctx)

    assert any("was unavailable" in note for note in result.notes)
    assert await observations(db_session, program, "registration") == {}


@respx.mock
async def test_unparseable_rdap_data_is_reported(program, db_session) -> None:
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, text="<html>not json</html>")
    )
    scope = make_scope(in_scope=["example.com"], out_of_scope=[])
    ctx, _ = await make_context(program, db_session, scope)

    result = await PassiveReconStage(max_reverse_lookups=0).run(ctx)

    assert any("unparseable" in note for note in result.notes)


# ---------------------------------------------------------------------------
# the DNS record sweep
# ---------------------------------------------------------------------------


@respx.mock
async def test_the_full_record_set_is_swept_and_addresses_are_returned(
    program, db_session
) -> None:
    respx.route(host="rdap.org").mock(return_value=httpx.Response(404))
    respx.route(host="dns.google").mock(return_value=httpx.Response(404))

    scope = make_scope(in_scope=["example.com"], out_of_scope=[])
    ctx, _ = await make_context(
        program,
        db_session,
        scope,
        forward={
            ("example.com", "A"): ("93.184.216.34",),
            ("example.com", "AAAA"): ("2606:2800:220:1:248:1893:25c8:1946",),
            ("example.com", "MX"): ("10 mail.example.com",),
            ("example.com", "NS"): ("a.iana-servers.net",),
            ("example.com", "TXT"): ("v=spf1 -all",),
            ("example.com", "CAA"): ('0 issue "letsencrypt.org"',),
        },
    )

    await PassiveReconStage(max_reverse_lookups=0).run(ctx)
    records = await observations(db_session, program, "dns")

    assert records["example.com:A"] == "93.184.216.34"
    assert records["example.com:AAAA"] == "2606:2800:220:1:248:1893:25c8:1946"
    assert records["example.com:MX"] == "10 mail.example.com"
    assert records["example.com:TXT"] == "v=spf1 -all"
    assert 'letsencrypt.org' in records["example.com:CAA"]


# ---------------------------------------------------------------------------
# ASN attribution over DNS-over-HTTPS
# ---------------------------------------------------------------------------


def doh_txt(value: str) -> httpx.Response:
    return httpx.Response(
        200, json={"Status": 0, "Answer": [{"name": "x", "type": 16, "data": f'"{value}"'}]}
    )


@respx.mock
async def test_asn_and_prefix_are_parsed_from_the_cymru_txt_record(
    program, db_session
) -> None:
    respx.route(host="rdap.org").mock(return_value=httpx.Response(404))
    respx.get("https://dns.google/resolve").mock(
        return_value=doh_txt("15169 | 8.8.8.0/24 | US | arin | 1992-12-01")
    )

    scope = make_scope(in_scope=["8.8.8.8"], out_of_scope=[])
    ctx, _ = await make_context(program, db_session, scope)

    result = await PassiveReconStage(max_reverse_lookups=0).run(ctx)
    asn = await observations(db_session, program, "asn")

    assert asn["8.8.8.8:asn"] == "AS15169"
    assert asn["8.8.8.8:prefix"] == "8.8.8.0/24"
    assert asn["8.8.8.8:country"] == "US"
    assert any("announced by AS15169" in note for note in result.notes)


@respx.mock
async def test_a_multi_origin_cymru_answer_takes_the_first_asn(
    program, db_session
) -> None:
    """A prefix announced by several ASNs lists them space-separated."""
    respx.route(host="rdap.org").mock(return_value=httpx.Response(404))
    respx.get("https://dns.google/resolve").mock(
        return_value=doh_txt("23028 3856 | 216.90.108.0/24 | US | arin | 1998-09-25")
    )

    scope = make_scope(in_scope=["216.90.108.1"], out_of_scope=[])
    ctx, _ = await make_context(program, db_session, scope)

    await PassiveReconStage(max_reverse_lookups=0).run(ctx)
    asn = await observations(db_session, program, "asn")

    assert asn["216.90.108.1:asn"] == "AS23028"


@respx.mock
async def test_a_cymru_answer_with_no_asn_records_nothing(program, db_session) -> None:
    respx.route(host="rdap.org").mock(return_value=httpx.Response(404))
    respx.get("https://dns.google/resolve").mock(return_value=doh_txt(" | | | |"))

    scope = make_scope(in_scope=["203.0.113.9"], out_of_scope=[])
    ctx, _ = await make_context(program, db_session, scope)

    await PassiveReconStage(max_reverse_lookups=0).run(ctx)

    assert await observations(db_session, program, "asn") == {}


# ---------------------------------------------------------------------------
# netblock RDAP
# ---------------------------------------------------------------------------

RDAP_IP = {
    "handle": "NET-203-0-113-0-1",
    "name": "TEST-NET-3",
    "country": "US",
    "type": "DIRECT ALLOCATION",
    "startAddress": "203.0.113.0",
    "endAddress": "203.0.113.255",
}


@respx.mock
async def test_netblock_detail_is_recorded_for_an_address_range(
    program, db_session
) -> None:
    respx.get("https://rdap.org/ip/203.0.113.0").mock(
        return_value=httpx.Response(200, json=RDAP_IP)
    )
    respx.route(host="dns.google").mock(return_value=httpx.Response(404))

    scope = make_scope(in_scope=["203.0.113.0/30"], out_of_scope=[])
    ctx, _ = await make_context(program, db_session, scope)

    await PassiveReconStage(max_reverse_lookups=8).run(ctx)
    netblock = await observations(db_session, program, "netblock")

    assert netblock["203.0.113.0:name"] == "TEST-NET-3"
    assert netblock["203.0.113.0:range"] == "203.0.113.0 - 203.0.113.255"
    assert netblock["203.0.113.0/30:size"] == "4"


# ---------------------------------------------------------------------------
# the reverse-DNS sweep: the reason this stage exists for an IP scope
# ---------------------------------------------------------------------------


@respx.mock
async def test_an_ip_only_scope_is_profiled_instead_of_skipped(
    program, db_session
) -> None:
    """The bug this fixes: an address range produced nothing at all.

    ``target_domains`` draws only on wildcard roots and named hosts, and an IP is
    in neither, so a scope of ``203.0.113.0/30`` used to print "scope named no
    domains to profile" and stop -- no RDAP, no ASN, and no reverse DNS, which is
    the highest-yield technique available against a range.
    """
    respx.route(host="rdap.org").mock(return_value=httpx.Response(200, json=RDAP_IP))
    respx.get("https://dns.google/resolve").mock(
        return_value=doh_txt("64496 | 203.0.113.0/24 | US | arin | 2010-01-01")
    )

    # A real range program usually names its domain too, which is what lets a
    # discovered PTR name become an asset rather than only an observation.
    scope = make_scope(
        in_scope=["203.0.113.0/30", "*.example.net"], out_of_scope=[]
    )
    ctx, resolver = await make_context(
        program,
        db_session,
        scope,
        ptr={
            "203.0.113.1": ("gw.example.net.",),
            "203.0.113.2": ("app-01.example.net",),
        },
    )

    result = await PassiveReconStage(max_reverse_lookups=8).run(ctx)

    assert not any("no domains" in note for note in result.notes)
    assert resolver.reverse_calls == 2, "a /30 has two usable addresses"

    # The names became assets, which is what seeds the rest of the pipeline.
    rows = await db_session.execute(select(Asset).where(Asset.program_id == program.id))
    hosts = {asset.host for asset in rows.scalars().all()}
    assert {"gw.example.net", "app-01.example.net"} <= hosts

    ptr = await observations(db_session, program, "dns_record")
    assert ptr["203.0.113.1:PTR"] == "gw.example.net"
    assert any("reverse DNS named 2 host" in note for note in result.notes)
    # One seed domain from the wildcard root, plus the two names reverse DNS found.
    assert result.items_out == 3


@respx.mock
async def test_a_ptr_pointing_outside_the_scope_is_recorded_but_not_adopted(
    program, db_session
) -> None:
    """A PTR record is a third party's claim, not an authorization.

    Whoever controls reverse DNS for an address can point it at any name at all,
    including one nobody authorized testing for. So the name is recorded as an
    observation and the guard decides whether it becomes an asset.
    """
    respx.route(host="rdap.org").mock(return_value=httpx.Response(404))
    respx.route(host="dns.google").mock(return_value=httpx.Response(404))

    scope = make_scope(
        in_scope=["203.0.113.0/30", "*.example.net"],
        out_of_scope=["secret.example.net"],
    )
    ctx, _ = await make_context(
        program,
        db_session,
        scope,
        ptr={
            "203.0.113.1": ("app.example.net",),
            "203.0.113.2": ("someone-else.example.org", "secret.example.net"),
        },
    )

    result = await PassiveReconStage(max_reverse_lookups=8).run(ctx)

    rows = await db_session.execute(select(Asset).where(Asset.program_id == program.id))
    hosts = {asset.host for asset in rows.scalars().all()}
    assert "app.example.net" in hosts
    # Out of scope entirely, and explicitly excluded: neither is adopted.
    assert "someone-else.example.org" not in hosts
    assert "secret.example.net" not in hosts

    # But both are still on record, because knowing is the point of recon.
    ptr = await observations(db_session, program, "dns_record")
    assert ptr["203.0.113.2:PTR"] in {"someone-else.example.org", "secret.example.net"}
    assert result.filter_reasons.get("ptr_out_of_scope") == 2
    # And the researcher is told what they are, since that is what to ask about.
    note = next((n for n in result.notes if "the scope does not cover" in n), None)
    assert note is not None, result.notes
    assert "example.org" in note


@respx.mock
async def test_an_oversized_range_is_reported_rather_than_swept(
    program, db_session
) -> None:
    """A /16 is 65,534 PTR queries. The limit is stated, not silently applied."""
    respx.route(host="rdap.org").mock(return_value=httpx.Response(404))
    respx.route(host="dns.google").mock(return_value=httpx.Response(404))

    scope = make_scope(in_scope=["203.0.113.0/16"], out_of_scope=[])
    ctx, resolver = await make_context(program, db_session, scope)

    result = await PassiveReconStage(max_reverse_lookups=256).run(ctx)

    assert resolver.reverse_calls == 0
    note = next((n for n in result.notes if "reverse-lookup limit" in n), None)
    assert note is not None, result.notes
    assert "65536 addresses" in note
    assert "narrow the scope entry" in note


@respx.mock
async def test_a_single_address_in_scope_is_still_reverse_resolved(
    program, db_session
) -> None:
    """A /32 has no "usable hosts", so it needs its own path."""
    respx.route(host="rdap.org").mock(return_value=httpx.Response(404))
    respx.route(host="dns.google").mock(return_value=httpx.Response(404))

    scope = make_scope(in_scope=["203.0.113.7"], out_of_scope=["*.example.com"])
    ctx, resolver = await make_context(
        program, db_session, scope, ptr={"203.0.113.7": ("host.example.net",)}
    )

    await PassiveReconStage(max_reverse_lookups=8).run(ctx)

    assert resolver.reverse_calls == 1
    ptr = await observations(db_session, program, "dns_record")
    assert ptr["203.0.113.7:PTR"] == "host.example.net"


async def test_an_empty_scope_says_so_and_does_nothing(program, db_session) -> None:
    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    # A wildcard root is a domain, so remove it to get a scope with no seeds at
    # all. Scope requires one entry, so use a regex rule, which names no host.
    scope = make_scope(in_scope=[r"re:^nothing-[0-9]+\.example\.com$"], out_of_scope=[])
    ctx, resolver = await make_context(program, db_session, scope)

    result = await PassiveReconStage().run(ctx)

    assert resolver.reverse_calls == 0
    assert any("no domains or address ranges" in note for note in result.notes)
    assert await observations(db_session, program) == {}


def test_the_reverse_sweep_can_be_switched_off_entirely() -> None:
    assert PassiveReconStage(max_reverse_lookups=0)._max_reverse_lookups == 0
    assert PassiveReconStage(max_reverse_lookups=-5)._max_reverse_lookups == 0


