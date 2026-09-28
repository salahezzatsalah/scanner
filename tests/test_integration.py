"""End-to-end tests against a local target and stubbed DNS.

These are the tests that check the central claim. Each one either proves a real
thing is found, or proves a deliberate false-positive trap is rejected for the
right reason.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from reconx.config import Settings
from reconx.db.models import Asset, Observation, Program
from reconx.net.dns import DnsAnswer, ScopedResolver, WildcardProfile
from reconx.net.http import ScopedHttpClient
from reconx.net.sources import SourceClient
from reconx.scope.guard import ScopeGuard
from reconx.stages.base import StageContext
from reconx.stages.resolve_probe import ResolveProbeStage
from reconx.stages.subdomains import SubdomainStage
from tests.conftest import make_scope
from tests.fixtures.target_app import run_target_app


def fast_settings(**overrides) -> Settings:
    payload = {
        "requests_per_second_per_host": 200.0,
        "max_concurrent_requests": 20,
        "http_timeout_seconds": 5.0,
        "max_retries": 0,
        "wildcard_probe_count": 2,
    }
    payload.update(overrides)
    return Settings(**payload)


@pytest.fixture
def target():
    with run_target_app() as app:
        yield app


# ---------------------------------------------------------------------------
# stubs
# ---------------------------------------------------------------------------


class StubResolver:
    """A resolver with scripted answers, for deterministic wildcard tests."""

    def __init__(
        self,
        *,
        answers: dict[str, tuple[str, ...]],
        wildcard: WildcardProfile | None = None,
        default: tuple[str, ...] = (),
    ) -> None:
        self._answers = answers
        self._wildcard = wildcard
        self._default = default
        self.queries = 0
        self.blocked = 0

    async def resolve(self, host: str, rdtype: str = "A") -> DnsAnswer:
        self.queries += 1
        values = self._answers.get(host, self._default)
        return DnsAnswer(
            host=host,
            rdtype=rdtype,
            values=values,
            error=None if values else "NXDOMAIN",
        )

    async def resolve_many(self, hosts, rdtype: str = "A") -> list[DnsAnswer]:
        return [await self.resolve(host, rdtype) for host in hosts]

    async def records(self, host: str, rdtypes=()) -> dict[str, DnsAnswer]:
        return {"A": await self.resolve(host, "A")}

    async def profile_wildcard(self, domain: str, **kwargs) -> WildcardProfile:
        if self._wildcard and self._wildcard.domain == domain:
            return self._wildcard
        return WildcardProfile(domain=domain, probed=True, is_wildcard=False)

    async def wildcard_for_host(self, host: str):
        return await self.profile_wildcard(host.partition(".")[2])


async def make_context(
    session: AsyncSession,
    program: Program,
    *,
    scope=None,
    dns=None,
    settings: Settings | None = None,
) -> StageContext:
    resolved_scope = scope or make_scope()
    guard = ScopeGuard(resolved_scope)
    resolved_settings = settings or fast_settings()
    return StageContext(
        program_id=program.id,
        scan_run_id=1,
        scope=resolved_scope,
        guard=guard,
        http=ScopedHttpClient(guard, settings=resolved_settings),
        dns=dns or ScopedResolver(guard, settings=resolved_settings),
        sources=SourceClient(settings=resolved_settings),
        session=session,
        settings=resolved_settings,
        # Hermetic: never shell out to a real scanner from a test.
        use_external_tools=False,
    )


# ---------------------------------------------------------------------------
# probing a real local target
# ---------------------------------------------------------------------------


async def test_probe_finds_a_real_host_and_records_what_it_serves(
    db_session: AsyncSession, program: Program, target
) -> None:
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope)
    ctx.shared["subdomain_hosts"] = [target.host]

    stage = ResolveProbeStage(ports=(target.port,))
    result = await stage.run(ctx)
    await db_session.commit()

    assert result.items_out == 1
    asset = (
        await db_session.execute(select(Asset).where(Asset.host == target.host))
    ).scalars().first()
    assert asset is not None
    assert asset.is_live is True
    assert asset.http_status == 200
    assert asset.title == "Example Corp"
    # Header- and body-based technology hints, without httpx installed.
    assert "ExampleCorp" in (asset.technologies or [])
    await ctx.http.aclose()
    await ctx.sources.aclose()


async def test_probe_never_touches_an_out_of_scope_host(
    db_session: AsyncSession, program: Program, target
) -> None:
    """The pipeline must not reach a host the scope does not cover."""
    scope = make_scope(in_scope=["api.example.io"], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope)
    ctx.shared["subdomain_hosts"] = [target.host, "api.example.io"]

    stage = ResolveProbeStage(ports=(target.port,))
    await stage.run(ctx)

    assert target.requested_paths == [], "the scanner reached an out-of-scope host"
    await ctx.http.aclose()
    await ctx.sources.aclose()


async def test_identical_hosts_collapse_into_one_application(
    db_session: AsyncSession, program: Program, target
) -> None:
    """Many names on one load balancer must not become many units of work."""
    scope = make_scope(in_scope=[target.host, "127.0.0.2"], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope)
    # Both names serve byte-identical content from the same fixture server.
    ctx.shared["subdomain_hosts"] = [target.host, "127.0.0.2"]

    stage = ResolveProbeStage(ports=(target.port,))
    result = await stage.run(ctx)
    await db_session.commit()

    if result.items_out < 2:
        pytest.skip("127.0.0.2 is not routable in this environment")

    groups = (
        await db_session.execute(
            select(Observation).where(Observation.kind == "duplicate_group")
        )
    ).scalars().all()
    assert groups, "identical responses were not grouped"
    assert any("distinct applications" in note for note in result.notes)
    await ctx.http.aclose()
    await ctx.sources.aclose()


# ---------------------------------------------------------------------------
# the soft-404 trap
# ---------------------------------------------------------------------------


async def test_soft_404_pages_are_recognised_as_the_same_page(
    db_session: AsyncSession, program: Program, target
) -> None:
    """The trap that makes other scanners report every path as a hit.

    The fixture answers unknown paths with HTTP 200 and not-found wording, plus a
    fresh request id and timestamp each time. Hash comparison sees two different
    pages; ReconX must see one.
    """
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    guard = ScopeGuard(scope)
    settings = fast_settings()

    async with ScopedHttpClient(guard, settings=settings) as client:
        first = await client.get(target.url("/reconx-probe-aaaa1111"))
        second = await client.get(target.url("/reconx-probe-bbbb2222"))
        real_page = await client.get(target.url("/admin"))

    assert first.status == second.status == 200
    # Byte-level they differ, which is why hashing fails here.
    assert first.fingerprint.body_sha256 != second.fingerprint.body_sha256
    # Fuzzy comparison sees through the noise.
    assert first.fingerprint.looks_same_as(second.fingerprint)
    # And a genuinely different page is still distinguished.
    assert not first.fingerprint.looks_same_as(real_page.fingerprint)


async def test_a_real_404_and_a_soft_404_are_not_confused(
    db_session: AsyncSession, program: Program, target
) -> None:
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    guard = ScopeGuard(scope)
    async with ScopedHttpClient(guard, settings=fast_settings()) as client:
        soft = await client.get(target.url("/some-missing-path"))
        hard = await client.get(target.url("/real-404"))
    assert soft.status == 200 and hard.status == 404
    assert not soft.fingerprint.looks_same_as(hard.fingerprint)


# ---------------------------------------------------------------------------
# the wildcard DNS trap
# ---------------------------------------------------------------------------


@respx.mock
async def test_wildcard_dns_artifacts_are_dropped_but_real_hosts_survive(
    db_session: AsyncSession, program: Program
) -> None:
    """The single biggest false positive in reconnaissance.

    Setup: ``*.example.com`` resolves everything to one address. Certificate
    transparency proposes two names, so both are evidence-backed and both get an
    HTTP check. One serves what the wildcard serves; the other serves something
    different. Only the second is a real host.
    """
    probe = "reconx-wildcard-probe-fixed.example.com"
    wildcard = WildcardProfile(
        domain="example.com",
        probed=True,
        is_wildcard=True,
        values=frozenset({"203.0.113.10"}),
        probes=[probe],
    )
    resolver = StubResolver(
        answers={},
        wildcard=wildcard,
        default=("203.0.113.10",),  # every name resolves, as a wildcard zone does
    )

    wildcard_body = (
        "<html><head><title>Example Corp</title></head><body>"
        "<h1>Nothing here yet</h1><p>This domain is parked.</p></body></html>"
    )
    real_body = (
        "<html><head><title>Internal Reporting</title></head><body>"
        "<h1>Reporting console</h1><p>Select a dataset to export.</p>"
        "<form><input name=dataset></form></body></html>"
    )

    # crt.sh proposes both names.
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name_value": "real.example.com"},
                {"name_value": "parked.example.com"},
            ],
        )
    )
    # The other passive sources are unavailable in this test.
    respx.get(url__startswith="https://api.certspotter.com").mock(
        return_value=httpx.Response(404)
    )
    respx.get(url__startswith="https://otx.alienvault.com").mock(
        return_value=httpx.Response(404)
    )

    html_headers = {"Content-Type": "text/html"}
    for host, body in (
        (probe, wildcard_body),
        ("parked.example.com", wildcard_body),
        ("real.example.com", real_body),
    ):
        for scheme in ("https", "http"):
            respx.get(f"{scheme}://{host}/").mock(
                return_value=httpx.Response(200, text=body, headers=html_headers)
            )

    scope = make_scope(in_scope=["*.example.com"], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope, dns=resolver)

    stage = SubdomainStage(brute_force=False, permutations=False)
    result = await stage.run(ctx)
    await db_session.commit()

    accepted = {asset.host for asset in (
        await db_session.execute(select(Asset).where(Asset.program_id == program.id))
    ).scalars().all()}

    assert "real.example.com" in accepted, "a real host behind a wildcard was lost"
    assert "parked.example.com" not in accepted, "a wildcard artifact was reported"
    assert result.filter_reasons.get("wildcard_dns", 0) >= 1
    assert any("wildcard DNS detected" in note for note in result.notes)

    await ctx.http.aclose()
    await ctx.sources.aclose()


@respx.mock
async def test_passive_sources_volunteering_unrelated_domains_are_dropped(
    db_session: AsyncSession, program: Program
) -> None:
    """crt.sh routinely returns names outside the program. They must not be scanned."""
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name_value": "good.example.com\nunrelated.other-company.com"},
                {"name_value": "payments.example.com"},  # explicitly excluded
            ],
        )
    )
    respx.get(url__startswith="https://api.certspotter.com").mock(
        return_value=httpx.Response(404)
    )
    respx.get(url__startswith="https://otx.alienvault.com").mock(
        return_value=httpx.Response(404)
    )
    leaked = respx.get(url__startswith="https://unrelated.other-company.com").mock(
        return_value=httpx.Response(200)
    )

    resolver = StubResolver(answers={"good.example.com": ("203.0.113.20",)})
    scope = make_scope(
        in_scope=["*.example.com"], out_of_scope=["payments.example.com"]
    )
    ctx = await make_context(db_session, program, scope=scope, dns=resolver)

    stage = SubdomainStage(brute_force=False, permutations=False)
    result = await stage.run(ctx)
    await db_session.commit()

    assert leaked.called is False
    accepted = {asset.host for asset in (
        await db_session.execute(select(Asset).where(Asset.program_id == program.id))
    ).scalars().all()}
    assert "good.example.com" in accepted
    assert "unrelated.other-company.com" not in accepted
    assert "payments.example.com" not in accepted
    assert result.filter_reasons.get("out_of_scope", 0) >= 2

    await ctx.http.aclose()
    await ctx.sources.aclose()


async def test_scope_without_wildcards_says_so_rather_than_silently_doing_nothing(
    db_session: AsyncSession, program: Program
) -> None:
    resolver = StubResolver(answers={"api.example.io": ("203.0.113.30",)})
    scope = make_scope(in_scope=["api.example.io"], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope, dns=resolver)

    result = await SubdomainStage().run(ctx)
    assert any("no wildcard domains" in note for note in result.notes)
    await ctx.http.aclose()
    await ctx.sources.aclose()


# ---------------------------------------------------------------------------
# IP and CIDR scopes
# ---------------------------------------------------------------------------


async def test_an_address_only_scope_still_gets_probed(
    db_session: AsyncSession, program: Program, target
) -> None:
    """Regression: a scope naming only addresses used to probe nothing.

    Seeding looked at hostnames only, so a program scoped to an IP or a CIDR
    range produced an empty probe list and reported success having done nothing.
    Programs routinely scope address ranges.
    """
    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope)
    # Deliberately no shared host list and no prior assets.
    assert ctx.shared == {}

    result = await ResolveProbeStage(ports=(target.port,)).run(ctx)
    await db_session.commit()

    assert result.items_in == 1, "the address named in the scope was not probed"
    assert result.items_out == 1
    asset = (
        await db_session.execute(select(Asset).where(Asset.host == target.host))
    ).scalars().first()
    assert asset is not None and asset.is_live is True
    assert asset.kind.value == "ip", "an address was recorded as a hostname"
    await ctx.http.aclose()
    await ctx.sources.aclose()


async def test_small_cidr_ranges_expand_and_oversized_ones_are_reported(
    db_session: AsyncSession, program: Program
) -> None:
    """A /30 is worth probing. A /8 is 16 million addresses and is not."""
    small = make_scope(in_scope=["203.0.113.0/30"], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=small)
    stage = ResolveProbeStage()
    stage._oversized_ranges = []
    assert len(stage._scope_addresses(ctx)) == 2
    assert stage._oversized_ranges == []

    huge = make_scope(in_scope=["10.0.0.0/8"], out_of_scope=[])
    ctx_huge = await make_context(db_session, program, scope=huge)
    stage_huge = ResolveProbeStage()
    stage_huge._oversized_ranges = []
    assert stage_huge._scope_addresses(ctx_huge) == []
    assert len(stage_huge._oversized_ranges) == 1
    assert "above the" in stage_huge._oversized_ranges[0]

    for context in (ctx, ctx_huge):
        await context.http.aclose()
        await context.sources.aclose()


async def test_nothing_to_probe_says_so_clearly(
    db_session: AsyncSession, program: Program
) -> None:
    scope = make_scope(in_scope=["api.example.io"], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope)
    result = await ResolveProbeStage().run(ctx)
    assert result.items_in == 0
    assert any("nothing in scope to probe" in note for note in result.notes)
    await ctx.http.aclose()
    await ctx.sources.aclose()


# ---------------------------------------------------------------------------
# content discovery on a soft-404 host
# ---------------------------------------------------------------------------


async def test_wordlist_discovery_on_a_soft_404_host_finds_only_real_paths(
    db_session: AsyncSession, program: Program, target
) -> None:
    """The trap that makes path brute forcing useless without a baseline.

    The fixture answers every unknown path with HTTP 200 and a not-found page, so
    a scanner that treats 200 as "exists" reports the entire wordlist. ReconX
    learns the not-found page first and keeps only what differs from it.
    """
    from reconx.db.models import Endpoint
    from reconx.stages.content import ContentStage

    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope)

    # Establish the host as live so content discovery has something to explore.
    await ResolveProbeStage(ports=(target.port,)).run(ctx)
    await db_session.commit()

    stage = ContentStage(crawl=True, archives=False, brute_force=True)
    result = await stage.run(ctx)
    await db_session.commit()

    found = {
        endpoint.url
        for endpoint in (
            await db_session.execute(
                select(Endpoint).where(Endpoint.program_id == program.id)
            )
        ).scalars().all()
    }
    paths = {url.split(target.base_url, 1)[-1] or "/" for url in found}

    # Real endpoints are found.
    assert "/admin" in paths
    assert "/robots.txt" in paths

    # Wordlist entries that do not exist are filtered, not reported.
    for missing in ("/phpmyadmin", "/wp-login.php", "/.aws/credentials", "/backup.sql"):
        assert missing not in paths, f"{missing} is a soft-404 page, not a discovery"

    # And the filtering is accounted for rather than silent.
    assert result.filter_reasons.get("soft_404", 0) > 20
    assert any("soft-404" in note for note in result.notes)
    assert len(paths) < 25, f"too many endpoints kept, filtering is not working: {len(paths)}"

    await ctx.http.aclose()
    await ctx.sources.aclose()


async def test_javascript_is_mined_for_endpoints_and_credentials(
    db_session: AsyncSession, program: Program, target
) -> None:
    """Client-side code names endpoints that are never linked."""
    from reconx.db.models import Endpoint, Finding
    from reconx.stages.content import ContentStage

    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope)
    await ResolveProbeStage(ports=(target.port,)).run(ctx)
    await db_session.commit()

    await ContentStage(crawl=True, archives=False, brute_force=False).run(ctx)
    await db_session.commit()

    found = {
        endpoint.url
        for endpoint in (
            await db_session.execute(
                select(Endpoint).where(Endpoint.program_id == program.id)
            )
        ).scalars().all()
    }
    # app.js names /api/v1/users and /api/v1/orders. Neither is linked from any
    # page, so finding them proves the JavaScript was actually read, and keeping
    # them proves they were confirmed to exist rather than assumed.
    assert any("/api/v1/users" in url for url in found), f"JS endpoints not mined: {found}"
    assert any("/api/v1/orders" in url for url in found), f"JS endpoints not mined: {found}"

    # The fixture's JS has no real credential, so nothing should be reported.
    secrets = (
        await db_session.execute(
            select(Finding).where(Finding.vuln_class == "exposed_secret")
        )
    ).scalars().all()
    assert secrets == [], "reported a credential where the fixture has none"

    await ctx.http.aclose()
    await ctx.sources.aclose()


async def test_endpoints_are_scored_so_the_interesting_ones_surface(
    db_session: AsyncSession, program: Program, target
) -> None:
    from reconx.db.models import Endpoint
    from reconx.stages.content import ContentStage

    scope = make_scope(in_scope=[target.host], out_of_scope=[])
    ctx = await make_context(db_session, program, scope=scope)
    await ResolveProbeStage(ports=(target.port,)).run(ctx)
    await db_session.commit()
    await ContentStage(crawl=True, archives=False, brute_force=True).run(ctx)
    await db_session.commit()

    rows = (
        await db_session.execute(
            select(Endpoint)
            .where(Endpoint.program_id == program.id)
            .order_by(Endpoint.interesting_score.desc())
        )
    ).scalars().all()
    assert rows
    top = rows[0]
    assert top.interesting_score > 0
    assert "admin" in top.url or "api" in top.url

    await ctx.http.aclose()
    await ctx.sources.aclose()
