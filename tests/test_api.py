"""Tests for the HTTP API."""

from __future__ import annotations

import httpx
import pytest
import pytest_asyncio

from reconx.api.app import ApiExposureError, assert_safe_binding, create_app
from reconx.config import Settings
from reconx.db.models import FindingTier, Severity
from reconx.db.session import get_session_factory
from reconx.db.store import upsert_asset, upsert_endpoint, upsert_finding, upsert_program
from tests.conftest import make_scope


@pytest_asyncio.fixture
async def seeded(file_db):
    """A program with one confirmed finding and one discarded candidate."""
    factory = get_session_factory()
    async with factory() as session:
        program = await upsert_program(
            session, make_scope(), scope_yaml="program: Example Corp VDP"
        )
        await session.commit()
        await upsert_asset(
            session, program.id, "www.example.com",
            is_live=True, http_status=200, title="Home", technologies=["nginx"],
        )
        await upsert_endpoint(
            session, program.id, "https://www.example.com/search?q=1",
            parameters=["q"], reflected_parameters=["q"], status=200,
            interesting_score=1.0,
        )
        finding, _ = await upsert_finding(
            session, program.id,
            dedup_key="sqli::/search::q", vuln_class="sqli",
            title="SQL injection in 'q' at /search",
            severity=Severity.CRITICAL, tier=FindingTier.CONFIRMED, confidence=95,
            priority=9.7, affected_hosts=["www.example.com"],
            signals=["boolean_differential", "error_signature"],
            description="two oracles agreed",
            recommendation="Establish impact without touching data.",
        )
        from reconx.db.store import add_evidence

        await add_evidence(
            session, finding.id, label="boolean differential",
            request_url="https://www.example.com/search?q=1%27",
            curl_command="curl -sS -i -k 'https://www.example.com/search?q=1%27'",
        )
        await upsert_finding(
            session, program.id,
            dedup_key="sqli::/static::id", vuln_class="sqli",
            title="SQL injection in 'id' at /static",
            severity=Severity.HIGH, tier=FindingTier.DISCARDED,
            discard_reason="the error string was already present in the unmodified page",
        )
        await session.commit()
    return "example-corp-vdp"


@pytest_asyncio.fixture
async def client(seeded):
    app = create_app(Settings())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as http_client, app.router.lifespan_context(app):
        yield http_client


# ---------------------------------------------------------------------------
# exposure
# ---------------------------------------------------------------------------


def test_loopback_needs_no_token() -> None:
    for host in ("127.0.0.1", "::1", "localhost"):
        assert_safe_binding(host, "")


def test_binding_off_loopback_without_a_token_is_refused() -> None:
    """This API serves a list of another organisation's weaknesses."""
    for host in ("0.0.0.0", "10.0.0.5", "example.com"):
        with pytest.raises(ApiExposureError, match="refusing to bind"):
            assert_safe_binding(host, "")


def test_binding_off_loopback_with_a_token_is_allowed() -> None:
    assert_safe_binding("0.0.0.0", "a-long-shared-secret")


async def test_a_configured_token_is_required(seeded) -> None:
    app = create_app(Settings(api_token="s3cret"))
    transport = httpx.ASGITransport(app=app)
    async with (
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as c,
        app.router.lifespan_context(app),
    ):
        assert (await c.get("/api/v1/programs")).status_code == 401
        bad = await c.get("/api/v1/programs", headers={"Authorization": "Bearer wrong"})
        assert bad.status_code == 401
        good = await c.get(
            "/api/v1/programs", headers={"Authorization": "Bearer s3cret"}
        )
        assert good.status_code == 200


# ---------------------------------------------------------------------------
# reads
# ---------------------------------------------------------------------------


async def test_health_needs_no_auth(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_programs_list(client: httpx.AsyncClient, seeded: str) -> None:
    payload = (await client.get("/api/v1/programs")).json()
    assert payload["count"] == 1
    assert payload["programs"][0]["slug"] == seeded


async def test_program_detail_includes_the_authorizing_scope(
    client: httpx.AsyncClient, seeded: str
) -> None:
    """Anyone reading findings should be able to see what was in bounds."""
    payload = (await client.get(f"/api/v1/programs/{seeded}")).json()
    assert "scope_yaml" in payload
    assert payload["attestation"]


async def test_an_unknown_program_is_a_404(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/programs/nope")
    assert response.status_code == 404
    assert "nope" in response.json()["detail"]


async def test_assets_can_be_filtered_by_liveness(
    client: httpx.AsyncClient, seeded: str
) -> None:
    live = (await client.get(f"/api/v1/programs/{seeded}/assets?live=true")).json()
    assert live["count"] == 1
    assert live["assets"][0]["host"] == "www.example.com"
    dead = (await client.get(f"/api/v1/programs/{seeded}/assets?live=false")).json()
    assert dead["count"] == 0


async def test_findings_return_only_what_surfaced_by_default(
    client: httpx.AsyncClient, seeded: str
) -> None:
    payload = (await client.get(f"/api/v1/programs/{seeded}/findings")).json()
    assert payload["count"] == 1
    finding = payload["findings"][0]
    assert finding["tier"] == "confirmed"
    assert finding["signals"] == ["boolean_differential", "error_signature"]
    assert finding["evidence"][0]["curl_command"].startswith("curl ")


async def test_discarded_findings_are_available_for_auditing(
    client: httpx.AsyncClient, seeded: str
) -> None:
    """The filter has to be inspectable through the API too."""
    payload = (
        await client.get(f"/api/v1/programs/{seeded}/findings?tier=discarded")
    ).json()
    assert payload["count"] == 1
    assert "already present" in payload["findings"][0]["discard_reason"]


async def test_an_unknown_tier_is_rejected_helpfully(
    client: httpx.AsyncClient, seeded: str
) -> None:
    response = await client.get(f"/api/v1/programs/{seeded}/findings?tier=nonsense")
    assert response.status_code == 400
    assert "confirmed" in response.json()["detail"]


async def test_endpoints_are_returned_with_their_parameters(
    client: httpx.AsyncClient, seeded: str
) -> None:
    payload = (await client.get(f"/api/v1/programs/{seeded}/endpoints")).json()
    assert payload["count"] == 1
    assert payload["endpoints"][0]["reflected_parameters"] == ["q"]


async def test_recommendations_are_served(
    client: httpx.AsyncClient, seeded: str
) -> None:
    payload = (
        await client.get(f"/api/v1/programs/{seeded}/recommendations?limit=5")
    ).json()
    assert payload["count"] >= 1
    first = payload["recommendations"][0]
    assert first["action"] and first["why"]


async def test_tools_endpoint_reports_availability_and_fallbacks(
    client: httpx.AsyncClient,
) -> None:
    payload = (await client.get("/api/v1/tools")).json()
    assert payload["count"] >= 10
    assert all("fallback" in tool for tool in payload["tools"])


async def test_reports_render_in_both_formats(
    client: httpx.AsyncClient, seeded: str
) -> None:
    markdown = await client.get(f"/api/v1/programs/{seeded}/report")
    assert markdown.status_code == 200
    assert "# Example Corp VDP" in markdown.text

    html = await client.get(f"/api/v1/programs/{seeded}/report.html")
    assert html.status_code == 200
    assert "<!doctype html>" in html.text.lower()
    assert "SQL injection" in html.text


# ---------------------------------------------------------------------------
# actions
# ---------------------------------------------------------------------------


async def test_starting_a_scan_on_an_unknown_program_is_a_404(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post("/api/v1/programs/nope/scans")
    assert response.status_code == 404


async def test_starting_a_scan_with_an_unknown_stage_is_rejected(
    client: httpx.AsyncClient, seeded: str
) -> None:
    response = await client.post(
        f"/api/v1/programs/{seeded}/scans", json={"stages": ["nonsense"]}
    )
    assert response.status_code == 400
    assert "unknown stage" in response.json()["detail"]


async def test_the_running_endpoint_reports_in_flight_scans(
    client: httpx.AsyncClient,
) -> None:
    payload = (await client.get("/api/v1/running")).json()
    assert payload["count"] == 0
    assert payload["programs"] == []
