"""Tests for per-program scan options and the wiring they fixed.

Three bugs are covered here, and all three had the same shape: the code ran, the
scan finished, and the setting did nothing.

* ``--wordlist`` reached only the subdomain stage, so pointing it at SecLists left
  content and parameter discovery on their 72 and 103 built-in entries.
* The REST API and the scheduler each built an orchestrator with no stage
  instances, so **a program under 24/7 monitoring could not be tuned at all**.
  Only a manually typed CLI scan could.
* A missing wordlist file fell back silently, so a typo looked exactly like a
  successful scan with ten thousand fewer requests.

Each is asserted against observable behaviour -- what was requested, what the
stage reported -- rather than by reading the configuration back.
"""

from __future__ import annotations

import pytest
import yaml

from reconx.config import Settings
from reconx.orchestrator import Orchestrator, build_stage
from reconx.scope.model import ScanOptions, Scope, ScopeParseError, load_scope
from reconx.stages.wordlists import (
    COMMON_CONTENT_PATHS,
    COMMON_PARAMETER_NAMES,
    COMMON_SUBDOMAIN_LABELS,
    resolve_wordlist,
)
from tests.conftest import make_scope
from tests.fixtures.target_app import run_target_app


@pytest.fixture
def target():
    with run_target_app() as app:
        yield app


def scope_yaml(**scan_options) -> str:
    return yaml.safe_dump(
        {
            "program": "Options Test",
            "authorization": {
                "authorized_by": "researcher@example.com",
                "date": "2026-09-28",
                "attestation": "I am authorized to test this scope.",
            },
            "in_scope": ["example.com"],
            "scan_options": scan_options,
        }
    )


# ---------------------------------------------------------------------------
# the options block itself
# ---------------------------------------------------------------------------


def test_scan_options_round_trip_through_a_scope_file(tmp_path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text(
        scope_yaml(
            path_wordlist="/tmp/paths.txt",
            skip_checks=["SSRF", " cmdi "],
            ports=[8443, 80, 8443],
            archives=False,
        )
    )
    scope = load_scope(path)

    assert scope.scan_options.path_wordlist == "/tmp/paths.txt"
    # Normalised, so a scope file may be written however its author likes.
    assert scope.scan_options.skip_checks == ["ssrf", "cmdi"]
    assert scope.scan_options.ports == [80, 8443]
    assert scope.scan_options.archives is False


def test_an_unknown_check_name_is_rejected_when_the_scope_loads(tmp_path) -> None:
    """A typo must not mean "everything runs" with nobody told."""
    path = tmp_path / "scope.yaml"
    path.write_text(scope_yaml(skip_checks=["sqli", "xxs"]))

    with pytest.raises(ScopeParseError) as excinfo:
        load_scope(path)
    assert "xxs" in str(excinfo.value)


def test_an_impossible_port_is_rejected() -> None:
    with pytest.raises(ValueError):
        ScanOptions(ports=[0])
    with pytest.raises(ValueError):
        ScanOptions(ports=[65536])


def test_a_scope_with_no_options_block_keeps_every_default() -> None:
    scope = make_scope()
    options = scope.scan_options
    assert options.subdomain_wordlist is None
    assert options.skip_checks == []
    assert options.run_nuclei is True
    assert options.crawl is True


# ---------------------------------------------------------------------------
# options reach the stages
# ---------------------------------------------------------------------------


def test_each_wordlist_reaches_its_own_stage() -> None:
    """The original bug: only the subdomain stage ever saw a wordlist."""
    options = ScanOptions(
        subdomain_wordlist="/s.txt",
        path_wordlist="/p.txt",
        parameter_wordlist="/q.txt",
    )
    assert build_stage("subdomains", options)._wordlist_path == "/s.txt"
    assert build_stage("content", options)._wordlist_path == "/p.txt"
    assert build_stage("params", options)._wordlist_path == "/q.txt"


def test_skipped_checks_reach_the_vulnerability_stage() -> None:
    stage = build_stage("vulns", ScanOptions(skip_checks=["ssrf", "cmdi", "cors"]))
    assert stage._enabled == {
        "sqli": True,
        "xss": True,
        "redirect": True,
        "cors": False,
        "traversal": True,
        "ssti": True,
        "cmdi": False,
        "deser": True,
        "ssrf": False,
    }


def test_ports_reach_the_probe_stage() -> None:
    assert build_stage("resolve_probe", ScanOptions(ports=[80, 8443]))._ports == (80, 8443)
    # No ports configured means the stage's own default set, not an empty one.
    assert build_stage("resolve_probe", ScanOptions())._ports


def test_a_stage_with_no_options_falls_back_to_a_plain_constructor() -> None:
    assert build_stage("ports", ScanOptions()) is None


def test_an_orchestrator_built_from_a_scope_alone_is_already_tuned() -> None:
    """This is the fix: the API and the scheduler pass only a scope.

    Neither has a way to hand over stage instances, so before ``scan_options``
    existed a scheduled scan was a default scan whatever its operator wanted.
    """
    raw = scope_yaml(
        path_wordlist="/p.txt",
        skip_checks=["ssrf"],
        run_nuclei=False,
        use_external_tools=False,
    )
    scope = Scope.model_validate(yaml.safe_load(raw))
    orchestrator = Orchestrator(scope, scope_yaml=raw, settings=Settings())

    assert orchestrator._use_external_tools is False
    assert orchestrator._stage("content")._wordlist_path == "/p.txt"
    vulns = orchestrator._stage("vulns")
    assert vulns._run_nuclei is False
    assert vulns._enabled["ssrf"] is False
    assert vulns._enabled["sqli"] is True


def test_an_explicit_stage_instance_still_wins_over_the_scope() -> None:
    """The CLI hands over instances, and those must not be second-guessed."""
    from reconx.stages.content import ContentStage

    raw = scope_yaml(path_wordlist="/from-scope.txt")
    scope = Scope.model_validate(yaml.safe_load(raw))
    orchestrator = Orchestrator(
        scope,
        scope_yaml=raw,
        stage_instances={"content": ContentStage(wordlist_path="/from-flag.txt")},
    )
    assert orchestrator._stage("content")._wordlist_path == "/from-flag.txt"


# ---------------------------------------------------------------------------
# a wordlist changes what is requested
# ---------------------------------------------------------------------------


@pytest.mark.slow
async def test_a_path_wordlist_changes_what_content_discovery_requests(
    file_db, target, tmp_path
) -> None:
    """Asserted against the audit log, not by reading the setting back.

    A configuration test that checks the value was stored proves nothing about
    whether anything used it. The claim is that these exact paths were requested,
    so that is what is checked -- and the paths are chosen to be ones no built-in
    list contains.
    """
    from reconx.stages.content import ContentStage
    from reconx.stages.resolve_probe import ResolveProbeStage

    distinctive = ["rx-marker-alpha", "rx-marker-beta", "rx-marker-gamma"]
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("# a comment that must be ignored\n\n" + "\n".join(distinctive))

    scope = make_scope(
        program="Wordlist Target", in_scope=[target.host], out_of_scope=[]
    )
    orchestrator = Orchestrator(
        scope,
        use_external_tools=False,
        stage_instances={
            "resolve_probe": ResolveProbeStage(ports=(target.port,)),
            "content": ContentStage(
                wordlist_path=str(wordlist),
                crawl=False,
                archives=False,
                brute_force=True,
            ),
        },
    )
    summary = await orchestrator.run(["resolve_probe", "content"])
    assert summary.status.value == "completed", summary.error

    requested = target.requested_paths
    for marker in distinctive:
        assert f"/{marker}" in requested, (
            f"{marker} from the wordlist was never requested"
        )
    # And the built-in list was not used instead of it.
    assert "/.git/config" not in requested


@pytest.mark.slow
async def test_a_scheduled_run_uses_the_programs_persisted_wordlist(
    file_db, target, tmp_path
) -> None:
    """The whole reason scan_options exists, proved through the scheduler.

    ``MonitorService.tick()`` reaches the orchestrator with nothing but the stored
    scope, exactly as a 3am cron firing would. If the wordlist in that scope does
    not reach the target, a monitored program cannot be tuned.
    """
    from reconx.db.session import get_session_factory
    from reconx.db.store import upsert_program, upsert_schedule_entry
    from reconx.monitor.scheduler import MonitorService

    distinctive = ["rx-scheduled-one", "rx-scheduled-two"]
    wordlist = tmp_path / "scheduled.txt"
    wordlist.write_text("\n".join(distinctive))

    raw = yaml.safe_dump(
        {
            "program": "Scheduled Wordlist Target",
            "authorization": {
                "authorized_by": "researcher@example.com",
                "date": "2026-09-28",
                "attestation": "I am authorized to test this scope.",
            },
            "in_scope": [target.host],
            "out_of_scope": [],
            "scan_options": {
                "path_wordlist": str(wordlist),
                "crawl": False,
                "archives": False,
                "use_external_tools": False,
                # The fixture listens on an ephemeral port, so this also proves
                # the ports option survives into a scheduled run: without it the
                # probe stage finds nothing live and content has no base URL.
                "ports": [target.port],
            },
        }
    )
    scope = Scope.model_validate(yaml.safe_load(raw))

    factory = get_session_factory()
    async with factory() as session:
        program = await upsert_program(session, scope, scope_yaml=raw)
        await session.commit()
        # Due immediately, so one tick picks it up exactly as a cron firing would.
        await upsert_schedule_entry(
            session, program.id, "content", interval_seconds=3600
        )
        await session.commit()

    service = MonitorService(tick_seconds=60, use_external_tools=False)
    report = await service.tick()

    assert not report.errors, report.errors
    assert "scheduled-wordlist-target" in report.programs_run, report
    requested = target.requested_paths
    for marker in distinctive:
        assert f"/{marker}" in requested, (
            f"{marker} from the program's stored options never reached the target: "
            "a scheduled scan is still not tunable"
        )


# ---------------------------------------------------------------------------
# a missing wordlist is reported, not swallowed
# ---------------------------------------------------------------------------


def test_a_missing_wordlist_falls_back_and_says_so() -> None:
    words, note = resolve_wordlist("/no/such/seclists.txt", COMMON_CONTENT_PATHS)
    assert words == list(COMMON_CONTENT_PATHS)
    assert note is not None
    assert "does not exist" in note
    assert "Check the path" in note


def test_a_wordlist_of_only_comments_falls_back_and_says_so(tmp_path) -> None:
    path = tmp_path / "empty.txt"
    path.write_text("# nothing here\n\n   \n")
    words, note = resolve_wordlist(path, COMMON_PARAMETER_NAMES)
    assert words == list(COMMON_PARAMETER_NAMES)
    assert "no usable entries" in note


def test_a_usable_wordlist_reports_what_it_loaded(tmp_path) -> None:
    path = tmp_path / "words.txt"
    path.write_text("Admin\n# comment\nadmin\nAPI\n")
    words, note = resolve_wordlist(path, COMMON_SUBDOMAIN_LABELS)
    # Lower-cased and deduplicated.
    assert words == ["admin", "api"]
    assert "loaded 2 entries" in note


def test_no_wordlist_configured_produces_no_note() -> None:
    words, note = resolve_wordlist(None, COMMON_SUBDOMAIN_LABELS)
    assert words == list(COMMON_SUBDOMAIN_LABELS)
    assert note is None
