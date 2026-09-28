"""Tests for external tool orchestration."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from reconx.scope.guard import OutOfScopeError, ScopeGuard
from reconx.tools.base import (
    ToolNotAvailable,
    ToolResult,
    ToolRunner,
    ToolSpec,
    find_binaries,
)
from reconx.tools.registry import TOOL_SPECS, detect_all, get_runner, get_spec, missing_tools
from tests.conftest import make_scope

ECHO = ToolSpec(
    name="echo-probe",
    binary="echo",
    purpose="a stand-in for a real scanner",
    install="already present",
    version_args=("--version",),
    fallback="nothing, this is a test double",
)

CAT = ToolSpec(
    name="cat-probe",
    binary="cat",
    purpose="echoes stdin back, standing in for a stdin-driven scanner",
    install="already present",
    version_args=("--version",),
    fallback="nothing, this is a test double",
)


@pytest.fixture
def guard() -> ScopeGuard:
    return ScopeGuard(make_scope())


# ---------------------------------------------------------------------------
# the guard requirement
# ---------------------------------------------------------------------------


def test_runner_cannot_be_built_without_a_guard() -> None:
    for bad in (None, "scope", object()):
        with pytest.raises(TypeError):
            ToolRunner(ECHO, bad)  # type: ignore[arg-type]


async def test_out_of_scope_argv_targets_are_dropped(guard: ScopeGuard) -> None:
    """A subprocess must never be handed an unchecked target."""
    runner = ToolRunner(ECHO, guard)
    result = await runner.run(
        [], targets=["www.example.com", "evil.com", "api.example.io", "payments.example.com"]
    )
    assert result.ok
    assert "www.example.com" in result.stdout
    assert "api.example.io" in result.stdout
    assert "evil.com" not in result.stdout
    assert "payments.example.com" not in result.stdout
    assert set(result.targets_skipped) == {"evil.com", "payments.example.com"}


async def test_out_of_scope_stdin_targets_are_dropped(guard: ScopeGuard) -> None:
    """Tools fed by stdin (httpx, dnsx) get the same treatment as argv."""
    runner = ToolRunner(CAT, guard)
    result = await runner.run(
        [], stdin_targets=["www.example.com", "evil.com", "internal.example.com"]
    )
    assert result.lines == ["www.example.com"]
    assert set(result.targets_skipped) == {"evil.com", "internal.example.com"}


async def test_all_targets_out_of_scope_raises_rather_than_running_blind(
    guard: ScopeGuard,
) -> None:
    """Running a scanner with an empty target list usually means a scope bug."""
    runner = ToolRunner(ECHO, guard)
    with pytest.raises(OutOfScopeError):
        await runner.run([], targets=["evil.com", "also-evil.net"])


async def test_require_targets_false_allows_an_empty_result(guard: ScopeGuard) -> None:
    runner = ToolRunner(ECHO, guard)
    result = await runner.run([], targets=["evil.com"], require_targets=False)
    assert result.ok
    assert result.targets_skipped == ["evil.com"]


# ---------------------------------------------------------------------------
# availability and degradation
# ---------------------------------------------------------------------------


async def test_missing_tool_raises_with_install_command_and_fallback(
    guard: ScopeGuard,
) -> None:
    """A missing tool must tell you how to fix it and what you lose meanwhile."""
    spec = ToolSpec(
        name="definitely-not-installed",
        binary="reconx-no-such-binary-xyz",
        purpose="testing",
        install="go install example.com/tool@latest",
        fallback="the built-in prober is used instead",
    )
    runner = ToolRunner(spec, guard)
    assert runner.available is False
    with pytest.raises(ToolNotAvailable) as excinfo:
        await runner.run([])
    message = str(excinfo.value)
    assert "go install example.com/tool@latest" in message
    assert "built-in prober" in message


async def test_status_reports_a_missing_tool_without_raising(guard: ScopeGuard) -> None:
    spec = ToolSpec(
        name="absent", binary="reconx-no-such-binary-xyz", purpose="t", install="n/a"
    )
    status = await ToolRunner(spec, guard).status()
    assert status.available is False
    assert "not found" in (status.error or "")


async def test_identity_check_rejects_a_same_named_different_tool(
    guard: ScopeGuard,
) -> None:
    """Binary names collide across ecosystems; the wrong tool must not count.

    `echo --version` prints GNU coreutils text, which will not match a pattern
    demanding ProjectDiscovery output.
    """
    spec = ToolSpec(
        name="pretend-pd-tool",
        binary="echo",
        purpose="testing identity verification",
        install="go install example.com/tool@latest",
        version_args=("--version",),
        identity_pattern=r"projectdiscovery",
        collision_hint="This is the collision hint.",
    )
    status = await ToolRunner(spec, guard).status()
    assert status.available is False
    assert "none of them is pretend-pd-tool" in (status.error or "")
    assert "This is the collision hint." in (status.error or "")


async def test_identity_check_accepts_a_matching_tool(guard: ScopeGuard) -> None:
    spec = ToolSpec(
        name="coreutils-echo",
        binary="echo",
        purpose="testing identity verification",
        install="n/a",
        version_args=("--version",),
        identity_pattern=r"coreutils|echo",
    )
    status = await ToolRunner(spec, guard).status()
    assert status.available is True
    assert status.path is not None


def test_find_binaries_returns_every_candidate() -> None:
    """Needed to resolve the Python-httpx / ProjectDiscovery-httpx collision."""
    found = find_binaries("sh")
    assert found, "expected to find at least one 'sh'"
    assert all(Path(path).name == "sh" for path in found)
    assert find_binaries("reconx-no-such-binary-xyz") == []


# ---------------------------------------------------------------------------
# output parsing
# ---------------------------------------------------------------------------


def test_json_lines_survives_interleaved_banner_noise() -> None:
    """One unparseable line must not lose the whole result set."""
    result = ToolResult(
        tool="fake",
        returncode=0,
        stdout=(
            "   __ banner art __\n"
            '{"host":"a.example.com","status_code":200}\n'
            "[INF] using 12 sources\n"
            "not json at all\n"
            '{"host":"b.example.com","status_code":403}\n'
            '{"broken": \n'
        ),
    )
    parsed = result.json_lines()
    assert [row["host"] for row in parsed] == ["a.example.com", "b.example.com"]


def test_tool_result_ok_accounts_for_timeouts() -> None:
    assert ToolResult(tool="t", returncode=0).ok is True
    assert ToolResult(tool="t", returncode=1).ok is False
    assert ToolResult(tool="t", returncode=0, timed_out=True).ok is False


async def test_timeout_is_reported_rather_than_hanging(guard: ScopeGuard) -> None:
    spec = ToolSpec(name="sleeper", binary="sleep", purpose="t", install="n/a")
    runner = ToolRunner(spec, guard)
    if not runner.available:
        pytest.skip("sleep not available")
    result = await runner.run(["5"], timeout=0.3)
    assert result.timed_out is True
    assert result.ok is False
    assert "timed out" in result.stderr


# ---------------------------------------------------------------------------
# the catalogue
# ---------------------------------------------------------------------------


def test_every_tool_declares_a_fallback() -> None:
    """No stage may hard-depend on a tool being installed."""
    for name, spec in TOOL_SPECS.items():
        assert spec.fallback.strip(), f"{name} has no documented fallback"


def test_every_tool_declares_an_identity_pattern() -> None:
    """Without one, a same-named binary from another ecosystem can be mistaken."""
    for name, spec in TOOL_SPECS.items():
        assert spec.identity_pattern, f"{name} has no identity_pattern"
        re.compile(spec.identity_pattern)  # must be a valid regex


def test_every_tool_declares_an_install_command() -> None:
    for name, spec in TOOL_SPECS.items():
        assert spec.install.strip(), f"{name} has no install command"


def test_get_spec_rejects_unknown_tools_helpfully() -> None:
    with pytest.raises(KeyError, match="known tools"):
        get_spec("not-a-real-tool")


async def test_detect_all_covers_the_whole_catalogue(guard: ScopeGuard) -> None:
    statuses = await detect_all(guard)
    assert set(statuses) == set(TOOL_SPECS)
    assert len(missing_tools(statuses)) <= len(TOOL_SPECS)


def test_get_runner_builds_a_scoped_runner(guard: ScopeGuard) -> None:
    runner = get_runner("subfinder", guard)
    assert runner.spec.name == "subfinder"


def test_bootstrap_script_and_registry_agree() -> None:
    """The installer and the catalogue must not drift apart.

    bootstrap.sh installs the Go tools; the registry is what `reconx doctor`
    reports against. If one gains a tool and the other does not, a user is told
    to run an installer that will not install it.
    """
    script = Path("scripts/bootstrap.sh").read_text(encoding="utf-8")

    # Entries look like:  "subfinder|github.com/...@latest"
    in_script = dict(
        re.findall(r'^\s*"([a-z0-9_-]+)\|(\S+)"\s*$', script, flags=re.MULTILINE)
    )
    assert in_script, "could not parse the tool list out of bootstrap.sh"

    for name, package in in_script.items():
        assert name in TOOL_SPECS, f"bootstrap.sh installs {name}, registry does not know it"
        assert package in TOOL_SPECS[name].install, (
            f"bootstrap.sh installs {name} from {package}, "
            f"but the registry says: {TOOL_SPECS[name].install}"
        )

    # Every registry tool installed via `go install` should either be in the
    # script's loop or be called out in its "not installed by this script"
    # section, so nothing is silently absent.
    for name, spec in TOOL_SPECS.items():
        if not spec.install.startswith("go install"):
            continue
        assert name in in_script or name in script, (
            f"{name} is a go-installable tool that bootstrap.sh never mentions"
        )


# ---------------------------------------------------------------------------
# regressions
# ---------------------------------------------------------------------------


async def test_run_verifies_identity_before_executing(guard: ScopeGuard) -> None:
    """Regression: a stage must not execute a same-named program from elsewhere.

    Identity verification used to happen only in status(), so a runner used
    without calling it first picked the first binary on PATH. On a machine with
    the Python httpx package installed, that meant a stage shelled out to the
    wrong program and reported a tool failure that looked like a ReconX bug.
    """
    spec = ToolSpec(
        name="strict-tool",
        binary="echo",  # exists, but will not satisfy the identity pattern
        purpose="testing",
        install="go install example.com/tool@latest",
        version_args=("--version",),
        identity_pattern=r"projectdiscovery",
        fallback="the built-in path is used",
    )
    runner = ToolRunner(spec, guard)

    # The cheap pre-check sees a binary with the right name.
    assert runner.available is True
    # The verified check does not, and running must refuse rather than execute it.
    assert await runner.ensure_available() is False
    with pytest.raises(ToolNotAvailable):
        await runner.run([], targets=["www.example.com"])


async def test_identity_resolution_is_cached(guard: ScopeGuard) -> None:
    """Verification executes a subprocess, so it must happen once per runner."""
    spec = ToolSpec(
        name="cached", binary="echo", purpose="t", install="n/a",
        version_args=("--version",), identity_pattern=r"coreutils|echo",
    )
    runner = ToolRunner(spec, guard)
    calls = 0
    original = runner.status

    async def counting_status():
        nonlocal calls
        calls += 1
        return await original()

    runner.status = counting_status  # type: ignore[method-assign]
    assert await runner.ensure_available() is True
    assert await runner.ensure_available() is True
    assert calls == 1
