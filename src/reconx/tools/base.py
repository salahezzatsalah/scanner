"""Running external tools safely.

ReconX orchestrates proven scanners rather than reimplementing them, which
raises an obvious risk: a subprocess handed the wrong argument can send traffic
anywhere. :class:`ToolRunner` closes that hole the same way
:class:`~reconx.net.http.ScopedHttpClient` does — it takes a
:class:`~reconx.scope.guard.ScopeGuard` as a required argument and scope-checks
every target it is asked to pass to a tool, whether via argv or stdin.

A tool that is not installed is not an error. Each wrapper reports availability,
and the stage falls back to a pure-Python path, so ReconX produces useful
results on a fresh install and gets faster as tools are added.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from reconx.scope.guard import OutOfScopeError, ScopeGuard

__all__ = [
    "ToolSpec",
    "ToolStatus",
    "ToolResult",
    "ToolRunner",
    "ToolNotAvailable",
    "find_binary",
    "find_binaries",
    "extra_search_paths",
]


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_VERSION_LINE_RE = re.compile(r"v?\d+\.\d+(\.\d+)?")


def _clean_version(raw: str) -> str:
    """Pull a readable version out of tool output.

    Tools emit ANSI colour and multi-line ASCII banners, so the first
    non-empty line is usually banner art. Prefer a line that actually looks
    like it carries a version number.
    """
    plain = _ANSI_RE.sub("", raw)
    lines = []
    for line in plain.splitlines():
        # Banners are drawn with block-drawing characters, and the version is
        # often printed inside one. Replace anything outside printable ASCII so
        # the decoration falls away and the text survives.
        cleaned = re.sub(r"[^\x20-\x7e]", " ", line)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        if cleaned:
            lines.append(cleaned)

    for line in lines:
        # Skip pure decoration: a line with almost no alphanumerics.
        if sum(character.isalnum() for character in line) < 3:
            continue
        if _VERSION_LINE_RE.search(line):
            return line[:120]
    for line in lines:
        if sum(character.isalnum() for character in line) >= 3:
            return line[:120]
    return ""


class ToolNotAvailable(RuntimeError):
    """The requested external tool is not installed."""


def extra_search_paths() -> list[Path]:
    """Places Go and package managers put binaries that may not be on PATH.

    ``go install`` writes to ``$GOBIN`` or ``$GOPATH/bin``, and a fresh shell
    often does not have those on PATH yet. Looking there directly means the
    tools work immediately after bootstrap instead of after a shell restart.
    """
    candidates: list[Path] = []
    gobin = os.environ.get("GOBIN")
    if gobin:
        candidates.append(Path(gobin))
    gopath = os.environ.get("GOPATH")
    if gopath:
        candidates.extend(Path(part) / "bin" for part in gopath.split(os.pathsep) if part)
    candidates.extend(
        [
            Path.home() / "go" / "bin",
            Path.home() / ".local" / "bin",
            Path("/usr/local/bin"),
            Path("/opt/homebrew/bin"),
        ]
    )
    seen: set[Path] = set()
    out: list[Path] = []
    for path in candidates:
        try:
            resolved = path.expanduser()
        except RuntimeError:  # pragma: no cover - no home directory
            continue
        if resolved not in seen:
            seen.add(resolved)
            out.append(resolved)
    return out


def find_binaries(name: str) -> list[str]:
    """Every executable named ``name``, in priority order.

    More than one can exist and only one may be the tool we want: the Python
    ``httpx`` package installs a CLI that collides with ProjectDiscovery's
    ``httpx`` prober. Returning all candidates lets
    :meth:`ToolRunner.status` identity-check each until it finds the right one,
    instead of giving up on the first wrong match.
    """
    candidates: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        try:
            resolved = str(Path(path).resolve())
        except OSError:  # pragma: no cover - unreadable path
            resolved = path
        if resolved not in seen:
            seen.add(resolved)
            candidates.append(path)

    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            add(str(candidate))

    for directory in extra_search_paths():
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            add(str(candidate))

    return candidates


def find_binary(name: str) -> str | None:
    """The first executable named ``name``, or None."""
    found = shutil.which(name)
    if found:
        return found
    candidates = find_binaries(name)
    return candidates[0] if candidates else None


@dataclass(frozen=True)
class ToolSpec:
    """Metadata for one external tool."""

    name: str
    binary: str
    purpose: str
    install: str
    version_args: tuple[str, ...] = ("-version",)
    # What ReconX does when this tool is missing. Every stage has one.
    fallback: str = "a slower pure-Python path is used"
    needs_root: bool = False
    notes: str | None = None
    # A regex the version output must match to confirm this really is the
    # expected tool. Binary names collide across ecosystems, and running the
    # wrong program produces failures that look like bugs in ReconX.
    identity_pattern: str | None = None
    # A human-readable hint shown when a same-named but different tool is found.
    collision_hint: str | None = None
    # How this tool is told to send an identifying request header, if it speaks
    # HTTP to the target at all. Two forms are in use across the catalogue:
    # ("-H", "{header}: {value}") passes one argument pair, and
    # ("--user-agent", "{value}") passes the value alone.
    #
    # Left None on purpose for subfinder, dnsx, gau, amass and naabu. The first
    # four query third-party sources rather than the target, so announcing a
    # research identity to them tells the wrong party; naabu speaks TCP and has
    # no headers to set. Marking a tool here is a statement that its traffic
    # reaches the target and should be attributable.
    identity_header_args: tuple[str, str] | None = None


@dataclass
class ToolStatus:
    """Whether a tool is usable right now."""

    spec: ToolSpec
    available: bool
    path: str | None = None
    version: str | None = None
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "name": self.spec.name,
            "available": self.available,
            "path": self.path,
            "version": self.version,
            "purpose": self.spec.purpose,
            "install": self.spec.install,
            "fallback": self.spec.fallback,
            "error": self.error,
        }


@dataclass
class ToolResult:
    """The outcome of one tool invocation."""

    tool: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False
    command: list[str] = field(default_factory=list)
    targets_skipped: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def lines(self) -> list[str]:
        return [line.strip() for line in self.stdout.splitlines() if line.strip()]

    def json_lines(self) -> list[dict]:
        """Parse JSON-lines output, skipping anything unparseable.

        Tools occasionally interleave a banner or a warning with their JSON
        output; one bad line should not lose the whole result set.
        """
        out: list[dict] = []
        for line in self.lines:
            if not line.startswith("{"):
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                out.append(parsed)
        return out


class ToolRunner:
    """Runs one external tool, enforcing scope on every target it is given."""

    def __init__(
        self,
        spec: ToolSpec,
        guard: ScopeGuard,
        *,
        default_timeout: float = 600.0,
        env: dict[str, str] | None = None,
        user_agent: str = "",
        identity_header: str = "User-Agent",
    ) -> None:
        if not isinstance(guard, ScopeGuard):
            raise TypeError(
                "ToolRunner requires a ScopeGuard: an external tool must not be "
                "handed a target that has not been scope-checked."
            )
        self._spec = spec
        self._guard = guard
        self._default_timeout = default_timeout
        self._env = env
        self._user_agent = user_agent.strip()
        self._identity_header = identity_header.strip() or "User-Agent"
        # Set once a candidate has passed the identity check.
        self._resolved_path: str | None = None
        self._resolution_attempted = False

    # -- availability -----------------------------------------------------

    @property
    def spec(self) -> ToolSpec:
        return self._spec

    @property
    def path(self) -> str | None:
        """The identity-verified path, once resolution has run.

        Before that it is only a best guess, because more than one binary can
        carry the name. Callers that are about to *use* the tool must go through
        :meth:`ensure_available`, which verifies identity.
        """
        return self._resolved_path or find_binary(self._spec.binary)

    @property
    def available(self) -> bool:
        """A fast pre-check: does any binary with this name exist?

        Not authoritative. Python's ``httpx`` package installs a CLI that
        collides with ProjectDiscovery's prober, so a name match is not a tool
        match. Use :meth:`ensure_available` before running anything.
        """
        return find_binary(self._spec.binary) is not None

    async def ensure_available(self) -> bool:
        """Resolve and verify the tool, once per runner.

        Identity verification means executing the binary, so this is async and
        the result is cached. This is the check stages should use: without it a
        stage can pick a same-named program from another ecosystem and fail in a
        way that looks like a bug in ReconX.
        """
        if self._resolved_path is not None:
            return True
        if self._resolution_attempted:
            return False
        self._resolution_attempted = True
        status = await self.status()
        return status.available

    async def status(self) -> ToolStatus:
        """Locate the tool, read its version, and confirm it is the right tool.

        Every candidate binary with the expected name is tried until one
        satisfies the spec's ``identity_pattern``. If binaries exist but none
        match, that is reported as a name collision rather than as "installed",
        because a wrong-tool match fails later in ways that look like bugs.
        """
        candidates = find_binaries(self._spec.binary)
        if not candidates:
            return ToolStatus(
                spec=self._spec,
                available=False,
                error=f"{self._spec.binary} not found on PATH",
            )

        pattern = (
            re.compile(self._spec.identity_pattern, re.IGNORECASE)
            if self._spec.identity_pattern
            else None
        )
        rejected: list[str] = []

        for path in candidates:
            try:
                result = await self._exec(
                    [path, *self._spec.version_args], stdin_data=None, timeout=15.0
                )
            except Exception as exc:  # pragma: no cover - defensive
                rejected.append(f"{path} ({type(exc).__name__})")
                continue

            raw = f"{result.stdout}\n{result.stderr}".strip()
            if pattern is not None and not pattern.search(raw):
                rejected.append(path)
                continue

            self._resolved_path = path
            return ToolStatus(
                spec=self._spec, available=True, path=path, version=_clean_version(raw)
            )

        hint = self._spec.collision_hint or (
            f"install it with: {self._spec.install}"
        )
        return ToolStatus(
            spec=self._spec,
            available=False,
            error=(
                f"found {', '.join(rejected)} but none of them is {self._spec.name}. "
                f"{hint}"
            ),
        )

    # -- scope enforcement ------------------------------------------------

    def _check_targets(self, targets: Iterable[str]) -> tuple[list[str], list[str]]:
        """Split targets into in-scope and refused."""
        kept: list[str] = []
        skipped: list[str] = []
        for target in targets:
            text = str(target).strip()
            if not text:
                continue
            if self._guard.decide(text).allowed:
                kept.append(text)
            else:
                skipped.append(text)
        return kept, skipped

    # -- execution --------------------------------------------------------

    async def run(
        self,
        args: Sequence[str],
        *,
        targets: Iterable[str] | None = None,
        stdin_targets: Iterable[str] | None = None,
        stdin_data: str | None = None,
        timeout: float | None = None,
        require_targets: bool = True,
    ) -> ToolResult:
        """Invoke the tool.

        ``targets`` and ``stdin_targets`` are scope-checked before the process
        starts. Out-of-scope entries are dropped and reported in
        :attr:`ToolResult.targets_skipped` rather than silently passed through.

        Raises :class:`OutOfScopeError` if every supplied target was refused,
        because running the tool with no targets usually means a scope bug.
        """
        if not await self.ensure_available():
            raise ToolNotAvailable(
                f"{self._spec.name} is not usable. Install it with:\n  {self._spec.install}\n"
                f"Without it, {self._spec.fallback}."
            )
        path = self._resolved_path
        assert path is not None  # ensure_available() guarantees this

        argv: list[str] = [path, *self.identity_args(), *args]
        skipped: list[str] = []

        if targets is not None:
            kept, refused = self._check_targets(targets)
            skipped.extend(refused)
            if not kept and require_targets:
                raise OutOfScopeError(
                    self._guard.decide(next(iter(refused), "")),
                )
            argv.extend(kept)

        payload = stdin_data
        if stdin_targets is not None:
            kept, refused = self._check_targets(stdin_targets)
            skipped.extend(refused)
            if not kept and require_targets:
                raise OutOfScopeError(self._guard.decide(next(iter(refused), "")))
            payload = "\n".join(kept) + "\n"

        result = await self._exec(argv, stdin_data=payload, timeout=timeout)
        result.targets_skipped = skipped
        return result

    def identity_args(self) -> list[str]:
        """Arguments that make this tool's traffic attributable to the operator.

        A program that permits automated testing almost always also requires the
        traffic to be identifiable, so it can tell research from an attack. Before
        this existed, ``RECONX_USER_AGENT`` reached only ReconX's own HTTP client,
        while subfinder, httpx, katana, nuclei and ffuf -- which generate most of
        the volume on a wildcard program -- went out with their own defaults. The
        audit log said one thing and the target saw another.

        Returns an empty list when no user agent is configured, or when the tool
        does not speak HTTP to the target.
        """
        if not self._user_agent or self._spec.identity_header_args is None:
            return []
        flag, template = self._spec.identity_header_args
        return [
            flag,
            template.format(header=self._identity_header, value=self._user_agent),
        ]

    async def _exec(
        self, argv: Sequence[str], *, stdin_data: str | None, timeout: float | None
    ) -> ToolResult:
        started = time.monotonic()
        limit = timeout if timeout is not None else self._default_timeout

        environment = {**os.environ, **(self._env or {})}
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(stdin_data.encode() if stdin_data else None),
                timeout=limit,
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            return ToolResult(
                tool=self._spec.name,
                returncode=-1,
                duration_s=time.monotonic() - started,
                timed_out=True,
                command=list(argv),
                stderr=f"timed out after {limit:.0f}s",
            )

        return ToolResult(
            tool=self._spec.name,
            returncode=process.returncode if process.returncode is not None else -1,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            duration_s=time.monotonic() - started,
            command=list(argv),
        )
