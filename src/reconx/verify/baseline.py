"""Learning how a host behaves before testing it.

Most content-discovery noise comes from one mistake: assuming a 200 means the
path exists. Plenty of applications answer every unknown path with a styled
"page not found" page and a 200 status, so a wordlist of ten thousand entries
produces ten thousand hits.

The fix is to ask the host first. Before any discovery on a directory, ReconX
requests a few paths that cannot exist and records what comes back. Anything
later found under that directory is compared against it, and a response that
matches the not-found page is not a discovery.

Baselines are learned **per directory**, because an application's 404 handling
routinely differs between ``/`` and ``/api/`` and ``/admin/``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from reconx.db.models import BaselineKind
from reconx.db.store import save_baseline
from reconx.net.fingerprint import ResponseFingerprint
from reconx.verify.waf import WafState, classify_response

__all__ = ["DirectoryBaseline", "BaselineCollector"]

_PROBE_PREFIX = "reconx-probe"


def _random_segment() -> str:
    return f"{_PROBE_PREFIX}-{secrets.token_hex(8)}"


def _normalize_directory(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    return path or "/"


@dataclass
class DirectoryBaseline:
    """What a host returns for paths that do not exist, in one directory."""

    host: str
    directory: str
    samples: list[ResponseFingerprint] = field(default_factory=list)
    statuses: set[int] = field(default_factory=set)
    obstructed: bool = False
    note: str | None = None

    @property
    def learned(self) -> bool:
        return bool(self.samples)

    @property
    def soft_404(self) -> bool:
        """True when missing paths come back as success rather than 404."""
        return bool(self.statuses) and all(
            200 <= status < 300 for status in self.statuses
        )

    @property
    def consistent(self) -> bool:
        """True when the not-found page is stable enough to compare against.

        If two probes for different non-existent paths return pages that do not
        resemble each other, there is no learnable not-found page and filtering
        against it would be guesswork.
        """
        if len(self.samples) < 2:
            return len(self.samples) == 1
        first = self.samples[0]
        return all(first.looks_same_as(other) for other in self.samples[1:])

    def matches(self, fingerprint: ResponseFingerprint, *, threshold: float = 0.92) -> bool:
        """True when a response is this directory's not-found page."""
        if not self.learned or not self.consistent:
            return False
        return any(
            sample.looks_same_as(fingerprint, threshold=threshold)
            for sample in self.samples
        )

    def explain(self) -> str:
        if not self.learned:
            return f"no not-found baseline was learned for {self.directory}"
        statuses = ", ".join(str(status) for status in sorted(self.statuses))
        kind = "soft-404 (success status)" if self.soft_404 else "a real error status"
        stability = "stable" if self.consistent else "unstable"
        return (
            f"{self.host}{self.directory} answers missing paths with {kind} "
            f"[{statuses}], {stability} across {len(self.samples)} probe(s)"
        )


class BaselineCollector:
    """Learns and caches per-host, per-directory baselines."""

    def __init__(
        self,
        http,
        *,
        probes: int = 3,
        session=None,
        program_id: int | None = None,
        persist: bool = True,
    ) -> None:
        self._http = http
        self._probes = max(1, probes)
        self._session = session
        self._program_id = program_id
        self._persist = persist and session is not None and program_id is not None
        self._directories: dict[tuple[str, str], DirectoryBaseline] = {}
        self._normal: dict[str, ResponseFingerprint | None] = {}

    # -- not-found baselines ----------------------------------------------

    async def for_directory(
        self, base_url: str, directory: str = "/", *, refresh: bool = False
    ) -> DirectoryBaseline:
        """Learn what ``directory`` returns for paths that cannot exist.

        ``base_url`` is a scheme-and-host prefix such as ``https://example.com``.
        """
        host = _host_of(base_url)
        normalized = _normalize_directory(directory)
        key = (base_url.rstrip("/"), normalized)

        if not refresh and key in self._directories:
            return self._directories[key]

        baseline = DirectoryBaseline(host=host, directory=normalized)

        for _ in range(self._probes):
            probe_url = f"{base_url.rstrip('/')}{normalized}{_random_segment()}"
            try:
                response = await self._http.get(probe_url)
            except Exception as exc:
                baseline.note = f"probe failed: {type(exc).__name__}"
                continue

            verdict = classify_response(
                status=response.status, headers=response.headers, body=response.body
            )
            if verdict.state is not WafState.CLEAN:
                baseline.obstructed = True
                baseline.note = (
                    f"the host was {verdict.state.value} while learning its "
                    f"not-found behaviour, so discovery here is unreliable"
                )
                continue

            baseline.samples.append(response.fingerprint)
            baseline.statuses.add(response.status)

        if self._persist and baseline.learned:
            for sample in baseline.samples:
                await save_baseline(
                    self._session,
                    self._program_id,
                    host,
                    BaselineKind.NOT_FOUND,
                    fingerprint=sample,
                    sample_url=f"{base_url.rstrip('/')}{normalized}",
                    path_scope=normalized,
                )

        self._directories[key] = baseline
        return baseline

    async def is_not_found(
        self, base_url: str, url_path: str, fingerprint: ResponseFingerprint
    ) -> tuple[bool, str | None]:
        """Is this response the not-found page for its directory?

        Returns ``(is_not_found, reason)``. The reason is kept so a discarded
        discovery can say why it was discarded.
        """
        directory = _normalize_directory(url_path)
        baseline = await self.for_directory(base_url, directory)

        if not baseline.learned:
            return False, None
        if not baseline.consistent:
            return False, (
                f"{baseline.host}{baseline.directory} returns inconsistent pages for "
                "missing paths, so no not-found baseline could be used"
            )
        if baseline.matches(fingerprint):
            kind = "soft-404" if baseline.soft_404 else "not-found"
            return True, (
                f"response is indistinguishable from the {kind} page that "
                f"{baseline.host}{baseline.directory} returns for paths that do not exist"
            )
        return False, None

    # -- normal baselines ---------------------------------------------------

    async def normal(self, base_url: str) -> ResponseFingerprint | None:
        """Fingerprint the host's root page, as an example of a real page."""
        key = base_url.rstrip("/")
        if key in self._normal:
            return self._normal[key]
        try:
            response = await self._http.get(f"{key}/")
        except Exception:
            self._normal[key] = None
            return None

        fingerprint = response.fingerprint
        if self._persist:
            await save_baseline(
                self._session,
                self._program_id,
                _host_of(base_url),
                BaselineKind.NORMAL,
                fingerprint=fingerprint,
                sample_url=f"{key}/",
            )
        self._normal[key] = fingerprint
        return fingerprint

    # -- reporting ----------------------------------------------------------

    def learned_directories(self) -> list[DirectoryBaseline]:
        return list(self._directories.values())

    def summary(self) -> dict:
        soft = [b for b in self._directories.values() if b.learned and b.soft_404]
        unstable = [b for b in self._directories.values() if b.learned and not b.consistent]
        obstructed = [b for b in self._directories.values() if b.obstructed]
        return {
            "directories_learned": len(self._directories),
            "soft_404_directories": [f"{b.host}{b.directory}" for b in soft],
            "unstable_directories": [f"{b.host}{b.directory}" for b in unstable],
            "obstructed_directories": [f"{b.host}{b.directory}" for b in obstructed],
        }


def _host_of(base_url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(base_url if "://" in base_url else f"http://{base_url}").hostname or ""
