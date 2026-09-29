"""Endpoint and content discovery.

Finds URLs worth testing, from four directions:

* **Declared** — robots.txt and sitemap.xml, which often name paths the site
  would rather you did not visit.
* **Crawled** — links, forms and script sources, via katana when installed and a
  built-in crawler otherwise.
* **Archived** — historical URLs from the Wayback CDX index, which surfaces
  endpoints that are no longer linked but frequently still work.
* **Guessed** — a path wordlist, rate limited.

The discovery itself is the easy part. What makes the results usable is that
every candidate is compared against the directory's not-found baseline before it
is recorded. On a host that answers unknown paths with HTTP 200, that is the
difference between finding four real endpoints and reporting four hundred.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from reconx.db.models import Severity
from reconx.db.store import upsert_endpoint, upsert_finding
from reconx.stages.base import Stage, StageContext, StageResult
from reconx.stages.wordlists import COMMON_CONTENT_PATHS, resolve_wordlist
from reconx.tools.base import ToolNotAvailable
from reconx.verify.baseline import BaselineCollector
from reconx.verify.waf import WafState, classify_response

__all__ = ["ContentStage"]

_WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"

# Paths that look like an endpoint when extracted from JavaScript.
_JS_PATH_RE = re.compile(r"""['"](/(?:[A-Za-z0-9_\-./]{2,120}))['"]""")
_JS_FETCH_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|patch|delete))\s*\(\s*['"]([^'"]{2,200})['"]"""
)
# Real code rarely writes a full path as one literal. It assigns a base to a
# constant and concatenates, or interpolates it into a template literal. Without
# resolving these, the most interesting endpoints in a bundle are missed.
_JS_CONST_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*['"]([^'"\n]{1,200})['"]"""
)
_JS_CONCAT_RE = re.compile(r"""([A-Za-z_$][\w$]*)\s*\+\s*['"]([^'"\n]{1,200})['"]""")
_JS_TEMPLATE_RE = re.compile(r"""`\$\{\s*([A-Za-z_$][\w$]*)\s*\}([^`$]{0,200})`""")

# Credential shapes worth reporting when they appear in client-side code.
# Each is a concrete format rather than a guess, to keep this useful.
_SECRET_PATTERNS: tuple[tuple[str, str, Severity], ...] = (
    ("AWS access key id", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", Severity.HIGH),
    ("Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b", Severity.MEDIUM),
    ("Slack token", r"\bxox[abprs]-[0-9A-Za-z\-]{10,72}\b", Severity.HIGH),
    ("GitHub token", r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b", Severity.HIGH),
    ("Stripe secret key", r"\bsk_live_[0-9A-Za-z]{24,}\b", Severity.CRITICAL),
    ("private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", Severity.HIGH),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
     Severity.LOW),
)

_INTERESTING_PATH_HINTS: tuple[tuple[str, float], ...] = (
    ("admin", 3.0), ("console", 2.5), ("dashboard", 2.0), ("login", 1.5),
    ("auth", 1.5), ("token", 2.0), ("api", 1.0), ("graphql", 2.0),
    ("debug", 2.5), ("actuator", 3.0), ("swagger", 2.0), ("openapi", 2.0),
    ("backup", 3.0), ("dump", 3.0), (".git", 4.0), (".env", 4.0),
    ("config", 2.0), ("upload", 2.0), ("internal", 2.5), ("private", 2.5),
    ("phpinfo", 3.0), ("wp-admin", 1.5), ("metrics", 1.5),
)


def _normalize_url(url: str) -> str:
    """Drop fragments and normalize so the same URL is not stored twice."""
    parts = urlsplit(url)
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def _interest_score(url: str) -> float:
    lowered = url.lower()
    return sum(weight for token, weight in _INTERESTING_PATH_HINTS if token in lowered)


class ContentStage(Stage):
    name = "content"
    description = "Crawl, archive mining, JavaScript analysis and path discovery"
    requires = ("resolve_probe",)
    active = True

    def __init__(
        self,
        *,
        wordlist_path: str | None = None,
        brute_force: bool = True,
        crawl: bool = True,
        archives: bool = True,
        max_hosts: int = 50,
        max_urls_per_host: int = 2000,
        crawl_depth: int = 2,
        max_scripts: int = 25,
    ) -> None:
        self._wordlist_path = wordlist_path
        self._brute_force = brute_force
        self._crawl = crawl
        self._archives = archives
        self._max_hosts = max_hosts
        self._max_urls_per_host = max_urls_per_host
        self._crawl_depth = crawl_depth
        self._max_scripts = max_scripts

    # -- entry point -------------------------------------------------------

    async def run(self, ctx: StageContext) -> StageResult:
        result = StageResult(stage=self.name)
        hosts = await self._live_hosts(ctx)
        result.items_in = len(hosts)

        if not hosts:
            result.note("no live hosts to explore; run resolve_probe first")
            return result

        if len(hosts) > self._max_hosts:
            result.note(
                f"exploring the first {self._max_hosts} of {len(hosts)} live hosts; "
                "raise --max-content-hosts to cover more"
            )
            hosts = hosts[: self._max_hosts]

        collector = BaselineCollector(
            ctx.http,
            probes=ctx.settings.soft404_probe_count,
            session=ctx.session,
            program_id=ctx.program_id,
        )
        discovered: dict[str, set[str]] = defaultdict(set)

        for base_url in hosts:
            await self._explore_host(ctx, base_url, collector, discovered, result)

        summary = collector.summary()
        if summary["soft_404_directories"]:
            result.note(
                f"{len(summary['soft_404_directories'])} directory/directories serve a "
                "soft-404: missing paths come back with a success status. Discovery "
                "there was filtered against the learned not-found page"
            )
        if summary["obstructed_directories"]:
            result.note(
                f"{len(summary['obstructed_directories'])} directory/directories were "
                "blocked or throttled while baselining, so results there are unreliable"
            )

        result.items_out = sum(len(urls) for urls in discovered.values())
        ctx.shared["endpoints"] = {
            host: sorted(urls) for host, urls in discovered.items()
        }
        result.checkpoint = {"hosts_explored": hosts}
        return result

    async def _live_hosts(self, ctx: StageContext) -> list[str]:
        """Base URLs for hosts known to answer over HTTP."""
        from sqlmodel import select

        from reconx.db.models import Asset

        rows = await ctx.session.execute(
            select(Asset).where(
                Asset.program_id == ctx.program_id,
                Asset.is_live == True,  # noqa: E712
            )
        )
        out: list[str] = []
        for asset in rows.scalars().all():
            if not ctx.guard.decide_host(asset.host).allowed:
                continue
            scheme = asset.scheme or "https"
            port = asset.port
            if port and port not in (80, 443):
                out.append(f"{scheme}://{asset.host}:{port}")
            else:
                out.append(f"{scheme}://{asset.host}")
        return out

    # -- per host ----------------------------------------------------------

    async def _explore_host(
        self,
        ctx: StageContext,
        base_url: str,
        collector: BaselineCollector,
        discovered: dict[str, set[str]],
        result: StageResult,
    ) -> None:
        host = urlsplit(base_url).hostname or base_url
        candidates: dict[str, str] = {}  # url -> source

        def propose(url: str, source: str) -> None:
            normalized = _normalize_url(urljoin(base_url + "/", url))
            if not ctx.guard.decide_url(normalized).allowed:
                result.filtered("out_of_scope")
                return
            if urlsplit(normalized).hostname != host:
                return
            candidates.setdefault(normalized, source)

        # Learn what a missing path looks like before proposing anything.
        await collector.for_directory(base_url, "/")

        await self._declared_paths(ctx, base_url, propose, result)
        if self._crawl:
            await self._crawl_host(ctx, base_url, propose, result)
            # Script files are referenced, not linked, so the crawl proposes them
            # without ever opening them. Mine them explicitly: client-side code
            # names endpoints that appear nowhere in the HTML.
            await self._mine_scripts(ctx, base_url, candidates, propose, result)
        if self._archives:
            await self._archived_urls(ctx, host, propose, result)
        if self._brute_force:
            self._guessed_paths(propose, result)

        if len(candidates) > self._max_urls_per_host:
            result.note(
                f"{host}: capped at {self._max_urls_per_host} candidate URLs "
                f"(had {len(candidates)})"
            )
            candidates = dict(list(candidates.items())[: self._max_urls_per_host])

        await self._confirm(ctx, base_url, candidates, collector, discovered, result)

    # -- sources -----------------------------------------------------------

    async def _declared_paths(self, ctx, base_url, propose, result: StageResult) -> None:
        """robots.txt and sitemap.xml: paths the site names itself."""
        try:
            robots = await ctx.http.get(f"{base_url}/robots.txt")
        except Exception:
            robots = None
        if robots is not None and robots.status == 200 and "text" in (
            robots.fingerprint.content_type or "text"
        ):
            for line in robots.text.splitlines():
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                if key.strip().lower() in {"disallow", "allow", "sitemap"}:
                    target = value.strip()
                    if target and target != "/":
                        propose(target, "robots.txt")

        try:
            sitemap = await ctx.http.get(f"{base_url}/sitemap.xml")
        except Exception:
            return
        if sitemap.status == 200 and b"<urlset" in sitemap.body[:4000]:
            for match in re.finditer(rb"<loc>\s*([^<\s]+)\s*</loc>", sitemap.body):
                propose(match.group(1).decode("utf-8", errors="replace"), "sitemap.xml")

    async def _crawl_host(self, ctx, base_url, propose, result: StageResult) -> None:
        runner = ctx.tool("katana")
        if await runner.ensure_available():
            try:
                outcome = await runner.run(
                    [
                        "-silent", "-jsonl",
                        "-depth", str(self._crawl_depth),
                        "-known-files", "all",
                        # Ask katana for form, input, textarea and select elements
                        # as well as links.
                        "-form-extraction",
                        "-u",
                    ],
                    targets=[base_url],
                    timeout=600.0,
                )
            except ToolNotAvailable:
                outcome = None
            if outcome is not None and outcome.lines:
                result.used_tool("katana")
                self._harvest_katana(ctx, outcome.lines, propose, result)
                return

        result.used_fallback("crawling with the built-in HTML parser instead of katana")
        await self._builtin_crawl(ctx, base_url, propose, result)

    def _harvest_katana(
        self, ctx: StageContext, lines: list[str], propose, result: StageResult
    ) -> None:
        """Take everything katana found, including from the bodies it returns.

        Katana's endpoint list is link-driven, so it misses a form's action and
        never reports the input names, which are exactly the parameters worth
        testing later. Its JSONL carries the full response body, so those are
        parsed out of what it already fetched rather than by crawling again.
        Without this, installing katana made the scan find *less* than the
        built-in crawler, which is backwards.
        """
        pages = 0
        for line in lines:
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            request = row.get("request") or {}
            endpoint = request.get("endpoint") or row.get("endpoint")
            if endpoint:
                propose(str(endpoint), "katana")

            response = row.get("response") or {}
            body = response.get("body")
            content_type = str(
                (response.get("headers") or {}).get("Content-Type", "")
            ).lower()
            if not body or not endpoint:
                continue

            if "html" in content_type or "<html" in body[:2000].lower():
                self._harvest_html(ctx, str(endpoint), body, propose, "katana")
                pages += 1

        if pages:
            result.note(
                f"parsed {pages} page(s) from katana's own output for forms and links"
            )

    def _harvest_html(
        self, ctx: StageContext, page_url: str, body: str | bytes, propose, source: str
    ) -> list[str]:
        """Pull links and form parameters out of one HTML page.

        Shared by the katana path and the built-in crawler so both find the same
        things. Returns the targets worth following, for callers that crawl.
        """
        soup = BeautifulSoup(body, "lxml")
        followable: list[str] = []

        for tag, attribute in (
            ("a", "href"), ("link", "href"), ("script", "src"),
            ("img", "src"), ("form", "action"), ("iframe", "src"),
        ):
            for element in soup.find_all(tag):
                value = element.get(attribute)
                if not value or value.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue
                target = _normalize_url(urljoin(page_url, value))
                propose(target, source)
                if tag in {"a", "form"}:
                    followable.append(target)

        # A form's inputs are the parameters the vulnerability stage will test.
        for form in soup.find_all("form"):
            action = _normalize_url(urljoin(page_url, form.get("action") or page_url))
            names = [
                element.get("name")
                for element in form.find_all(["input", "textarea", "select"])
                if element.get("name")
            ]
            if names:
                existing = ctx.shared.setdefault("form_params", {})
                merged = set(existing.get(action) or []) | set(names)
                existing[action] = sorted(merged)
                propose(action, "form")
                followable.append(action)

        return followable

    async def _builtin_crawl(self, ctx, base_url, propose, result: StageResult) -> None:
        """A breadth-first crawl of links, forms and script sources."""
        seen: set[str] = set()
        frontier: list[tuple[str, int]] = [(f"{base_url}/", 0)]

        while frontier:
            url, depth = frontier.pop(0)
            if url in seen or depth > self._crawl_depth:
                continue
            seen.add(url)

            try:
                response = await ctx.http.get(url)
            except Exception:
                continue

            verdict = classify_response(
                status=response.status, headers=response.headers, body=response.body
            )
            if verdict.state is not WafState.CLEAN:
                result.note(f"crawl of {url} hit a {verdict.state.value} response")
                continue

            content_type = response.fingerprint.content_type
            if "javascript" in content_type or url.endswith(".js"):
                await self._mine_javascript(ctx, url, response, propose, result)
                continue
            if "html" not in content_type:
                continue

            followable = self._harvest_html(ctx, url, response.body, propose, "crawl")
            if depth < self._crawl_depth:
                for target in followable:
                    if target not in seen and len(seen) < 200:
                        frontier.append((target, depth + 1))

    async def _mine_scripts(
        self,
        ctx: StageContext,
        base_url: str,
        candidates: dict[str, str],
        propose,
        result: StageResult,
    ) -> None:
        """Fetch and analyse the JavaScript the crawl found."""
        scripts = [
            url
            for url in list(candidates)
            if urlsplit(url).path.endswith((".js", ".mjs", ".jsx", ".ts"))
        ][: self._max_scripts]
        if not scripts:
            return

        for url in scripts:
            try:
                response = await ctx.http.get(url)
            except Exception:
                continue
            if response.status != 200:
                continue
            await self._mine_javascript(ctx, url, response, propose, result)

        result.note(f"analysed {len(scripts)} script file(s) for endpoints and secrets")

    async def _mine_javascript(
        self, ctx, url: str, response, propose, result: StageResult
    ) -> None:
        """Pull endpoints and credential shapes out of client-side code."""
        text = response.text[:600_000]

        def is_asset(candidate: str) -> bool:
            return bool(
                re.search(r"\.(png|jpe?g|gif|svg|woff2?|ttf|eot|ico|css|map)$", candidate)
            )

        for match in _JS_FETCH_RE.finditer(text):
            propose(match.group(1), "javascript:call")

        for match in _JS_PATH_RE.finditer(text):
            candidate = match.group(1)
            if not is_asset(candidate):
                propose(candidate, "javascript:path")

        # Resolve `const API_BASE = "/api/v1"` then `API_BASE + "/users"` and
        # `${API_BASE}/users`, which is how paths are actually written.
        constants = {
            name: value
            for name, value in _JS_CONST_RE.findall(text)
            if value.startswith("/") or value.startswith("http")
        }
        if constants:
            for pattern in (_JS_CONCAT_RE, _JS_TEMPLATE_RE):
                for match in pattern.finditer(text):
                    name, suffix = match.group(1), match.group(2)
                    base = constants.get(name)
                    if base is None or not suffix:
                        continue
                    joined = base.rstrip("/") + "/" + suffix.lstrip("/")
                    if not is_asset(joined):
                        propose(joined, "javascript:concat")

        for label, pattern, severity in _SECRET_PATTERNS:
            for match in re.finditer(pattern, text):
                snippet = match.group(0)
                redacted = (
                    snippet[:6] + "…" + snippet[-4:] if len(snippet) > 14 else "…"
                )
                _, is_new = await upsert_finding(
                    ctx.session,
                    ctx.program_id,
                    dedup_key=f"secret::{label}::{url}",
                    vuln_class="exposed_secret",
                    title=f"{label} present in client-side JavaScript",
                    severity=severity,
                    description=(
                        f"A string matching the format of a {label} appears in "
                        f"`{url}`, which is served to every visitor. Value redacted: "
                        f"`{redacted}`.\n\n"
                        "Client-side code is public, so anything shaped like a "
                        "credential here should be treated as disclosed until proven "
                        "to be a public identifier."
                    ),
                    detector="reconx:js-secret",
                    signals=["format_match"],
                    affected_hosts=[urlsplit(url).hostname or ""],
                    recommendation=(
                        "Confirm whether the value is a real credential or a public "
                        "client identifier. If real, report it and recommend rotation; "
                        "many key formats are safe to publish by design, so check "
                        "before escalating."
                    ),
                )
                if is_new:
                    result.new_findings.append(f"{label} in {url}")
                break  # one finding per key type per file is enough

    async def _archived_urls(self, ctx, host: str, propose, result: StageResult) -> None:
        """Historical URLs. Often still live, rarely still linked."""
        runner = ctx.tool("gau")
        if await runner.ensure_available():
            try:
                outcome = await runner.run(
                    ["--subs", "--threads", "5"], stdin_targets=[host], timeout=300.0
                )
            except ToolNotAvailable:
                outcome = None
            if outcome is not None and outcome.lines:
                result.used_tool("gau")
                for line in outcome.lines[:5000]:
                    propose(line, "archive:gau")
                return

        response = await ctx.sources.try_get(
            _WAYBACK_CDX,
            params={
                "url": f"{host}/*",
                "output": "text",
                "fl": "original",
                "collapse": "urlkey",
                "limit": "2000",
            },
            source="wayback",
        )
        if response is None:
            return
        result.used_tool("wayback")
        result.used_fallback("archive URLs from the Wayback CDX API instead of gau")
        for line in response.text.splitlines()[:2000]:
            candidate = line.strip()
            if candidate:
                propose(candidate, "archive:wayback")

    def _guessed_paths(self, propose, result: StageResult) -> None:
        paths, note = resolve_wordlist(self._wordlist_path, COMMON_CONTENT_PATHS)
        if note:
            result.note(f"path wordlist: {note}")
        elif self._wordlist_path is None:
            result.note(
                f"using the built-in list of {len(paths)} paths; point "
                "--path-wordlist at SecLists for real coverage"
            )
        for path in paths:
            propose(path if path.startswith("/") else f"/{path}", "wordlist")

    # -- confirmation -------------------------------------------------------

    async def _confirm(
        self,
        ctx: StageContext,
        base_url: str,
        candidates: dict[str, str],
        collector: BaselineCollector,
        discovered: dict[str, set[str]],
        result: StageResult,
    ) -> None:
        """Fetch each candidate and keep only the ones that are really there.

        This is where the not-found baseline earns its keep: on a soft-404 host
        every candidate returns 200, and without the comparison every one of
        them would be reported as a discovery.
        """
        host = urlsplit(base_url).hostname or base_url

        for url, source in candidates.items():
            try:
                response = await ctx.http.get(url)
            except Exception:
                result.filtered("unreachable")
                continue

            verdict = classify_response(
                status=response.status, headers=response.headers, body=response.body
            )
            if verdict.should_back_off:
                result.filtered(f"host_{verdict.state.value}")
                continue

            path = urlsplit(url).path or "/"
            is_missing, reason = await collector.is_not_found(
                base_url, path, response.fingerprint
            )
            if is_missing:
                result.filtered("soft_404")
                continue
            if reason:
                # Only surfaced when a baseline could not be used, which is worth
                # knowing. Matches are counted, not narrated.
                result.note(reason)

            # A 404 or 410 is a real absence.
            if response.status in {404, 410}:
                result.filtered("not_found")
                continue

            parameters = [name for name, _ in parse_qsl(urlsplit(url).query)]
            form_params = (ctx.shared.get("form_params") or {}).get(url) or []

            _, is_new = await upsert_endpoint(
                ctx.session,
                ctx.program_id,
                url,
                method="GET",
                source=source,
                status=response.status,
                content_type=response.fingerprint.content_type or None,
                content_length=response.fingerprint.body_length,
                title=response.fingerprint.title,
                parameters=sorted(set(parameters) | set(form_params)) or None,
                fingerprint_sha256=response.fingerprint.body_sha256,
                fingerprint_simhash=f"{response.fingerprint.simhash_value:016x}",
                is_soft_404=False,
                interesting_score=_interest_score(url),
            )
            discovered[host].add(url)
            if is_new:
                result.new_endpoints.append(url)
