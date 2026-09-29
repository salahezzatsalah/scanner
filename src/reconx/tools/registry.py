"""The catalogue of external tools, and what ReconX does without each one.

Every entry names a fallback. That is a deliberate constraint: no stage may
depend on a tool being installed, so a fresh clone produces useful results
immediately and improves as tools are added. ``reconx doctor`` prints this
table with the exact install command for anything missing.
"""

from __future__ import annotations

import asyncio

from reconx.scope.guard import ScopeGuard
from reconx.tools.base import ToolRunner, ToolSpec, ToolStatus

__all__ = [
    "TOOL_SPECS",
    "get_spec",
    "get_runner",
    "detect_all",
    "missing_tools",
    "install_script_lines",
]

_GO = "go install -v"

# ProjectDiscovery tools all print their banner or an "[INF] Current <tool>
# version" line. Requiring one of these stops a same-named binary from another
# ecosystem being mistaken for the real thing.
_PD_IDENTITY = r"projectdiscovery|current\s+\S+\s+version|v\d+\.\d+\.\d+"

# How a tool is asked to send an identifying header. Most of the catalogue takes
# a header line; sqlmap takes the value alone.
_HEADER_FLAG: tuple[str, str] = ("-H", "{header}: {value}")
_USER_AGENT_FLAG: tuple[str, str] = ("--user-agent", "{value}")

TOOL_SPECS: dict[str, ToolSpec] = {
    # --- subdomain enumeration ------------------------------------------
    "subfinder": ToolSpec(
        name="subfinder",
        binary="subfinder",
        purpose="passive subdomain enumeration across many sources",
        install=f"{_GO} github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        fallback="certificate transparency (crt.sh) is queried directly over HTTP",
        identity_pattern=_PD_IDENTITY,
    ),
    "amass": ToolSpec(
        name="amass",
        binary="amass",
        purpose="deep passive and active subdomain enumeration",
        version_args=("-version",),
        install=f"{_GO} github.com/owasp-amass/amass/v4/...@master",
        fallback="subfinder and certificate transparency cover most of this ground",
        notes="Slow. Best run on a longer cadence than the rest of the pipeline.",
        identity_pattern=r"amass",
    ),
    "alterx": ToolSpec(
        name="alterx",
        binary="alterx",
        purpose="generates subdomain permutations from known names",
        install=f"{_GO} github.com/projectdiscovery/alterx/cmd/alterx@latest",
        fallback="a built-in permutation generator with a smaller pattern set",
        identity_pattern=_PD_IDENTITY,
    ),
    # --- resolution and probing -----------------------------------------
    "dnsx": ToolSpec(
        name="dnsx",
        binary="dnsx",
        purpose="fast bulk DNS resolution and brute forcing",
        install=f"{_GO} github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        fallback="dnspython resolves in bounded-concurrency batches, which is slower",
        identity_pattern=_PD_IDENTITY,
    ),
    "httpx": ToolSpec(
        name="httpx",
        binary="httpx",
        purpose="HTTP probing: status, title, technology, TLS detail",
        install=f"{_GO} github.com/projectdiscovery/httpx/cmd/httpx@latest",
        fallback="the built-in scoped HTTP client probes hosts directly",
        notes="Distinct from the Python library of the same name.",
        identity_pattern=_PD_IDENTITY,
        collision_hint=(
            "The Python 'httpx' package installs a CLI of the same name. Install "
            "ProjectDiscovery httpx and make sure its directory (usually ~/go/bin) "
            "comes first on PATH, or invoke it by full path."
        ),
        identity_header_args=_HEADER_FLAG,
    ),
    # --- ports ------------------------------------------------------------
    "naabu": ToolSpec(
        name="naabu",
        binary="naabu",
        purpose="fast port discovery",
        install=f"{_GO} github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        fallback="an asyncio TCP connect scan over a top-ports list",
        needs_root=True,
        notes="SYN scan needs root and libpcap; connect scan works unprivileged.",
        identity_pattern=_PD_IDENTITY,
    ),
    "nmap": ToolSpec(
        name="nmap",
        binary="nmap",
        purpose="service and version detection on discovered ports",
        version_args=("--version",),
        install="apt install nmap  # or: brew install nmap",
        fallback="service names are inferred from the port number and banner",
        identity_pattern=r"nmap",
    ),
    # --- content discovery -----------------------------------------------
    "katana": ToolSpec(
        name="katana",
        binary="katana",
        purpose="crawling, including JavaScript-aware crawling",
        install=f"{_GO} github.com/projectdiscovery/katana/cmd/katana@latest",
        fallback="a built-in crawler parses HTML links, forms and script sources",
        identity_pattern=_PD_IDENTITY,
        identity_header_args=_HEADER_FLAG,
    ),
    "gau": ToolSpec(
        name="gau",
        binary="gau",
        purpose="historical URLs from Wayback, Common Crawl and URLScan",
        version_args=("--version",),
        install=f"{_GO} github.com/lc/gau/v2/cmd/gau@latest",
        fallback="the Wayback CDX API is queried directly over HTTP",
        identity_pattern=r"gau|\d+\.\d+",
    ),
    "ffuf": ToolSpec(
        name="ffuf",
        binary="ffuf",
        purpose="content and directory brute forcing",
        version_args=("-V",),
        install=f"{_GO} github.com/ffuf/ffuf/v2@latest",
        fallback="a built-in rate-limited path prober with soft-404 filtering",
        identity_pattern=r"ffuf",
        identity_header_args=_HEADER_FLAG,
    ),
    # --- vulnerability detection ------------------------------------------
    "nuclei": ToolSpec(
        name="nuclei",
        binary="nuclei",
        purpose="template-driven vulnerability and misconfiguration detection",
        install=f"{_GO} github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        fallback="only ReconX's own checks run, which cover far less ground",
        notes="Run 'nuclei -update-templates' after install.",
        identity_pattern=_PD_IDENTITY,
        identity_header_args=_HEADER_FLAG,
    ),
    "dalfox": ToolSpec(
        name="dalfox",
        binary="dalfox",
        purpose="XSS parameter analysis and payload selection",
        version_args=("version",),
        install=f"{_GO} github.com/hahwul/dalfox/v2@latest",
        fallback="ReconX's own reflection-context analyser is used",
        identity_pattern=r"dalfox",
        identity_header_args=_HEADER_FLAG,
    ),
    "sqlmap": ToolSpec(
        name="sqlmap",
        binary="sqlmap",
        purpose="SQL injection confirmation (detection only, non-destructive)",
        version_args=("--version",),
        install="pipx install sqlmap  # or: apt install sqlmap",
        fallback="ReconX's own two-oracle differential SQLi verifier is used",
        notes=(
            "ReconX runs sqlmap in detection mode only, with no flags that "
            "modify data or request an OS shell."
        ),
        identity_pattern=r"sqlmap|\d+\.\d+",
        identity_header_args=_USER_AGENT_FLAG,
    ),
}


def get_spec(name: str) -> ToolSpec:
    try:
        return TOOL_SPECS[name]
    except KeyError:
        raise KeyError(
            f"unknown tool {name!r}; known tools: {', '.join(sorted(TOOL_SPECS))}"
        ) from None


def get_runner(name: str, guard: ScopeGuard, **kwargs) -> ToolRunner:
    """Build a scope-enforcing runner for a catalogued tool."""
    return ToolRunner(get_spec(name), guard, **kwargs)



async def detect_all(guard: ScopeGuard) -> dict[str, ToolStatus]:
    """Probe every catalogued tool concurrently."""
    names = list(TOOL_SPECS)
    runners = [get_runner(name, guard) for name in names]
    statuses = await asyncio.gather(*(runner.status() for runner in runners))
    return dict(zip(names, statuses, strict=True))


def missing_tools(statuses: dict[str, ToolStatus]) -> list[ToolStatus]:
    return [status for status in statuses.values() if not status.available]


def install_script_lines(statuses: dict[str, ToolStatus] | None = None) -> list[str]:
    """Install commands for the missing tools, or for all of them."""
    if statuses is None:
        return [spec.install for spec in TOOL_SPECS.values()]
    return [status.spec.install for status in missing_tools(statuses)]
