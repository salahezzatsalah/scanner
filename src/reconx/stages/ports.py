"""Port and service discovery.

Web scanning finds what is on 80 and 443. Plenty of interesting things are not:
an admin panel on 8080, a database that should never have been exposed, a Redis
instance with no password, a Jenkins on 8090.

naabu is used when installed. Without it, an asyncio TCP connect scan covers the
same ground more slowly. Connect scanning is used either way rather than SYN
scanning, because SYN needs root and the extra stealth is worth nothing here:
ReconX is not trying to be unnoticed on a target it is authorised to test.

Rate limiting applies. A port scan is the easiest way to look like an attack, so
concurrency is bounded per host and the default port list is small enough to be
polite.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from dataclasses import dataclass

from sqlmodel import select

from reconx.db.models import Asset, FindingTier, Severity
from reconx.db.store import record_observation, upsert_finding
from reconx.stages.base import Stage, StageContext, StageResult
from reconx.tools.base import ToolNotAvailable

__all__ = ["PortStage", "TOP_PORTS", "SERVICE_NAMES", "EXPOSURE_CONCERNS"]

# A deliberately short list: the ports that actually pay off on a web estate,
# plus the ones that are serious findings when exposed.
TOP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
    1433, 1521, 2049, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 4200, 4444, 5000,
    5432, 5601, 5672, 5900, 5984, 6379, 7001, 7077, 8000, 8008, 8009, 8080, 8081,
    8088, 8090, 8161, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 10250,
    11211, 15672, 27017, 27018, 50070,
)

SERVICE_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp-submission", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle-db", 2049: "nfs",
    2181: "zookeeper", 2375: "docker-api", 2376: "docker-api-tls",
    3000: "http-alt", 3128: "squid-proxy", 3306: "mysql", 3389: "rdp",
    4200: "http-alt", 4444: "http-alt", 5000: "http-alt", 5432: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    7001: "weblogic", 7077: "spark", 8000: "http-alt", 8008: "http-alt",
    8009: "ajp13", 8080: "http-alt", 8081: "http-alt", 8088: "http-alt",
    8090: "http-alt", 8161: "activemq", 8443: "https-alt", 8500: "consul",
    8888: "http-alt", 9000: "http-alt", 9042: "cassandra", 9090: "prometheus",
    9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch-transport",
    10250: "kubelet", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb-shard", 50070: "hadoop-namenode",
}

# Services that are a finding purely by being reachable from the internet.
# Severity reflects what an unauthenticated connection typically yields.
EXPOSURE_CONCERNS: dict[int, tuple[Severity, str]] = {
    23: (Severity.HIGH, "Telnet sends credentials in clear text"),
    445: (Severity.HIGH, "SMB exposed to the internet"),
    1433: (Severity.HIGH, "Microsoft SQL Server reachable directly"),
    1521: (Severity.HIGH, "Oracle database reachable directly"),
    2049: (Severity.HIGH, "NFS export reachable directly"),
    2181: (Severity.HIGH, "ZooKeeper typically has no authentication"),
    2375: (Severity.CRITICAL, "Unencrypted Docker API is remote code execution"),
    2376: (Severity.HIGH, "Docker API reachable directly"),
    3306: (Severity.HIGH, "MySQL reachable directly"),
    3389: (Severity.MEDIUM, "RDP exposed to the internet"),
    5432: (Severity.HIGH, "PostgreSQL reachable directly"),
    5900: (Severity.HIGH, "VNC exposed to the internet"),
    5984: (Severity.HIGH, "CouchDB reachable directly"),
    6379: (Severity.CRITICAL, "Redis usually has no authentication at all"),
    9042: (Severity.HIGH, "Cassandra reachable directly"),
    9200: (Severity.HIGH, "Elasticsearch typically has no authentication"),
    10250: (Severity.CRITICAL, "Kubelet API can expose container execution"),
    11211: (Severity.HIGH, "Memcached has no authentication and is a DDoS amplifier"),
    27017: (Severity.HIGH, "MongoDB reachable directly"),
    50070: (Severity.HIGH, "Hadoop NameNode reachable directly"),
}


@dataclass
class OpenPort:
    host: str
    port: int
    service: str
    banner: str | None = None


class PortStage(Stage):
    name = "ports"
    description = "TCP port discovery and service identification"
    requires = ("resolve_probe",)
    active = True

    def __init__(
        self,
        *,
        ports: tuple[int, ...] = TOP_PORTS,
        max_hosts: int = 100,
        concurrency_per_host: int = 8,
        connect_timeout: float = 2.5,
        grab_banners: bool = True,
    ) -> None:
        self._ports = ports
        self._max_hosts = max_hosts
        self._concurrency = max(1, concurrency_per_host)
        self._timeout = connect_timeout
        self._grab_banners = grab_banners

    async def run(self, ctx: StageContext) -> StageResult:
        result = StageResult(stage=self.name)
        hosts = await self._hosts(ctx)
        result.items_in = len(hosts)

        if not hosts:
            result.note("no in-scope hosts to scan")
            return result

        if len(hosts) > self._max_hosts:
            result.note(
                f"scanning the first {self._max_hosts} of {len(hosts)} hosts; "
                "raise the limit to cover more"
            )
            hosts = hosts[: self._max_hosts]

        runner = ctx.tool("naabu")
        if await runner.ensure_available():
            found = await self._scan_with_naabu(ctx, runner, hosts, result)
            if found is None:
                found = await self._scan_builtin(ctx, hosts, result)
        else:
            result.used_fallback(
                "scanning with an asyncio connect scan; naabu would be faster"
            )
            found = await self._scan_builtin(ctx, hosts, result)

        await self._persist(ctx, found, result)
        result.items_out = len(found)
        ctx.shared["open_ports"] = [
            {"host": item.host, "port": item.port, "service": item.service}
            for item in found
        ]
        return result

    # -- input -------------------------------------------------------------

    async def _hosts(self, ctx: StageContext) -> list[str]:
        rows = await ctx.session.execute(
            select(Asset).where(Asset.program_id == ctx.program_id)
        )
        return [
            asset.host
            for asset in rows.scalars().all()
            if ctx.guard.decide_host(asset.host).allowed
        ]

    # -- naabu -------------------------------------------------------------

    async def _scan_with_naabu(
        self, ctx: StageContext, runner, hosts: list[str], result: StageResult
    ) -> list[OpenPort] | None:
        port_list = ",".join(str(port) for port in self._ports)
        rate = int(
            ctx.guard.effective_limit(
                "requests_per_second_per_host", ctx.settings.requests_per_second_per_host
            )
        )
        args = [
            "-silent", "-json", "-no-color",
            "-scan-type", "c",  # connect scan: no root needed, no stealth wanted
            "-p", port_list,
            "-rate", str(max(10, rate * 10)),
            "-timeout", str(int(self._timeout * 1000)),
            "-retries", "1",
        ]
        try:
            outcome = await runner.run(args, stdin_targets=hosts, timeout=1800.0)
        except ToolNotAvailable:
            return None
        if not outcome.ok and not outcome.lines:
            result.note(f"naabu failed, falling back: {outcome.stderr.strip()[:140]}")
            return None

        result.used_tool("naabu")
        found: list[OpenPort] = []
        # naabu repeats a port across its retries, so the same host and port can
        # appear more than once in one run.
        seen: set[tuple[str, int]] = set()
        for line in outcome.lines:
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = str(row.get("host") or row.get("ip") or "")
            port = row.get("port")
            if not host or not isinstance(port, int):
                continue
            if (host, port) in seen:
                continue
            if not ctx.guard.decide_host(host).allowed:
                result.filtered("out_of_scope")
                continue
            seen.add((host, port))
            found.append(
                OpenPort(host=host, port=port, service=SERVICE_NAMES.get(port, "unknown"))
            )
        return found

    # -- built-in connect scan ---------------------------------------------

    async def _scan_builtin(
        self, ctx: StageContext, hosts: list[str], result: StageResult
    ) -> list[OpenPort]:
        found: list[OpenPort] = []

        for host in hosts:
            semaphore = asyncio.Semaphore(self._concurrency)

            async def probe(
                port: int,
                target: str = host,
                gate: asyncio.Semaphore = semaphore,
            ) -> OpenPort | None:
                async with gate:
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(target, port), timeout=self._timeout
                        )
                    except (TimeoutError, OSError):
                        return None

                    banner: str | None = None
                    try:
                        if self._grab_banners:
                            # Many services speak first. Anything that does not is
                            # left alone rather than being poked.
                            with contextlib.suppress(TimeoutError):
                                data = await asyncio.wait_for(
                                    reader.read(256), timeout=1.5
                                )
                                if data:
                                    banner = data.decode(
                                        "utf-8", errors="replace"
                                    ).strip()[:200]
                    finally:
                        writer.close()
                        with contextlib.suppress(Exception):
                            await writer.wait_closed()

                    return OpenPort(
                        host=target,
                        port=port,
                        service=SERVICE_NAMES.get(port, "unknown"),
                        banner=banner,
                    )

            outcomes = await asyncio.gather(*(probe(port) for port in self._ports))
            found.extend(item for item in outcomes if item is not None)

        result.note(
            f"connect-scanned {len(self._ports)} port(s) on {len(hosts)} host(s)"
        )
        return found

    # -- persistence --------------------------------------------------------

    async def _persist(
        self, ctx: StageContext, found: list[OpenPort], result: StageResult
    ) -> None:
        by_host: dict[str, list[OpenPort]] = {}
        for item in found:
            by_host.setdefault(item.host, []).append(item)

        for host, items in by_host.items():
            for item in items:
                await record_observation(
                    ctx.session,
                    ctx.program_id,
                    kind="open_port",
                    key=f"{host}:{item.port}",
                    value=item.service + (f" | {item.banner}" if item.banner else ""),
                    source="ports",
                )

            # Services that should not be reachable from the internet are a
            # finding in themselves, not just an observation.
            for item in items:
                concern = EXPOSURE_CONCERNS.get(item.port)
                if concern is None:
                    continue
                severity, why = concern
                _, is_new = await upsert_finding(
                    ctx.session,
                    ctx.program_id,
                    dedup_key=f"exposed_service::{item.service}",
                    vuln_class="exposed_service",
                    title=f"{item.service} reachable on port {item.port}",
                    severity=severity,
                    # Reachability is a fact, not an inference, so this is
                    # Confirmed. Whether it is *exploitable* still needs a look.
                    tier=FindingTier.CONFIRMED,
                    confidence=80,
                    description=(
                        f"{host} accepts connections on port {item.port} "
                        f"({item.service}). {why}."
                        + (f"\n\nBanner: `{item.banner}`" if item.banner else "")
                    ),
                    signals=["tcp_connect"],
                    affected_hosts=[host],
                    detector="reconx:ports",
                    scan_run_id=ctx.scan_run_id,
                    recommendation=(
                        "Confirm whether it requires authentication, and from where it "
                        "is reachable. An exposed service that turns out to need "
                        "credentials is still worth reporting as an exposure, but rate "
                        "it accordingly."
                    ),
                )
                if is_new:
                    result.new_findings.append(
                        f"CONFIRMED | {severity.value.upper()}: "
                        f"{item.service} on {host}:{item.port}"
                    )

        if by_host:
            summary = ", ".join(
                f"{host} ({len(items)})" for host, items in list(by_host.items())[:5]
            )
            result.note(f"open ports found on: {summary}")
