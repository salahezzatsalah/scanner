"""A local out-of-band callback listener.

Some vulnerabilities are only observable from outside the response. An SSRF that
discards the body still makes a request, so the proof is a listener that records
it. That listener is normally a hosted "interaction" service, and using one has a
cost nobody mentions: **every payload publishes the target's hostnames, paths and
parameter names to a third party**, correlated with the moment you tested them.
For a private bug bounty program that is a disclosure, and it is not yours to
make.

So ReconX ships its own, and it is local:

* it binds ``127.0.0.1`` by default and is **off** unless explicitly enabled,
* it never contacts any third-party service, and there is no setting that points
  it at one,
* it records the request line, the headers and the peer, and serves a fixed
  marker body. It stores nothing else and executes nothing.

The honest limitation, stated plainly because it decides when this is useful: a
loopback listener can only be reached by a target that is on the same machine.
Against a remote target you must give ``public_base_url`` an address that target
can reach — your own host, or a tunnel you control. Without that, the callback
oracle simply does not agree, and the SSRF verifier falls back to what it can
observe in the response. It does not guess.

DNS-only interaction, where a resolver lookup is the sole evidence, needs an
authoritative nameserver and is deliberately not implemented: there is no way to
do it locally, and the alternative is the third-party service this exists to
avoid.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime

__all__ = ["Interaction", "LocalCollaborator"]

#: Served to anything that connects. Unique enough to search a response for.
MARKER_PREFIX = "reconx-oob-marker"

_MAX_INTERACTIONS = 2000
_MAX_REQUEST_BYTES = 8192


@dataclass(frozen=True)
class Interaction:
    """One request the listener received."""

    token: str
    method: str
    path: str
    host_header: str
    peer: str
    at: datetime
    user_agent: str = ""

    def as_dict(self) -> dict:
        return {
            "token": self.token,
            "method": self.method,
            "path": self.path,
            "host_header": self.host_header,
            "peer": self.peer,
            "at": self.at.isoformat(),
            "user_agent": self.user_agent,
        }


@dataclass
class LocalCollaborator:
    """A loopback HTTP listener that records what reaches it.

    ``public_base_url`` overrides the URL written into payloads, for the case
    where the listener is reachable from the target at some other address. The
    bind address itself stays loopback unless ``bind_host`` is changed, and
    changing it is the operator's decision to expose a port.
    """

    bind_host: str = "127.0.0.1"
    bind_port: int = 0
    public_base_url: str = ""
    interactions: list[Interaction] = field(default_factory=list)
    _server: asyncio.AbstractServer | None = field(default=None, repr=False)
    _port: int = field(default=0, repr=False)
    _marker: str = field(default="", repr=False)

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> LocalCollaborator:
        if self._server is not None:
            return self
        self._marker = f"{MARKER_PREFIX}-{secrets.token_hex(6)}"
        self._server = await asyncio.start_server(
            self._handle, self.bind_host, self.bind_port
        )
        sockets = self._server.sockets or ()
        self._port = sockets[0].getsockname()[1] if sockets else self.bind_port
        return self

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def __aenter__(self) -> LocalCollaborator:
        return await self.start()

    async def __aexit__(self, *_exc) -> None:
        await self.stop()

    # -- addressing --------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def port(self) -> int:
        return self._port

    @property
    def marker(self) -> str:
        """The body this listener serves, so a response carrying it is evidence."""
        return self._marker

    @property
    def base_url(self) -> str:
        if self.public_base_url:
            return self.public_base_url.rstrip("/")
        return f"http://{self.bind_host}:{self._port}"

    @property
    def is_loopback_only(self) -> bool:
        """True when only a target on this machine could reach the listener."""
        return not self.public_base_url and self.bind_host in {
            "127.0.0.1", "localhost", "::1",
        }

    def new_token(self) -> str:
        return f"rx{secrets.token_hex(8)}"

    def url_for(self, token: str) -> str:
        """The URL to put in a payload, carrying ``token`` in its path."""
        return f"{self.base_url}/{token}"

    # -- reading what arrived ---------------------------------------------

    def received(self, token: str, *, exclude_user_agents: tuple[str, ...] = ()) -> list[Interaction]:
        """Interactions carrying ``token``, optionally ignoring some clients.

        ``exclude_user_agents`` exists because of a false positive this fixture
        caught: an open-redirect endpoint answered a probe with ``Location:`` set
        to the listener, the scanner followed the hop, and the listener recorded a
        request that looked exactly like a server-side fetch. It was the scanner's
        own request. A callback that carries ReconX's user agent came from ReconX.
        """
        hits = [item for item in self.interactions if item.token == token]
        if not exclude_user_agents:
            return hits
        lowered = tuple(item.lower() for item in exclude_user_agents if item)
        return [
            item
            for item in hits
            if not any(needle in item.user_agent.lower() for needle in lowered)
        ]

    async def wait_for(
        self,
        token: str,
        *,
        timeout: float = 5.0,
        exclude_user_agents: tuple[str, ...] = (),
    ) -> list[Interaction]:
        """Poll briefly for an interaction, since the callback is asynchronous.

        A server-side fetch does not complete before the response that triggered
        it, so a callback can land slightly late. The wait is short and bounded.
        """
        deadline = asyncio.get_running_loop().time() + max(0.0, timeout)
        while True:
            hits = self.received(token, exclude_user_agents=exclude_user_agents)
            if hits:
                return hits
            if asyncio.get_running_loop().time() >= deadline:
                return []
            await asyncio.sleep(0.1)

    # -- the listener ------------------------------------------------------

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Record the request and answer with a fixed marker. Nothing is executed."""
        try:
            raw = await asyncio.wait_for(reader.read(_MAX_REQUEST_BYTES), timeout=5.0)
        except (TimeoutError, OSError):
            writer.close()
            return

        text = raw.decode("latin-1", errors="replace")
        lines = text.split("\r\n")
        request_line = lines[0] if lines else ""
        parts = request_line.split(" ")
        method = parts[0][:10] if parts else ""
        path = parts[1][:500] if len(parts) > 1 else "/"

        headers = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()[:300]

        peer = ""
        try:
            info = writer.get_extra_info("peername")
            peer = f"{info[0]}:{info[1]}" if info else ""
        except (TypeError, IndexError):  # pragma: no cover - defensive
            peer = ""

        if len(self.interactions) < _MAX_INTERACTIONS:
            self.interactions.append(
                Interaction(
                    token=path.lstrip("/").split("/")[0].split("?")[0],
                    method=method,
                    path=path,
                    host_header=headers.get("host", ""),
                    peer=peer,
                    at=datetime.now(UTC),
                    user_agent=headers.get("user-agent", ""),
                )
            )

        body = self._marker.encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        with contextlib.suppress(OSError):  # the peer may hang up first
            await writer.drain()
        writer.close()
