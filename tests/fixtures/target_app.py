"""A local test target with known answers.

You cannot validate a scanner without a target whose truth you already know.
This serves, on 127.0.0.1 only:

**Real behaviour to detect**
  ``/``, ``/admin``, ``/api/users``   distinct pages a probe should find
  ``/xss``                            reflects input unencoded into the HTML body
  ``/sqli``                           genuine boolean-differential behaviour

**Deliberate false-positive traps**
  unknown paths      HTTP 200 carrying a "not found" page (soft-404), so a
                     scanner without baseline learning thinks every path exists
  ``/reflect``       reflects input but HTML-encodes it, so it is inert
  ``/static-error``  always contains a SQL error string, whatever you send
  ``/jitter``        random latency, which mimics time-based injection
  ``/waf``           returns a block page, as a WAF would

Each trap corresponds to a class of finding other scanners report and ReconX is
supposed to discard. The integration tests assert both halves: the real issues
are found, and the traps are rejected with the right reason.
"""

from __future__ import annotations

import html
import json
import random
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

__all__ = ["TargetApp", "run_target_app"]

_HOME = """<!doctype html><html><head><title>Example Corp</title></head>
<body><h1>Welcome to Example Corp</h1>
<p>We sell examples. Browse our <a href="/products">products</a> or
<a href="/admin">sign in</a>.</p>
<form action="/search"><input name="q"><input name="page"></form>
<script src="/static/app.js"></script></body></html>"""

_ADMIN = """<!doctype html><html><head><title>Administrator sign in</title></head>
<body><h1>Administrator sign in</h1>
<form method="post" action="/admin"><input name="username"><input name="password"
type="password"><input type="hidden" name="csrf" value="%s"></form>
<p>Unauthorized access is prohibited and monitored.</p></body></html>"""

# The soft-404: HTTP 200, with wording that reads like a 404 to a human. A
# request id makes the body differ on every fetch, which is exactly the dynamic
# noise that defeats hash-based comparison.
_SOFT_404 = """<!doctype html><html><head><title>Page not found</title></head>
<body><h1>Sorry, we could not find that page</h1>
<p>Try our <a href="/">home page</a> instead.</p>
<p class="meta">Request %s at %s</p></body></html>"""

_WAF_BLOCK = """<!doctype html><html><head><title>Request blocked</title></head>
<body><h1>Request blocked</h1><p>Your request was blocked by our security
policy. Reference %s.</p></body></html>"""

_STATIC_ERROR = """<!doctype html><html><head><title>Product</title></head>
<body><h1>Product detail</h1>
<pre>Notice: the legacy import job logged: You have an error in your SQL syntax
near 'LIMIT 1' at line 3. This message is part of the page template.</pre>
<p>Product id: %s</p></body></html>"""

_JS_FILE = """// app.js
const API_BASE = "/api/v1";
fetch(API_BASE + "/users");
fetch("/api/v1/orders?status=open");
const INTERNAL = "https://internal-admin.example.com/panel";
// TODO: rotate this before launch
const LEGACY_KEY = "example-not-a-real-secret";
"""


# Boolean markers the SQLi surrogate responds to, as a real injectable query
# would respond to the logic rather than to the literal text.
_Q = chr(39)
_TRUE_MARKERS = frozenset({_Q + '1' + _Q + '=' + _Q + '1', '1=1',
                           _Q + 'a' + _Q + '=' + _Q + 'a'})
_FALSE_MARKERS = frozenset({_Q + '1' + _Q + '=' + _Q + '2', '1=2',
                            _Q + 'a' + _Q + '=' + _Q + 'b'})

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ExampleCorp/1.0"

    # Silence the default stderr access log during tests.
    def log_message(self, fmt: str, *args) -> None:  # noqa: A002
        return

    # -- helpers ----------------------------------------------------------

    def _send(
        self, status: int, body: str, content_type: str = "text/html; charset=utf-8"
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Powered-By", "ExampleCorp")
        self.end_headers()
        self.wfile.write(payload)

    @staticmethod
    def _one(params: dict[str, list[str]], name: str, default: str = "") -> str:
        values = params.get(name) or []
        return values[0] if values else default

    # -- routing ----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        params = parse_qs(parts.query)
        self.server.record(path)  # type: ignore[attr-defined]

        if path == "/":
            self._send(200, _HOME)
        elif path == "/admin":
            self._send(200, _ADMIN % random.randint(10**9, 10**10))
        elif path == "/robots.txt":
            self._send(
                200,
                "User-agent: *\nDisallow: /admin\nDisallow: /internal-reports\n",
                "text/plain",
            )
        elif path == "/static/app.js":
            self._send(200, _JS_FILE, "application/javascript")
        # Named only in app.js, never linked from any page. A crawler that does
        # not read JavaScript will miss these entirely.
        elif path == "/api/v1/users":
            self._send(
                200,
                json.dumps({"users": [{"id": 1, "name": "alice"}]}),
                "application/json",
            )
        elif path == "/api/v1/orders":
            self._send(
                200,
                json.dumps({"orders": [{"id": 7, "status": "open"}]}),
                "application/json",
            )
        # --- a genuine reflected XSS: input lands unencoded in the body ----
        elif path == "/xss":
            value = self._one(params, "q")
            self._send(
                200,
                f"<!doctype html><html><head><title>Search</title></head><body>"
                f"<h1>Results for {value}</h1><p>No matches.</p></body></html>",
            )
        # --- trap: reflected but HTML-encoded, so inert --------------------
        elif path == "/reflect":
            value = html.escape(self._one(params, "q"))
            self._send(
                200,
                f"<!doctype html><html><head><title>Echo</title></head><body>"
                f"<h1>You said {value}</h1></body></html>",
            )
        # --- a genuine SQLi surrogate --------------------------------------
        # Behaves as if the parameter were concatenated into a query: it
        # responds to the *logic* of an injected boolean, and leaks a driver
        # error on unbalanced quotes. Both are real injectable behaviours, and
        # together they are what two independent oracles should agree on.
        elif path == "/sqli":
            raw = self._one(params, "id", "1")
            compact = raw.replace(" ", "").replace(chr(34), chr(39))

            if compact.count(chr(39)) % 2 == 1:
                self._send(
                    200,
                    "<html><title>Item</title><body><p>Database error: You have "
                    "an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version for the right "
                    "syntax to use near line 1</p></body></html>",
                )
            elif _FALSE_MARKERS & {m for m in _FALSE_MARKERS if m in compact}:
                self._send(
                    200,
                    "<html><title>Item</title><body><p>No such item.</p>"
                    "</body></html>",
                )
            elif compact == "1" or {m for m in _TRUE_MARKERS if m in compact}:
                self._send(
                    200,
                    "<html><title>Item</title><body><h1>Widget</h1>"
                    "<p>In stock: 42 units. Ships today.</p></body></html>",
                )
            else:
                self._send(
                    200,
                    "<html><title>Item</title><body><p>No such item.</p>"
                    "</body></html>",
                )
        # --- trap: reflects into a quoted attribute but encodes the quote ---
        elif path == "/attr":
            value = self._one(params, "q").replace(chr(34), "&quot;")
            self._send(
                200,
                "<!doctype html><html><head><title>Filter</title></head><body>"
                + chr(60) + "input type=" + chr(34) + "text" + chr(34)
                + " name=" + chr(34) + "q" + chr(34)
                + " value=" + chr(34) + value + chr(34) + chr(62)
                + "</body></html>",
            )
        # --- a genuine XSS in a quoted attribute: the quote is NOT encoded --
        elif path == "/attr-xss":
            value = self._one(params, "q")
            self._send(
                200,
                "<!doctype html><html><head><title>Filter</title></head><body>"
                + chr(60) + "input type=" + chr(34) + "text" + chr(34)
                + " name=" + chr(34) + "q" + chr(34)
                + " value=" + chr(34) + value + chr(34) + chr(62)
                + "</body></html>",
            )
        # --- trap: a SQL error string that is always present ---------------
        elif path == "/static-error":
            self._send(200, _STATIC_ERROR % html.escape(self._one(params, "id", "1")))
        # --- trap: random latency, mimicking time-based injection ----------
        elif path == "/jitter":
            time.sleep(random.choice([0.0, 0.0, 0.45, 0.9]))
            self._send(200, "<html><title>Report</title><body>Done.</body></html>")
        # --- trap: a WAF-style block page -----------------------------------
        elif path == "/waf":
            self._send(403, _WAF_BLOCK % random.randint(10**6, 10**7))
        elif path == "/real-404":
            self._send(404, "<html><title>Not Found</title><body>404</body></html>")
        else:
            # The soft-404 trap: 200 with not-found wording and dynamic noise.
            self._send(
                200, _SOFT_404 % (random.randint(10**7, 10**8), time.strftime("%H:%M:%S"))
            )

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._send(200, "<html><title>Accepted</title><body>ok</body></html>")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.requested: list[str] = []
        self._lock = threading.Lock()

    def record(self, path: str) -> None:
        with self._lock:
            self.requested.append(path)


class TargetApp:
    """A running local target."""

    def __init__(self, server: _Server, thread: threading.Thread) -> None:
        self._server = server
        self._thread = thread

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    @property
    def requested_paths(self) -> list[str]:
        return list(self._server.requested)

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@contextmanager
def run_target_app() -> Iterator[TargetApp]:
    """Run the target app on an ephemeral port, bound to localhost only."""
    server = _Server(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    app = TargetApp(server, thread)
    try:
        yield app
    finally:
        app.shutdown()
