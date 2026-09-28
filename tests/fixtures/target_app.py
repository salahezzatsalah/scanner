"""A local test target with known answers.

You cannot validate a scanner without a target whose truth you already know.
This serves, on 127.0.0.1 only:

**Real behaviour to detect**
  ``/``, ``/admin``, ``/api/users``   distinct pages a probe should find
  ``/xss``                            reflects input unencoded into the HTML body
  ``/sqli``                           genuine boolean-differential behaviour

  ``/login``                          an SSO-only sign-in: no local password
  ``/register``                       a local sign-up that works anyway
  ``/dashboard``                      staff-only; redirects anonymous callers
                                      to ``/login`` and serves customer records
                                      to anyone holding a session

**Deliberate false-positive traps**
  unknown paths      HTTP 200 carrying a "not found" page (soft-404), so a
                     scanner without baseline learning thinks every path exists
  ``/reflect``       reflects input but HTML-encodes it, so it is inert
  ``/static-error``  always contains a SQL error string, whatever you send
  ``/jitter``        random latency, which mimics time-based injection
  ``/waf``           returns a block page, as a WAF would
  ``/shop/*``        public sign-up with no identity provider anywhere: an
                     ordinary consumer account system, not a bypass
  ``/sso/register``  a "register" page that only hands off to the identity
                     provider, so it creates nothing locally
  ``/invite/*``      registration gated behind an invitation code
  ``/both/*``        an identity provider *and* a local password login, which
                     is a deliberate design rather than a boundary to cross

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
<p>Popular: <a href="/sqli?id=1">Widget</a> &middot;
<a href="/static-error?id=1">Gadget</a> &middot;
<a href="/attr?q=blue">Filter by colour</a> &middot;
<a href="/attr-xss?q=blue">Saved filter</a> &middot;
<a href="/reflect?q=hello">Echo</a> &middot;
<a href="/jitter?id=1">Slow report</a></p>
<form action="/xss"><input name="q"><input name="page"></form>
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

# ---------------------------------------------------------------------------
# A staff portal that authenticates through an identity provider — and ships an
# enabled local sign-up anyway. This is the shape the registration check exists
# to find, with the surrounding traps that make finding it non-trivial.
# ---------------------------------------------------------------------------

_IDP = "https://login.microsoftonline.com/ffffffff-0000-0000-0000-000000000000"

# Sign-in offers one route in: the identity provider. No password field.
_SSO_LOGIN = f"""<!doctype html><html><head><title>Staff sign in</title></head>
<body><h1>Example Salon Staff Portal</h1>
<p>Staff accounts are managed by IT. Sign in with your work account.</p>
<a class="btn" href="{_IDP}/oauth2/v2.0/authorize?client_id=abc&response_type=code">
Sign in with Microsoft</a>
<p class="meta">Having trouble? Contact the service desk.</p></body></html>"""

# ...and yet this is reachable, unauthenticated, and creates a local password.
_REGISTER = """<!doctype html><html><head><title>Create staff account</title></head>
<body><h1>Create your account</h1>
<form method="POST" action="/register">
<input type="hidden" name="_token" value="%s">
<input name="name" placeholder="Name" required>
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" required>
<input type="password" name="password_confirmation" required>
<button type="submit">Register</button></form></body></html>"""

# The page the bypass reaches: customer records, straight in the HTML.
_DASHBOARD = """<!doctype html><html><head><title>Dashboard</title></head>
<body><h1>Halo, %s</h1>
<p>Total Pesanan: 5 &middot; Total Pesanan Tertunda: 5</p>
<table><thead><tr><th>Customer</th><th>Mobile</th><th>Status</th><th>Amount</th>
<th>Timestamp</th></tr></thead><tbody>
<tr><td>Ani</td><td>6281100000101</td><td>Tertunda</td><td>Rp 788,421</td>
<td>28-09-2026 23:49:57</td></tr>
<tr><td>Budi</td><td>6281100000102</td><td>Tertunda</td><td>Rp 362,511</td>
<td>28-09-2026 23:49:43</td></tr>
<tr><td>Citra</td><td>6281100000103</td><td>Tertunda</td><td>Rp 2,461,157</td>
<td>28-09-2026 23:45:36</td></tr>
<tr><td>Dewi</td><td>6281100000104</td><td>Tertunda</td><td>Rp 1,172,324</td>
<td>28-09-2026 23:41:02</td></tr>
<tr><td>Eko</td><td>6281100000105</td><td>Tertunda</td><td>Rp 124,199</td>
<td>28-09-2026 23:38:19</td></tr>
</tbody></table></body></html>"""

# Trap: an ordinary consumer shop. Public sign-up is the product, not a bug.
_SHOP_LOGIN = """<!doctype html><html><head><title>Sign in</title></head>
<body><h1>Sign in to your account</h1>
<form method="POST" action="/shop/login"><input name="email">
<input type="password" name="password"><button type="submit">Sign in</button>
</form><p>New here? <a href="/shop/signup">Create an account</a></p>
</body></html>"""

_SHOP_SIGNUP = """<!doctype html><html><head><title>Create an account</title></head>
<body><h1>Create an account</h1>
<form method="POST" action="/shop/signup">
<input name="full_name"><input type="email" name="email">
<input type="password" name="password">
<input type="password" name="password_confirmation">
<button type="submit">Sign up</button></form></body></html>"""

# Trap: looks like registration, posts to the identity provider. Nothing local
# is created, so there is nothing to bypass.
_SSO_HANDOFF = f"""<!doctype html><html><head><title>Register</title></head>
<body><h1>Create your account</h1>
<form method="POST" action="{_IDP}/signup">
<input type="hidden" name="client_id" value="abc">
<input name="email"><input type="password" name="passwd">
<button type="submit">Create account</button></form></body></html>"""

# Trap: provisioning is controlled, whatever the form looks like.
_INVITE_REGISTER = """<!doctype html><html><head><title>Register</title></head>
<body><h1>Create your account</h1>
<p>You need an invitation code from your administrator.</p>
<form method="POST" action="/invite/register">
<input name="full_name"><input type="email" name="email">
<input name="invitation_code" required>
<input type="password" name="password">
<input type="password" name="password_confirmation">
<button type="submit">Register</button></form></body></html>"""

# Trap: the identity provider is one option among two. Local accounts are
# clearly intended here, so registration is not crossing anything.
_BOTH_LOGIN = f"""<!doctype html><html><head><title>Sign in</title></head>
<body><h1>Sign in</h1>
<a href="{_IDP}/oauth2/v2.0/authorize?client_id=abc">Sign in with Microsoft</a>
<p>or use your email</p>
<form method="POST" action="/both/login"><input name="email">
<input type="password" name="password"><button type="submit">Sign in</button>
</form></body></html>"""

_BOTH_REGISTER = """<!doctype html><html><head><title>Register</title></head>
<body><h1>Create your account</h1>
<form method="POST" action="/both/register">
<input name="full_name"><input type="email" name="email">
<input type="password" name="password">
<input type="password" name="password_confirmation">
<button type="submit">Register</button></form></body></html>"""

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
        self,
        status: int,
        body: str,
        content_type: str = "text/html; charset=utf-8",
        extra: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Powered-By", "ExampleCorp")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _redirect(self, location: str, extra: dict[str, str] | None = None) -> None:
        self._send(302, "", extra={"Location": location, **(extra or {})})

    def _session(self) -> str | None:
        """The staff session this request carries, if the server issued it."""
        raw = self.headers.get("Cookie") or ""
        for chunk in raw.split(";"):
            name, _, value = chunk.strip().partition("=")
            if name == "staff_session" and value in self.server.sessions:  # type: ignore[attr-defined]
                return value
        return None

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
        # --- the staff portal: SSO sign-in, open sign-up, protected area ---
        elif path == "/login":
            self._send(200, _SSO_LOGIN)
        elif path == "/register":
            self._send(200, _REGISTER % random.randint(10**19, 10**20))
        elif path == "/dashboard":
            session = self._session()
            if session is None:
                self._redirect("/login")
            else:
                name = self.server.sessions[session]  # type: ignore[attr-defined]
                self._send(200, _DASHBOARD % html.escape(name))
        # --- traps ---------------------------------------------------------
        elif path == "/shop/login":
            self._send(200, _SHOP_LOGIN)
        elif path == "/shop/signup":
            self._send(200, _SHOP_SIGNUP)
        elif path == "/shop/account":
            self._redirect("/shop/login")
        elif path == "/sso/register":
            self._send(200, _SSO_HANDOFF)
        elif path == "/sso/login":
            self._send(200, _SSO_LOGIN)
        elif path == "/sso/dashboard":
            self._redirect("/sso/login")
        elif path == "/invite/register":
            self._send(200, _INVITE_REGISTER)
        elif path == "/invite/login":
            self._send(200, _SSO_LOGIN)
        elif path == "/invite/dashboard":
            self._redirect("/invite/login")
        elif path == "/both/login":
            self._send(200, _BOTH_LOGIN)
        elif path == "/both/register":
            self._send(200, _BOTH_REGISTER)
        elif path == "/both/dashboard":
            self._redirect("/both/login")
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
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        path = urlsplit(self.path).path.rstrip("/") or "/"
        self.server.record(f"POST {path}")  # type: ignore[attr-defined]
        fields = {key: values[0] for key, values in parse_qs(raw).items()}

        # The whole point of the fixture: an unauthenticated POST creates a
        # staff account and is handed a session on the spot.
        if path == "/register":
            email = fields.get("email", "")
            password = fields.get("password", "")
            if (
                not fields.get("_token")
                or "@" not in email
                or not password
                or password != fields.get("password_confirmation")
            ):
                self._send(422, "<html><title>Invalid</title><body>check the form</body></html>")
                return
            name = fields.get("name") or email.split("@")[0]
            token = f"sess-{random.randint(10**15, 10**16)}"
            self.server.sessions[token] = name  # type: ignore[attr-defined]
            self.server.accounts.append(dict(fields))  # type: ignore[attr-defined]
            self._redirect(
                "/dashboard",
                {"Set-Cookie": f"staff_session={token}; Path=/; HttpOnly"},
            )
            return

        self._send(200, "<html><title>Accepted</title><body>ok</body></html>")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.requested: list[str] = []
        # Sessions the app has issued, and the accounts that produced them, so
        # a test can assert what a scan actually left behind on the target.
        self.sessions: dict[str, str] = {}
        self.accounts: list[dict[str, str]] = []
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

    @property
    def accounts(self) -> list[dict[str, str]]:
        """Accounts created through ``POST /register`` during the test."""
        return list(self._server.accounts)

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
