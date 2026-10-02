"""A local test target with known answers.

You cannot validate a scanner without a target whose truth you already know.
This serves, on 127.0.0.1 only:

Every vulnerability class ReconX verifies is paired here: a route where the bug
is real, and a route where the same *signal* appears for an innocent reason. A
class without a trap is not trustworthy, because nothing has shown it can say no.

**Real behaviour to detect**
  ``/``, ``/admin``, ``/api/v1/users``  distinct pages a probe should find
  ``/xss``             reflects input unencoded into the HTML body
  ``/attr-xss``        reflects into a quoted attribute without encoding the quote
  ``/sqli``            genuine boolean-differential behaviour
  ``/redirect``        sends Location: wherever the parameter points
  ``/cors``            reflects any Origin and allows credentials
  ``/download``        resolves ``../`` and serves the file it lands on
  ``/template``        evaluates the expression it is given
  ``/ping``            concatenates input into a command line
  ``/fetch``           requests any URL the parameter names
  ``/pickle``          base64-decodes the parameter and unpickles it, leaking a
                       real ``UnpicklingError`` on malformed input

**Deliberate false-positive traps**
  unknown paths      HTTP 200 carrying a "not found" page (soft-404), so a
                     scanner without baseline learning thinks every path exists
  ``/reflect``       reflects input but HTML-encodes it, so it is inert
  ``/attr``          reflects into an attribute but encodes the quote
  ``/static-error``  always contains a SQL error string, whatever you send
  ``/jitter``        random latency, which mimics time-based injection
  ``/waf``           returns a block page, as a WAF would
  ``/echo-url``      echoes a URL into the page but never redirects to it
  ``/cors-public``   allows any origin with ``*`` and no credentials, which is
                     the intended configuration for a public API
  ``/docs/passwd``   a page documenting ``/etc/passwd``, so it contains the
                     ``root:x:0:0`` signature without being a traversal
  ``/braces``        prints ``{{7*7}}`` back without evaluating it
  ``/echo-cmd``      echoes the command string, canary included, without running it
  ``/internal-only`` fetches a fixed internal URL whatever the parameter says
  ``/pickle-docs``   documents unpickling errors, so ``UnpicklingError`` text is
                     in the page for an innocent reason

Each trap corresponds to a class of finding other scanners report and ReconX is
supposed to discard. The integration tests assert both halves: the real issues
are found, and the traps are rejected with the right reason.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import pickle
import posixpath
import random
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

__all__ = ["TargetApp", "run_target_app"]

_HOME = """<!doctype html><html><head><title>Example Corp</title></head>
<body><h1>Welcome to Example Corp</h1>
<p>We sell examples. Browse our <a href="/products">products</a> or
<a href="/admin">sign in</a>.</p>
<p><a href="/account">My account</a> &middot; <a href="/login">Sign in</a></p>
<p>Popular: <a href="/sqli?id=1">Widget</a> &middot;
<a href="/static-error?id=1">Gadget</a> &middot;
<a href="/attr?q=blue">Filter by colour</a> &middot;
<a href="/attr-xss?q=blue">Saved filter</a> &middot;
<a href="/reflect?q=hello">Echo</a> &middot;
<a href="/jitter?id=1">Slow report</a></p>
<p>Tools: <a href="/redirect?next=/">Continue</a> &middot;
<a href="/echo-url?next=/">Link check</a> &middot;
<a href="/download?file=readme.txt">Docs</a> &middot;
<a href="/docs/passwd?file=overview">Account files</a> &middot;
<a href="/template?name=guest">Greeting</a> &middot;
<a href="/braces?name=guest">Template preview</a> &middot;
<a href="/ping?host=127.0.0.1">Ping</a> &middot;
<a href="/echo-cmd?host=127.0.0.1">Diagnostics</a> &middot;
<a href="/fetch?url=/">Fetch</a> &middot;
<a href="/internal-only?url=/">Status</a> &middot;
<a href="/pickle?data=Ti4=">Saved cart</a> &middot;
<a href="/pickle-docs?topic=overview">Serialization docs</a> &middot;
<a href="/cors">Account API</a> &middot;
<a href="/cors-public">Version API</a></p>
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

# A page that legitimately documents /etc/passwd. The traversal signature is in
# its text for an innocent reason, exactly as /static-error carries SQL error
# text. A scanner that greps for the signature reports this.
_PASSWD_DOCS = """<!doctype html><html><head><title>Account files</title></head>
<body><h1>Where accounts live</h1>
<p>On a Unix host the account list is in <code>/etc/passwd</code>, one record per
line. The superuser record looks like this:</p>
<pre>root:x:0:0:root:/root:/bin/bash</pre>
<p>Only the superuser can edit it.</p></body></html>"""

# The real traversal target. Served only when the path resolves outside the
# document root, which is what makes it a traversal rather than a normal read.
_PASSWD_FILE = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)

# A second file, because a real traversal reaches more than one and two
# different record formats are what make the finding independent of any one
# page happening to contain a signature.
_GROUP_FILE = "root:x:0:\nadm:x:4:syslog\nwww-data:x:33:\n"

# What an unauthenticated request to the gated surface gets. Deliberately carries
# a password field and no session marker, so the logged-out heuristic in
# reconx.verify.session recognises it.
_SIGN_IN_PAGE = """<!doctype html><html><head><title>Sign in</title></head>
<body><h1>Please sign in to continue</h1>
<form method="post" action="/login"><input name="user">
<input name="pass" type="password"></form></body></html>"""

# The signed-in account page. Carries the session marker.
_ACCOUNT_PAGE = """<!doctype html><html><head><title>Your account</title></head>
<body><h1>Your account</h1>
<p>Recent orders: <a href="/account/orders?ref=A-1001">A-1001</a></p>
<p><a href="/account/fake-gate">Preferences</a></p>
<p><a href="/logout">Sign out</a></p></body></html>"""

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

    def _redirect(self, location: str) -> None:
        """A 302 whose Location is whatever was asked for. The real bug."""
        body = b"<html><body>Redirecting...</body></html>"
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _one(params: dict[str, list[str]], name: str, default: str = "") -> str:
        values = params.get(name) or []
        return values[0] if values else default

    def _signed_in(self) -> bool:
        """Does this request carry a session the fixture still honours?"""
        return self.server.accepts(self.headers.get("Cookie") or "")  # type: ignore[attr-defined]

    # -- surrogates for the classes that need one -------------------------

    @staticmethod
    def _render_template(source: str) -> str:
        """A deliberately small template engine, in the Jinja/Twig dialect.

        It evaluates two things and nothing else: integer multiplication, and
        multiplying an integer by a numeric string, which that dialect answers by
        repeating the string. Both are pure, so the surrogate is a real
        evaluation without being a real sandbox escape.
        """

        def evaluate(match: re.Match[str]) -> str:
            expression = match.group(1).strip()
            repeat = re.fullmatch(r"(\d{1,4})\s*\*\s*'(\d{1,4})'", expression)
            if repeat:
                return str(repeat.group(2)) * int(repeat.group(1))
            product = re.fullmatch(r"(\d{1,6})\s*\*\s*(\d{1,6})", expression)
            if product:
                return str(int(product.group(1)) * int(product.group(2)))
            # Anything the engine cannot parse raises, as a real one would.
            return "[TemplateSyntaxError]"

        return re.sub(r"\{\{(.*?)\}\}", evaluate, source)

    @staticmethod
    def _run_shell(command: str) -> str:
        """What a vulnerable ``system("ping " + host)`` would print.

        Nothing is executed. Three read-only shell behaviours are simulated,
        because those are the ones a scanner needs and none of them writes,
        deletes or reaches the network: arithmetic expansion, which spawns no
        process at all; command substitution around ``expr``, which computes and
        exits; and ``echo``, a builtin. An unterminated expansion is left alone,
        exactly as a shell leaves it.
        """
        out = command

        def arithmetic(match: re.Match[str]) -> str:
            return str(int(match.group(1)) * int(match.group(2)))

        def expr_product(match: re.Match[str]) -> str:
            return str(int(match.group(1)) * int(match.group(2)))

        out = re.sub(r"\$\(\((\d{1,6})\s*\*\s*(\d{1,6})\)\)", arithmetic, out)
        # $(expr a \* b) and `expr a \* b`: command substitution, a different
        # mechanism from arithmetic expansion and defeatable separately.
        expr_body = r"expr\s+(\d{1,6})\s*\\?\*\s*(\d{1,6})"
        out = re.sub(rf"\$\(\s*{expr_body}\s*\)", expr_product, out)
        out = re.sub(rf"`\s*{expr_body}\s*`", expr_product, out)
        # $(echo x) and `echo x` both substitute the argument.
        out = re.sub(r"\$\(\s*echo\s+([^)]*)\)", lambda m: m.group(1), out)
        out = re.sub(r"`\s*echo\s+([^`]*)`", lambda m: m.group(1), out)
        # ; echo x runs a second command whose output follows the first.
        parts = re.split(r"[;&|]+", out)
        rendered: list[str] = []
        for part in parts:
            stripped = part.strip()
            echoed = re.fullmatch(r"echo\s+(.*)", stripped)
            rendered.append(echoed.group(1) if echoed else stripped)
        return "\n".join(filter(None, rendered))

    def _server_side_fetch(self, url: str, *, forced: bool = False) -> str:
        """Fetch a URL server-side, refusing anything that is not loopback.

        A test fixture that fetched arbitrary URLs would be an open proxy, so the
        host is checked here. The SSRF being simulated is the *reachability* of a
        callback, which loopback demonstrates completely.
        """
        from urllib.parse import urlsplit as _split

        parsed = _split(url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
            "127.0.0.1", "localhost", "::1",
        }:
            return (
                "<html><title>Fetch</title><body><p>Refused: only loopback URLs "
                "are fetched by this fixture.</p></body></html>"
            )
        try:
            with urllib.request.urlopen(url, timeout=3) as handle:  # noqa: S310
                body = handle.read(4096).decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            body = f"fetch failed: {type(exc).__name__}"
        label = "fixed internal URL" if forced else "requested URL"
        return (
            f"<html><title>Fetch</title><body><h1>Fetched the {label}</h1>"
            f"<pre>{html.escape(body[:1000])}</pre></body></html>"
        )

    @staticmethod
    def _sleep_for(command: str) -> float:
        """Honour a `sleep N` the way a vulnerable shell would, bounded."""
        match = re.search(r"\bsleep\s+(\d{1,2})", command)
        if not match:
            return 0.0
        seconds = min(int(match.group(1)), 6)
        time.sleep(seconds)
        return float(seconds)

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
        # === open redirect =================================================
        # Real: the parameter becomes the Location header verbatim.
        elif path == "/redirect":
            destination = self._one(params, "next", "/")
            self._redirect(destination)
        # Trap: the URL is printed into the page and never redirected to. A
        # scanner that looks for its sentinel anywhere in the response fires.
        elif path == "/echo-url":
            value = html.escape(self._one(params, "next"))
            self._send(
                200,
                "<!doctype html><html><head><title>Link</title></head><body>"
                f"<p>You asked for <code>{value}</code>. We do not follow "
                "external links.</p></body></html>",
            )

        # === CORS =========================================================
        # Real: any origin is reflected, and credentials are allowed with it,
        # so any site can read this response as the logged-in user.
        elif path == "/cors":
            origin = self.headers.get("Origin") or "*"
            payload = json.dumps({"balance": 4200, "owner": "alice"})
            encoded = payload.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(encoded)
        # Trap: a wildcard origin with no credentials. This is how a public API
        # is supposed to be configured, and reporting it wastes a triager's time.
        elif path == "/cors-public":
            payload = json.dumps({"version": "1.4.0", "status": "ok"})
            encoded = payload.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(encoded)

        # === path traversal ===============================================
        # Real: the filename is joined to a root and normalised, so ../ escapes.
        elif path == "/download":
            requested = self._one(params, "file", "readme.txt")
            resolved = posixpath.normpath(posixpath.join("/srv/docs", requested))
            if resolved == "/etc/passwd":
                self._send(200, _PASSWD_FILE, "text/plain")
            elif resolved == "/etc/group":
                self._send(200, _GROUP_FILE, "text/plain")
            elif resolved.startswith("/srv/docs/"):
                name = html.escape(posixpath.basename(resolved))
                self._send(
                    200,
                    "<!doctype html><html><head><title>Document</title></head>"
                    f"<body><h1>{name}</h1><p>Document contents.</p></body></html>",
                )
            else:
                self._send(404, "<html><title>Not Found</title><body>404</body></html>")
        # Trap: a page that documents /etc/passwd, so the signature is in its
        # text for an innocent reason. The same shape as /static-error.
        elif path == "/docs/passwd":
            self._send(200, _PASSWD_DOCS)

        # === server-side template injection ===============================
        # Real: the parameter is rendered as a template, not as data.
        elif path == "/template":
            rendered = self._render_template(self._one(params, "name", "guest"))
            self._send(
                200,
                "<!doctype html><html><head><title>Greeting</title></head><body>"
                f"<h1>Hello {html.escape(rendered)}</h1></body></html>",
            )
        # Trap: the braces come back untouched. Reflected, never evaluated.
        elif path == "/braces":
            value = html.escape(self._one(params, "name"))
            self._send(
                200,
                "<!doctype html><html><head><title>Preview</title></head><body>"
                f"<p>Template source: <code>{value}</code></p></body></html>",
            )

        # === command injection ============================================
        # Real: the parameter is concatenated into a command line.
        elif path == "/ping":
            host = self._one(params, "host", "localhost")
            command = f"ping -c 1 {host}"
            self._sleep_for(command)
            self._send(
                200,
                "<!doctype html><html><head><title>Ping</title></head><body><pre>"
                f"{html.escape(self._run_shell(command))}\n1 packet transmitted"
                "</pre></body></html>",
            )
        # Trap: the command line is echoed into the page without being run, so a
        # canary comes back whether or not anything executed.
        elif path == "/echo-cmd":
            host = self._one(params, "host", "localhost")
            self._send(
                200,
                "<!doctype html><html><head><title>Diagnostics</title></head><body>"
                f"<pre>would run: ping -c 1 {html.escape(host)}</pre></body></html>",
            )

        # === SSRF =========================================================
        # Real: the parameter names a URL and the server fetches it. Restricted
        # to loopback so this fixture can never be used to reach anything real.
        elif path == "/fetch":
            self._send(200, self._server_side_fetch(self._one(params, "url")))
        # Trap: fetches internally, but always the same fixed URL, so the
        # parameter cannot be redirected outward.
        elif path == "/internal-only":
            del params
            self._send(200, self._server_side_fetch(f"http://127.0.0.1:{self.server.server_address[1]}/robots.txt", forced=True))

        # === insecure deserialization =====================================
        # Real: the parameter is base64-decoded and unpickled. A well-formed
        # object loads into a normal page; a corrupt one raises a genuine
        # ``UnpicklingError`` with a 500. Both behaviours are real, and
        # together they are what two independent oracles should agree on.
        elif path == "/pickle":
            raw = self._one(params, "data", "")
            if not raw:
                self._send(
                    200,
                    "<!doctype html><html><head><title>Cart</title></head><body>"
                    "<h1>Saved cart</h1><p>Send base64-encoded state.</p></body></html>",
                )
            else:
                try:
                    blob = base64.b64decode(raw, validate=True)
                except (binascii.Error, ValueError):
                    self._send(
                        200,
                        "<!doctype html><html><head><title>Cart</title></head><body>"
                        "<h1>Saved cart</h1><p>Expected base64-encoded state.</p>"
                        "</body></html>",
                    )
                else:
                    try:
                        obj = pickle.loads(blob)
                    except Exception as exc:
                        self._send(
                            500,
                            "<html><title>Cart</title><body><p>Unhandled "
                            f"{type(exc).__module__}.{type(exc).__name__}: {exc}"
                            "</p></body></html>",
                        )
                    else:
                        self._send(
                            200,
                            "<!doctype html><html><head><title>Cart</title></head><body>"
                            f"<h1>Saved cart</h1><p>Loaded {html.escape(type(obj).__name__)}."
                            "</p></body></html>",
                        )
        # Trap: documents unpickling errors, so ``UnpicklingError`` text is in
        # the page for an innocent reason. The same shape as /static-error.
        elif path == "/pickle-docs":
            topic = html.escape(self._one(params, "topic", "overview"))
            self._send(
                200,
                "<!doctype html><html><head><title>Serialization docs</title></head>"
                "<body><h1>Unpickling without validation</h1>"
                "<p>Never pass user input to <code>pickle.loads</code>. A corrupt "
                "value raises <code>_pickle.UnpicklingError: invalid load key, "
                "'x'</code> instead of loading.</p>"
                f"<p>Topic: {topic}</p></body></html>",
            )

        # === the authenticated surface ====================================
        # Everything under /account needs the session. A scanner without one sees
        # the sign-in page, which is the whole reason authenticated scanning
        # exists: on a mature program this is where the unswept surface is.
        elif path == "/login":
            self._send(
                200,
                "<!doctype html><html><head><title>Sign in</title></head><body>"
                '<form method="post" action="/login">'
                '<input name="user"><input name="pass" type="password">'
                "</form></body></html>",
            )
        elif path == "/account":
            if not self._signed_in():
                self._send(200, _SIGN_IN_PAGE)
            else:
                self._send(200, _ACCOUNT_PAGE)
        # A real bug that only exists behind the login. Reflects unencoded into
        # the body exactly as /xss does, but is unreachable unless signed in, so a
        # test can assert auth found what unauthenticated scanning could not.
        elif path == "/account/orders":
            if not self._signed_in():
                self._send(200, _SIGN_IN_PAGE)
            else:
                value = self._one(params, "ref")
                self._send(
                    200,
                    "<!doctype html><html><head><title>Order</title></head><body>"
                    f"<h1>Order {value}</h1><p>Shipped.</p>"
                    f'<a href="/logout">{self.server.SESSION_MARKER}</a>'  # type: ignore[attr-defined]
                    "</body></html>",
                )
        # Trap: sits under /account and answers 200, but behaves identically with
        # or without the session. "I got a 200 while logged in" is not a finding,
        # and a scanner that reports gated-looking pages will report this one.
        elif path == "/account/fake-gate":
            self._send(
                200,
                "<!doctype html><html><head><title>Preferences</title></head><body>"
                "<h1>Public preferences</h1><p>No account required.</p></body></html>",
            )
        # The dangerous action. A logged-in crawler that follows this ends its own
        # session and silently turns the rest of the scan unauthenticated, which is
        # why ScopeGuard refuses it while authenticated. No test should ever see
        # this recorded.
        elif path == "/logout":
            self._send(
                200,
                "<!doctype html><html><head><title>Signed out</title></head><body>"
                "<h1>You have been signed out</h1></body></html>",
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
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("latin-1") if length else ""
        self.server.record(f"POST {path}")  # type: ignore[attr-defined]

        # Signing in by hand is how a researcher gets a session: ReconX is handed
        # one, it never submits credentials itself.
        if path == "/login":
            if "user=" in body and "pass=" in body:
                payload = b"<html><title>Welcome</title><body>Signed in.</body></html>"
                self.send_response(302)
                self.send_header(
                    "Set-Cookie",
                    f"{self.server.SESSION_COOKIE}; Path=/; HttpOnly",  # type: ignore[attr-defined]
                )
                self.send_header("Location", "/account")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self._send(401, "<html><title>Sign in</title><body>Bad credentials</body></html>")
            return

        self._send(200, "<html><title>Accepted</title><body>ok</body></html>")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    #: The session value the authenticated surface accepts. Fixed rather than
    #: random so a test can assert it never appears in stored evidence.
    SESSION_VALUE = "rx-fixture-session-DO-NOT-STORE"
    SESSION_COOKIE = f"rxsession={SESSION_VALUE}"
    #: Present only on the signed-in account page, for the session check.
    SESSION_MARKER = "Sign out"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.requested: list[str] = []
        self._lock = threading.Lock()
        # Authenticated requests served so far. Used only by expire_after.
        self.authenticated_requests = 0
        # When set, the session stops being honoured after this many
        # authenticated requests, which is how the session gate gets tested. A
        # session that dies mid-scan is the failure mode that produces a run full
        # of logged-out results looking exactly like a clean scan.
        self.expire_after: int | None = None

    def record(self, path: str) -> None:
        with self._lock:
            self.requested.append(path)

    def accepts(self, cookie_header: str) -> bool:
        """Is this request signed in? Honours expire_after."""
        if self.SESSION_VALUE not in (cookie_header or ""):
            return False
        with self._lock:
            self.authenticated_requests += 1
            if self.expire_after is not None:
                return self.authenticated_requests <= self.expire_after
        return True


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

    # -- the authenticated surface ----------------------------------------

    @property
    def session_cookie(self) -> str:
        """A ``Cookie`` header value the gated routes accept."""
        return self._server.SESSION_COOKIE

    @property
    def session_value(self) -> str:
        """The secret alone, for asserting it never reaches storage."""
        return self._server.SESSION_VALUE

    @property
    def session_marker(self) -> str:
        """Text present only on the signed-in page."""
        return self._server.SESSION_MARKER

    def expire_session_after(self, requests: int) -> None:
        """Stop honouring the session after this many authenticated requests.

        The silent-failure case: a scan that loses its session does not error, it
        returns logged-out results that look like a clean scan. This is how the
        session gate is proved to catch it.
        """
        self._server.expire_after = requests

    @property
    def authenticated_requests(self) -> int:
        return self._server.authenticated_requests

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
