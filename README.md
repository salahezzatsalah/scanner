# ReconX

**Continuous reconnaissance and vulnerability verification for authorized security research.**

ReconX takes a program scope and works it: information gathering, subdomain enumeration for
wildcard programs, endpoint discovery, and vulnerability scanning — continuously, on a schedule,
alerting you when something new appears and telling you what to look at next.

> **Authorized use only.** ReconX requires a scope file with an explicit authorization block and
> refuses to send a single packet to anything outside that scope. Use it on bug bounty programs
> you are enrolled in and engagements you have written permission for. Nothing else.

---

## The point: findings you can trust

Most scanners fail researchers the same way. They report pattern matches rather than confirmed
issues, so you spend your time triaging noise instead of hunting. ReconX is built around the
opposite bet: **every candidate finding is independently re-proved before you ever see it.**

ReconX does not ship a new detection engine. Detection quality takes years to tune, and a
from-scratch scanner produces *more* false positives, not fewer. Instead ReconX orchestrates
proven tools (subfinder, dnsx, httpx, naabu, katana, nuclei, ffuf, dalfox, sqlmap) and adds the
layer none of them have — a verification pipeline:

| Technique | The noise it removes |
|---|---|
| **Baseline fingerprinting** | Findings indistinguishable from the host's own error page |
| **Wildcard-DNS detection** | Thousands of phantom subdomains from wildcard zones |
| **Soft-404 learning** | Content discovery where every path looks like a hit |
| **Reproducibility gate** (3× re-test) | Flaky and timing-luck findings |
| **Control/differential testing** | "That SQL error string was always on the page" |
| **SQLi: two independent oracles** | Network jitter mistaken for time-based injection |
| **XSS: context analysis + real DOM execution** | Reflected-but-inert input reported as XSS |
| **Every class: two independent oracles** | One signal seen twice counted as corroboration |
| **Session gating** | A scan that silently logged out, reported as a clean result |
| **WAF state gating** | Whole runs poisoned by block pages read as anomalies |
| **Cross-asset correlation** | One issue spammed as 200 separate findings |
| **Evidence or it isn't Confirmed** | Unreproducible findings that waste submissions |

Findings land in tiers — **Confirmed**, **Probable**, **Needs review**, **Discarded**. Only the
first two surface by default. Discarded findings are *kept, with the reason they were dropped*, so
you can audit the filter rather than trust it blindly.

### The classes, and the trap each one has to reject

Every vulnerability class is paired in the test fixture with a route where the
same *signal* appears for an innocent reason. A class without a trap does not
ship, because nothing has shown it can say no until it has rejected something —
and saying no is the entire value here. Each trap below is a finding other
scanners report.

| Class | Confirmed on | The trap it rejects |
|---|---|---|
| SQL injection | a boolean differential **and** a driver error a benign control does not produce | a page whose template always contains SQL error text |
| Cross-site scripting | escapable context **and** execution in a real browser | input reflected but encoded, so it is inert |
| Open redirect | an absolute **and** a protocol-relative value reaching a host we name | a URL printed into the page that nothing redirects to |
| CORS | an arbitrary origin reflected **and** credentials allowed with it | `Access-Control-Allow-Origin: *` with no credentials, which is the intended config for a public API |
| Path traversal | two **different** well-known files reached, each against a control | a page documenting `/etc/passwd`, so the record shape is in its text |
| Template injection | a random product computed **and** a dialect-specific expression naming the engine | template braces reflected but never evaluated |
| Command injection | shell arithmetic **and** command substitution, both computing a value the request never contained | an endpoint that echoes the command line without running it |
| SSRF | a callback we observe arriving **and** its answer coming back in the response | a parameter that fetches internally but always the same fixed URL |
| Subdomain takeover | delegation, the service's unclaimed page, **and** a dangling check | a page containing a service's unclaimed text without delegating to it |

Timing signals never confirm anything on their own, in any class. Network
variance imitates them too well.

**What the payloads will not do.** Command injection uses read-only markers only:
shell arithmetic spawns no process, `expr` computes and exits. Nothing writes,
deletes, opens a shell, reads a file or reaches the network. Path traversal reads
one matching record to prove the boundary is crossed and does not enumerate or
exfiltrate. nuclei runs with `dos,fuzz,intrusive,stress` excluded. The SSRF
callback listener is **local**: it binds loopback, is off by default, and there is
no setting pointing it at a hosted interaction service — that would publish the
target's hostnames to a third party outside the program.

---

## Install

Requires Python 3.11+. Go 1.21+ is optional but recommended — it unlocks the fast scanners.

```bash
git clone <your-remote> scanner && cd scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env          # edit as needed; SQLite default needs no setup
./scripts/bootstrap.sh        # installs the Go scanners + nuclei templates
reconx doctor                 # shows what's installed and how to fix gaps
```

**ReconX runs with zero Go tools installed.** Every stage has a pure-Python fallback, so you get
useful results immediately and more speed and breadth as you add tools. `reconx doctor` prints the
exact install command for anything missing, and `--no-external-tools` forces the built-in paths
when you want a run that does not depend on what happens to be installed.

One caveat `doctor` handles for you: the Python `httpx` package installs a command-line tool with
the same name as ProjectDiscovery's `httpx` prober. ReconX checks each candidate binary's identity
before using it, so it picks the right one even when the wrong one comes first on your `PATH`.

Optional extras:

```bash
pip install -e ".[browser]" && playwright install chromium   # headless XSS confirmation
pip install -e ".[postgres]"                                 # Postgres instead of SQLite
```

---

## Usage

### 1. Define your scope

```yaml
# scopes/acme.yaml
program: "Acme Corp VDP"
platform: hackerone
program_url: "https://hackerone.com/acme"

authorization:
  authorized_by: "you@example.com"
  date: "2026-09-28"
  attestation: "I am enrolled in this program and authorized to test the scope below."

in_scope:
  - "*.acme.com"           # wildcard: enumerate subdomains
  - "api.acme.io"
  - "203.0.113.0/24"

out_of_scope:              # always wins over in_scope
  - "payments.acme.com"
  - "*.internal.acme.com"

limits:
  requests_per_second_per_host: 3
  max_concurrent_hosts: 5
```

### 2. Run it

```bash
# Check the scope before anything touches the network.
reconx scope validate scopes/acme.yaml
reconx scope test scopes/acme.yaml www.acme.com payments.acme.com evil.com

reconx scope add scopes/acme.yaml         # store it under a slug
reconx scope list

reconx scan run acme --stage recon        # passive recon + subdomains + probe
reconx scan run acme                      # everything available
reconx scan run acme --no-brute           # passive enumeration only
reconx scan run acme --no-external-tools  # pure Python, ignore installed scanners
reconx scan run acme --resume 42          # pick up an interrupted run

# Wordlists. One file cannot serve all three -- subdomain labels, URL paths and
# parameter names have nothing in common -- so each has its own flag. The
# built-in lists are 235 / 72 / 103 entries: fallbacks, not wordlists.
#   git clone --depth 1 https://github.com/danielmiessler/SecLists
reconx scan run acme \
  --wordlist       SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  --path-wordlist  SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  --param-wordlist SecLists/Discovery/Web-Content/burp-parameter-names.txt

reconx scan run acme --skip-check cmdi --skip-check ssti   # narrow the classes
reconx scan run acme --oob                # enable the local SSRF callback listener

reconx scan history acme
reconx assets list acme --live
reconx findings list acme --tier confirmed
reconx findings list acme --tier discarded   # audit what the filter rejected

reconx next acme                  # what to do next, ordered, with reasoning
reconx triage rescore acme        # recompute priority for every finding

reconx report acme -o report.md
reconx report acme -f html -o report.html    # standalone, no external requests
reconx report acme -f json -o report.json    # for archiving or diffing
reconx api                        # HTTP API on 127.0.0.1:8000, docs at /docs
```

`scope validate` and `scope test` send no traffic at all, so you can check a
scope before you trust it. `scope test` exits non-zero if any target you name is
out of scope, which makes it usable in a script.

`reconx doctor` reports which external tools are installed, whether the callback
listener is enabled, and where to get SecLists.

### Scanning behind a login

On a mature program the unauthenticated surface has been swept by hundreds of
researchers. The bugs are behind the login, so an `auth` block in the scope file is
usually the difference between a scan that finds something and one that does not.

```yaml
auth:
  credential_env: "RECONX_AUTH_ACME"   # the variable, never the value
  kind: cookie                          # cookie | header | bearer
  session_check_url: "https://app.acme.com/account"
  session_check_marker: "Sign out"      # text present only while signed in
```

```bash
export RECONX_AUTH_ACME='session=abc123...'    # sign in with a browser, copy it
reconx scope validate scopes/acme.yaml         # says whether it is set, never what it is
```

Four things about it are deliberate:

- **The credential is never in the scope file**, which is checked in and is your
  authorization record. `credential_env` rejects a value that looks like a pasted
  secret rather than a variable name.
- **`session_check_marker` is not optional.** A session that expires mid-scan does
  not fail: every verifier afterwards finds nothing and the run reads as a clean
  scan. The marker is how that is caught, and findings gathered after it disappears
  become Needs review rather than clean. A check that cannot complete counts too.
- **Nothing ReconX stores contains the session.** Evidence rows, `curl`
  reproductions, the audit log and every report format have it stripped on the way
  in and replaced with `$YOUR_SESSION`. A cookie-borne *payload* still reproduces:
  the payload survives, the credential does not. The passive tools never receive it
  at all, because they query crt.sh and VirusTotal rather than your target.
- **A logged-in crawler is not a reader.** While authenticated, ~37
  state-changing path patterns are refused — `/logout`, `/delete`,
  `/change-password`, `/billing`, `/invite` — and form and JSON parameters are not
  fuzzed, because a POST to an authenticated endpoint changes your own data. Both
  are overridable per program; `scope validate` tells you what it turned off.

ReconX does not log in for you. Scripted credential submission is how a scanner
locks an account out, and it buys nothing.

### Options that survive into scheduled scans

A flag cannot tune a scan nobody is typing. Anything you want a **monitored**
program to use goes in its scope file, under `scan_options` — the CLI, the REST
API and the scheduler all read it, so a 3am run is the same run you tested by
hand:

```yaml
scan_options:
  path_wordlist: "~/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
  parameter_wordlist: "~/SecLists/Discovery/Web-Content/burp-parameter-names.txt"
  skip_checks: ["cmdi"]        # sqli xss redirect cors traversal ssti cmdi ssrf
  enable_timing: false         # slow, and never confirms alone
  ports: [80, 443, 8443]
```

An unknown check name is rejected when the scope loads rather than silently
ignored, and `scopes/example.yaml` documents every field.

### 3. Run it continuously

```bash
reconx monitor enable acme        # create the default schedule
reconx monitor status acme        # what runs when, and when it next fires
reconx monitor cadence acme resolve_probe 30m   # tune any stage
reconx monitor tick               # run one cycle now, to check your setup
reconx serve                      # run continuously in the foreground
```

Each stage has its own cadence, because different things change at different speeds:

| Stage | Default | Why |
|---|---|---|
| `resolve_probe` | hourly | liveness and titles change fast |
| `subdomains` | daily | **a new host is the highest-value signal on a wildcard program** |
| `content` | daily | new endpoints appear with deploys |
| `passive_recon` | weekly | registration data moves slowly |
| `params` | weekly | |
| `vulns` | weekly | the most expensive pass |

The diff engine watches for new hosts, hosts that start or stop answering, notable new endpoints,
and new findings, then sends one message with findings first. **It stays silent when nothing
changed** — a monitor that pings you hourly regardless gets muted, and then it is useless.

Set any of `RECONX_DISCORD_WEBHOOK`, `RECONX_SLACK_WEBHOOK`, `RECONX_TELEGRAM_BOT_TOKEN` plus
`RECONX_TELEGRAM_CHAT_ID`, or `RECONX_GENERIC_WEBHOOK` in `.env`. The generic webhook posts
structured JSON, so it can feed a dashboard rather than only a chat window.

Alerts carry hostnames, URLs and finding titles, so point them at a channel only you can read.
The schedule lives in the database: stopping and restarting `reconx serve` picks up where it left
off, and only one scan runs per program at a time so the scope's rate limits still hold.

---

## How it is built to stay safe

These are structural, not advisory:

- **A scope file is mandatory**, and carries an authorization block. No scan starts without one.
- **`ScopeGuard` is a single chokepoint.** Every DNS query and HTTP request resolves through it.
  A test asserts no network path bypasses it. Out-of-scope patterns override in-scope wildcards.
- **Polite by default.** Per-host token-bucket rate limiting and concurrency caps, tuned low.
- **Intrusive checks are opt-in.** No DoS or stress categories at all. `sqlmap` is constrained to
  non-destructive detection. Command-injection probes are read-only markers; path traversal proves
  the boundary is crossed and reads no further.
- **Out-of-band callbacks stay local.** The SSRF listener binds loopback, is off unless you enable
  it, and cannot be pointed at a hosted interaction service — which would publish the target's
  hostnames to someone outside the program.
- **A PTR record is information, not authorization.** Reverse DNS across an address range is
  recorded in full, and a name it returns becomes a testable asset only if the scope covers it.
- **A session reaches the target and nothing else.** Headers are attached only after the guard has
  allowed that exact hop, including every redirect, so a credential cannot follow a 302 off-scope.
  It is redacted on the way into storage rather than on the way out, so no unredacted copy exists.
- **An authenticated scan says which surface it describes.** The run records the session state, so a
  scan that lost its session is not mistaken for a scan that found nothing.
- **Full audit log.** Every request recorded with a timestamp, so you can show exactly what you
  touched and when.
- **Attributable traffic.** `RECONX_USER_AGENT` is carried by ReconX's own client and by every
  external tool that speaks HTTP to the target, so a program can tell your research from an attack.
  Put your handle in it. Set `RECONX_IDENTITY_HEADER` if a program wants its own header name. The
  passive tools are deliberately excluded: they query crt.sh and VirusTotal, not the target, and
  your handle is not theirs to have.
- **Scope-focused by design.** Built to work one program you are authorized on — not for
  untargeted sweeping, and with no detection-evasion features.

---

## Architecture

```
scope.yaml → ScopeGuard → Orchestrator (dependency-ordered, parallel, resumable)
   ├─ passive_recon ... RDAP registration, DNS records, IP and ASN attribution,
   │                    and reverse DNS across an in-scope address range
   ├─ subdomains ...... passive sources + brute + permutations → wildcard filter
   ├─ resolve_probe ... liveness, tech, TLS → group identical responses
   ├─ ports ........... naabu or a connect scan → exposed-service findings
   ├─ content ......... robots/sitemap, crawl, archives, JS mining → soft-404 filter
   ├─ params .......... parameter discovery + reflection map
   └─ vulns ........... nuclei, SQLi, XSS, takeover, open redirect, CORS,
                        path traversal, template and command injection, SSRF
                              ↓
                      VERIFICATION ENGINE
              baseline · WAF state · reproducibility
              payload-versus-control differential
              two independent oracles per class · DOM XSS
              local out-of-band callback listener
                              ↓
   Confirmed / Probable / Needs review / Discarded (with the reason)
                              ↓
   priority scoring · next actions · diff engine · alerts · reports · API
```

Three outbound channels, each constrained differently:

| Channel | What it reaches | What constrains it |
|---|---|---|
| `net/http.py` | the target | the program scope, re-checked on every redirect |
| `net/sources.py` | public data services | a code-defined allowlist, immutable at runtime |
| `notify/base.py` | your alert endpoint | read from settings, never from scan data |

A test scans the source tree and fails if any other module opens a client.

### What to do next

`reconx next acme` is the part that turns data into a plan. It orders findings
with their escalation steps, points at interesting hosts that have produced
nothing yet, and — most usefully — names the **coverage gaps**: endpoints whose
parameters were found but never tested, hosts discovered but never explored,
stages that have not run in days. A researcher staring at an empty findings list
has nowhere to go; one who knows twenty-three hosts were never content-scanned
does.

## Development

```bash
make test       # pytest
make lint       # ruff
make fmt        # ruff format
```

## License

MIT
