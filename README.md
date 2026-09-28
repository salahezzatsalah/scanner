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
| **WAF state gating** | Whole runs poisoned by block pages read as anomalies |
| **Registration: SSO-boundary test** | Every consumer sign-up page called an auth bypass |
| **Cross-asset correlation** | One issue spammed as 200 separate findings |
| **Evidence or it isn't Confirmed** | Unreproducible findings that waste submissions |

Findings land in tiers — **Confirmed**, **Probable**, **Needs review**, **Discarded**. Only the
first two surface by default. Discarded findings are *kept, with the reason they were dropped*, so
you can audit the filter rather than trust it blindly.

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
reconx scan run acme --wordlist big.txt   # deeper brute force
reconx scan run acme --no-external-tools  # pure Python, ignore installed scanners
reconx scan run acme --resume 42          # pick up an interrupted run

reconx scan run acme --allow-account-creation   # prove a registration bypass (see below)
reconx scan run acme --no-registration          # skip the registration check entirely

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

### Registration that bypasses SSO

An application meant to be reachable only through an identity provider, still shipping an enabled
local `/register`, is an authentication bypass: anyone can mint themselves an account the
organisation never issued. The hard part is that over HTTP it looks exactly like a shop letting
customers sign up, so the check is built around one contradiction rather than the presence of a
form. All three of these must hold:

1. the sign-in page hands off to an identity provider and carries **no local password form**,
2. a local registration form exists anyway, posts same-origin, and sets a password,
3. some area refuses anonymous callers — a redirect to login, a 401 or a 403.

That, reproduced, is **Probable**, and it costs nothing but GETs. An invitation-code field, an
approval notice, a cross-origin form that only hands off to the provider, or a login page that
offers local accounts *and* SSO each end the check with that reason recorded.

**Confirmed requires registering**, because only a session proves the endpoint accepts a stranger:

```yaml
permissions:
  account_creation: true
  test_account_email: "you+reconx@example.com"
```

```bash
reconx scan run acme --allow-account-creation
```

Both are required — the flag alone runs the read-only half and tells you why. One account per host,
plus-addressed under your mailbox and named `ReconX Authorized Test`, never retried and never
re-created for reproducibility. The proof is differential: the area that refused us anonymously must
answer the new session with application content. The address goes in the finding so your report can
ask for it to be deleted.

Whatever that account reaches is scanned for personal data, and **only counts and masked samples are
stored** — `5 distinct telephone numbers, 5 distinct monetary amounts across 5 table rows`, with
`62********01` rather than the number. Values that also appear on the anonymous version of the page
are subtracted first, so a support address in the footer is not a breach. Reaching the page and what
the page holds are reported as two findings, because they are two different fixes.

## How it is built to stay safe

These are structural, not advisory:

- **A scope file is mandatory**, and carries an authorization block. No scan starts without one.
- **`ScopeGuard` is a single chokepoint.** Every DNS query and HTTP request resolves through it.
  A test asserts no network path bypasses it. Out-of-scope patterns override in-scope wildcards.
- **Polite by default.** Per-host token-bucket rate limiting and concurrency caps, tuned low.
- **Intrusive checks are opt-in.** No DoS or stress categories at all. `sqlmap` is constrained to
  non-destructive detection.
- **Writing to a target needs the scope's permission, not a flag.** The one check that can create
  an account refuses unless `permissions.account_creation` is set in the scope file *and*
  `--allow-account-creation` is passed. It creates one account per host, plus-addressed under a
  mailbox you name, and puts the address in the finding so you can ask for it to be deleted.
- **Full audit log.** Every request recorded with a timestamp, so you can show exactly what you
  touched and when.
- **Scope-focused by design.** Built to work one program you are authorized on — not for
  untargeted sweeping, and with no detection-evasion features.

---

## Architecture

```
scope.yaml → ScopeGuard → Orchestrator (dependency-ordered, parallel, resumable)
   ├─ passive_recon ... RDAP registration, DNS records, IP and ASN attribution
   ├─ subdomains ...... passive sources + brute + permutations → wildcard filter
   ├─ resolve_probe ... liveness, tech, TLS → group identical responses
   ├─ ports ........... naabu or a connect scan → exposed-service findings
   ├─ content ......... robots/sitemap, crawl, archives, JS mining → soft-404 filter
   ├─ params .......... parameter discovery + reflection map
   └─ vulns ........... nuclei, SQLi, XSS, takeover, registration bypass
                              ↓
                      VERIFICATION ENGINE
              baseline · WAF state · reproducibility
              differential · two-oracle SQLi · DOM XSS
              SSO-boundary contradiction · redacted data scan
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
