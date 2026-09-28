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

reconx scan history acme
reconx assets list acme --live
reconx findings list acme --tier confirmed
reconx findings list acme --tier discarded   # audit what the filter rejected
reconx report acme -o report.md
```

`scope validate` and `scope test` send no traffic at all, so you can check a
scope before you trust it. `scope test` exits non-zero if any target you name is
out of scope, which makes it usable in a script.

### 3. Run it continuously

```bash
reconx serve            # worker + scheduler + API in one local process
```

Cadences are per program and per stage (liveness hourly, subdomain enumeration daily, full vuln
sweep weekly — all configurable). The diff engine watches for **new subdomain, new open port, new
endpoint, new finding** and notifies you. On a wildcard program, being first to see a new asset is
the highest-value thing this tool does for you.

Set any of `RECONX_DISCORD_WEBHOOK`, `RECONX_SLACK_WEBHOOK`, `RECONX_TELEGRAM_BOT_TOKEN`, or
`RECONX_GENERIC_WEBHOOK` in `.env` to get alerts.

---

## How it is built to stay safe

These are structural, not advisory:

- **A scope file is mandatory**, and carries an authorization block. No scan starts without one.
- **`ScopeGuard` is a single chokepoint.** Every DNS query and HTTP request resolves through it.
  A test asserts no network path bypasses it. Out-of-scope patterns override in-scope wildcards.
- **Polite by default.** Per-host token-bucket rate limiting and concurrency caps, tuned low.
- **Intrusive checks are opt-in.** No DoS or stress categories at all. `sqlmap` is constrained to
  non-destructive detection.
- **Full audit log.** Every request recorded with a timestamp, so you can show exactly what you
  touched and when.
- **Scope-focused by design.** Built to work one program you are authorized on — not for
  untargeted sweeping, and with no detection-evasion features.

---

## Architecture

```
scope.yaml → ScopeGuard → Orchestrator (asyncio DAG, resumable, rate limited)
   ├─ passive recon ... WHOIS/RDAP, DNS, cert transparency, ASN
   ├─ subdomains ...... passive + brute + permutations → wildcard-DNS filter
   ├─ resolve/probe ... dnsx + httpx → dedupe by response fingerprint
   ├─ ports ........... naabu
   ├─ content ......... katana, historical URLs, JS parsing, ffuf → soft-404 filter
   ├─ params .......... parameter mining + reflection map
   └─ vulns ........... nuclei, SQLi/XSS candidates, takeover
                              ↓
                      VERIFICATION ENGINE
                              ↓
        Triage + recommendations · diff engine · alerts · reports
```

See `src/reconx/` for the module layout and `docs/` for details.

## Development

```bash
make test       # pytest
make lint       # ruff
make fmt        # ruff format
```

## License

MIT
