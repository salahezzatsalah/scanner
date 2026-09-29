# Working on ReconX

Notes for anyone — person or agent — changing this codebase. They are the
things that were learned the hard way here, not a restatement of the README.

## What this project is

Reconnaissance and vulnerability verification for **authorized** security
research: bug bounty programs and engagements where someone has given permission.
Scope enforcement is not a feature bolted on the side; it is the reason the
architecture looks the way it does.

## The two rules that shape everything

### 1. Nothing reaches the network without passing the guard

`ScopeGuard` (`src/reconx/scope/guard.py`) is the single chokepoint.
`ScopedHttpClient.__init__` **requires** a guard and raises `TypeError` without
one, so "everything is scope-checked" is structural rather than a convention
someone might forget. Redirects are re-checked at every hop, because otherwise a
target could walk the scanner off-scope with a 302.

There are exactly **four** ways out to the network, and a test asserts there is
no fifth (`test_no_module_reaches_the_network_around_the_guard`):

| Channel | Reaches | Enforced by |
|---|---|---|
| `net/http.py` | the target | `ScopeGuard`, per request and per redirect hop |
| `net/dns.py` | resolvers | `ScopeGuard` on the name, or on the **address** for a PTR |
| `net/sources.py` | intelligence sources | a code-defined `SOURCE_ALLOWLIST`, so a target can never be reclassified as a source |
| `monitor/notify.py` | the operator's own alert destinations | destinations come from settings only, never from scan data |

Adding a fifth channel means changing that test deliberately and saying why. If
you find yourself reaching for `httpx` directly in a stage or a verifier, that is
the signal you are about to make a mistake.

The `.arpa` exemption in `ScopedResolver.reverse` is the one place a query name is
not itself checked, and the docstring states why: the authorization check is on
the **address**, and `4.3.2.1.in-addr.arpa` is the mechanism for asking about it,
not a host being tested.

### 1b. Traffic that reaches a target is attributable

A program that permits automated testing almost always also requires the traffic
to be identifiable, so it can tell research from an attack. `RECONX_USER_AGENT`
(and `RECONX_IDENTITY_HEADER`, for a program that wants its own header name) is
carried by ReconX's own client **and** by every external tool that speaks HTTP to
the target — injected once in `ToolRunner.run` from `ToolSpec.identity_header_args`.

Marking a tool in that field is a statement that its traffic reaches the target.
`subfinder`, `amass`, `gau` and `dnsx` are deliberately *not* marked: they ask
third-party sources about the target rather than asking the target, so handing them
a researcher handle announces it to crt.sh and VirusTotal, who are not in the
program. `naabu` and `nmap` speak TCP and have no headers. A test asserts both the
presence and the absence, and another asserts the flag reaches the executed argv
rather than only the accessor.

### 2. Two independent oracles, or it is not Confirmed

`decide_from_oracles` in `src/reconx/verify/base.py` is the verification standard,
in one function, shared by every class:

- **two independent oracles agree**, each reproduced → Confirmed
- one **decisive** oracle → Probable
- one **strong** oracle → Probable, lower confidence
- one **weak** oracle (timing) → Needs review, never better
- none → Discarded, **with the reason kept**

"Independent" is the load-bearing word. Two views of the same observation is one
oracle wearing two hats. `XssVerifier` deliberately does *not* use this function,
and its `_decide` says why: reflection, escape analysis and execution gate each
other in sequence, so counting them as votes would confirm on one fact seen three
times.

A discarded finding keeps its `discard_reason` so the filter can be audited
instead of trusted. That is the difference between a scanner you can defend and
one you hope is right.

## Adding a vulnerability class

1. **A new module in `src/reconx/verify/`**, subclassing `ParameterVerifier`
   (`verify/base.py`). You get one `fetch` that records failures instead of
   swallowing them, one WAF gate, `ParamTarget` for query/form/JSON/header/cookie
   parameters, typed `Evidence`, and the decision function.
2. **Two independent oracles.** Use `DifferentialOracle`
   (`verify/differential.py`) for payload-versus-control, which is what most
   classes need. Give each one a control that is *structurally similar and
   harmless*: the control failing is what makes the payload succeeding mean
   something.
3. **A real case AND a trap in `tests/fixtures/target_app.py`.** This is not
   optional. A verifier that says yes is easy; the entire value of this project is
   in the ones that say no, and nothing has shown a class can say no until it has
   rejected something. Every trap in that fixture is a finding another scanner
   reports.
4. **A test per class** asserting: the real case reaches Confirmed with both
   oracles named; the trap is Discarded and the test checks the **reason text**,
   not just the tier; a blocked host yields Needs review.
5. **A row in `PARAMETER_CHECKS`** (`stages/vulns.py`), with a `selects` predicate
   that spends the expensive checks where they pay.
6. **A playbook entry in `triage/recommend.py`.** A test asserts every reported
   class has guidance.

## Payload conduct

These are in the code and its docstrings because they are constraints, not
preferences:

- **Command injection** uses read-only markers only: shell arithmetic (spawns no
  process), `expr` (computes and exits), and optionally `sleep`. Nothing writes,
  deletes, opens a shell, reads a file or reaches the network. A test asserts the
  payload table contains none of those tokens.
- **Path traversal** reads only well-known files with a machine-checkable record
  *format*, to prove the boundary is crossed. It does not enumerate the
  filesystem or copy contents into a report.
- **SSRF's collaborator is local.** It binds loopback, is off by default, and
  there is no setting pointing it at a hosted interaction service — using one
  publishes the target's hostnames to a third party outside the program. The
  honest limitation is stated in `verify/collaborator.py`: against a remote target
  it needs an address that target can reach, and a quiet loopback listener is not
  evidence that a parameter is safe.
- **nuclei** runs with `-exclude-tags dos,fuzz,intrusive,stress`. Availability is
  not ours to spend.
- Rate limits default low. A program's own stated limit goes in the scope file's
  `limits` block and wins over the global configuration.

## Things that will bite you

- **SQLite is a single writer.** Stages are serialised when `database_url` starts
  with `sqlite` (`Orchestrator._serialize_stages`), because a stage holds a write
  transaction for its whole duration. WAL and `busy_timeout` reduce the problem;
  they do not remove it. Each stage gets its own session.
- **A stage that returns early skips the work after it.** Installing katana once
  made the scanner find *less*, because the katana path returned before form
  extraction ran. `_harvest_html` is shared by both paths for that reason.
- **`load_wordlist` falls back silently; `resolve_wordlist` does not.** A typo in
  a path to SecLists otherwise looks exactly like a successful scan with ten
  thousand fewer requests. Use `resolve_wordlist` and surface the note.
- **`python-httpx` shadows ProjectDiscovery's `httpx` on PATH.** Tool detection
  verifies identity with `identity_pattern` and `find_binaries` enumerates every
  candidate; `ensure_available()` is mandatory before `run()`.
- **The test suite must not read your `.env`.** An autouse fixture in
  `tests/conftest.py` disables it. A locally configured webhook silently changed
  three test outcomes before that existed.
- **Do not follow redirects while testing a redirect or an SSRF.** An open-redirect
  endpoint pointed at the SSRF collaborator satisfied both SSRF oracles with the
  scanner's own traffic. Fixed in two places: the probe does not follow hops, and a
  callback carrying ReconX's user agent is discarded. There is a regression test.

## Per-program configuration

The scope file is the one artefact that travels with a program, and every entry
point reads it. Tuning belongs in its `scan_options` block (`scope/model.py`), not
in CLI flags alone: flags cannot reach a scan nobody is typing, which is why a
monitored program was previously untunable. `Orchestrator._stage` builds stages
from that block via `build_stage`, so the CLI, the REST API and the scheduler all
produce the same scan.

## Running things

```bash
make test-fast   # the gate: about a minute, skips end-to-end
make test        # everything, about three minutes
make lint        # ruff check (there is no format gate; see .github/workflows/ci.yml)
make doctor      # which external tools are installed
```

The end-to-end tests run a local target on 127.0.0.1 with known answers and
assert both halves: the real bugs are found, and the traps are rejected with the
right reason. If you change a verifier, that is the test that tells you whether
you changed it for the better.

## What has not been proven

Everything here is validated against a fixture whose answers were written
alongside the code. That is a weaker claim than working in the field, and it
should stay written down until someone has run it against a program they are
enrolled on. Scanning behind a login is not implemented at all; `verify/xss.py`'s
browser context and `stages/vulns.py`'s curl reproductions are the two places that
would need explicit work beyond client-level headers.
