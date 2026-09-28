#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Install the external scanners ReconX orchestrates.
#
# None of these are required. ReconX has a pure-Python fallback for every
# stage, so it works on a fresh clone and gets faster and broader as tools are
# added. Run `reconx doctor` afterwards to see what landed.
#
# Safe to re-run: `go install` upgrades in place.
# ---------------------------------------------------------------------------
set -uo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
YELLOW=$'\033[33m'; RESET=$'\033[0m'

ONLY="${1:-}"
installed=(); failed=(); skipped=()

say()  { printf '%s\n' "$*"; }
head2() { printf '\n%s%s%s\n' "$BOLD" "$*" "$RESET"; }

# --- prerequisites ---------------------------------------------------------
head2 "Checking prerequisites"

if ! command -v go >/dev/null 2>&1; then
  say "${RED}Go is not installed.${RESET}"
  say "Most of these scanners are Go programs. Install Go 1.21+ from"
  say "  https://go.dev/dl/"
  say ""
  say "${YELLOW}ReconX still runs without them${RESET} using its Python fallbacks."
  say "Run 'reconx doctor' to see what that costs you."
  exit 1
fi
say "  go        $(go version | awk '{print $3}')"

GOBIN_DIR="$(go env GOBIN)"
[ -z "$GOBIN_DIR" ] && GOBIN_DIR="$(go env GOPATH)/bin"
mkdir -p "$GOBIN_DIR"
say "  install   -> ${GOBIN_DIR}"

# --- the catalogue ---------------------------------------------------------
# Keep in step with TOOL_SPECS in src/reconx/tools/registry.py
GO_TOOLS=(
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
  "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "alterx|github.com/projectdiscovery/alterx/cmd/alterx@latest"
  "ffuf|github.com/ffuf/ffuf/v2@latest"
  "gau|github.com/lc/gau/v2/cmd/gau@latest"
  "dalfox|github.com/hahwul/dalfox/v2@latest"
)

head2 "Installing scanners"
for entry in "${GO_TOOLS[@]}"; do
  name="${entry%%|*}"
  pkg="${entry#*|}"

  if [ -n "$ONLY" ] && [ "$ONLY" != "$name" ]; then
    skipped+=("$name")
    continue
  fi

  printf '  %-12s ' "$name"
  if GOFLAGS=-mod=mod go install -v "$pkg" >/tmp/reconx-install-"$name".log 2>&1; then
    printf '%sok%s\n' "$GREEN" "$RESET"
    installed+=("$name")
  else
    printf '%sfailed%s %s(see /tmp/reconx-install-%s.log)%s\n' \
      "$RED" "$RESET" "$DIM" "$name" "$RESET"
    failed+=("$name")
  fi
done

# --- nuclei templates ------------------------------------------------------
if [ -x "${GOBIN_DIR}/nuclei" ]; then
  head2 "Updating nuclei templates"
  if "${GOBIN_DIR}/nuclei" -update-templates -silent >/tmp/reconx-nuclei-templates.log 2>&1; then
    say "  ${GREEN}templates updated${RESET}"
  else
    say "  ${YELLOW}template update failed${RESET} ${DIM}(see /tmp/reconx-nuclei-templates.log)${RESET}"
  fi
fi

# --- tools we do not install for you --------------------------------------
head2 "Not installed by this script"
say "  ${DIM}amass${RESET}   deep enumeration, slow to build:"
say "          go install -v github.com/owasp-amass/amass/v4/...@master"
say "  ${DIM}sqlmap${RESET}  SQLi confirmation (ReconX uses detection mode only):"
say "          pipx install sqlmap"
say "  ${DIM}nmap${RESET}    service/version detection:"
say "          apt install nmap   # or: brew install nmap"

# --- PATH guidance ---------------------------------------------------------
case ":${PATH}:" in
  *":${GOBIN_DIR}:"*) ;;
  *)
    head2 "Add the install directory to your PATH"
    say "  ${GOBIN_DIR} is not on your PATH."
    say "  ReconX looks there anyway, but your shell will not find these tools."
    say ""
    say "    echo 'export PATH=\"\$PATH:${GOBIN_DIR}\"' >> ~/.bashrc"
    say ""
    say "  ${YELLOW}Note:${RESET} if the Python 'httpx' package is installed, its CLI shadows"
    say "  ProjectDiscovery's httpx. Put ${GOBIN_DIR} ${BOLD}first${RESET} on PATH to win."
    ;;
esac

# --- summary ---------------------------------------------------------------
head2 "Summary"
say "  installed: ${#installed[@]}   failed: ${#failed[@]}   skipped: ${#skipped[@]}"
[ ${#failed[@]} -gt 0 ] && say "  ${RED}failed:${RESET} ${failed[*]}"
say ""
say "Next: ${BOLD}reconx doctor${RESET}"

[ ${#failed[@]} -gt 0 ] && exit 1
exit 0
