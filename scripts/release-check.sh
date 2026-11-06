#!/usr/bin/env bash
# Everything that must be green before a commit is submitted for approval
# or deployed: what CI runs, plus what CI does not (the Playwright e2e on a
# fresh broker, the agent SDK and wallet-service suites). Exits non-zero on
# the first failing step and prints one line per step at the end.
#
#   scripts/release-check.sh            # from the repo root, clean tree
#   RELEASE_CHECK_SKIP="supply" scripts/release-check.sh   # space-separated step names to skip (dev only)
#
# On the dev box run it through `ssh localtest` so cargo's test binaries
# are not stalled by Gatekeeper. Needs: cargo, node (with the SDK
# node_modules installed), python3, Playwright browsers in e2e-tests.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
export PATH="$HOME/.cargo/bin:$PATH"
LOGDIR="${RELEASE_CHECK_LOGDIR:-/tmp/release-check}"
mkdir -p "$LOGDIR"
SKIP=" ${RELEASE_CHECK_SKIP:-} "
declare -a RESULTS=()
FAILED=0

step() {
  local name="$1"; shift
  if [[ "$SKIP" == *" $name "* ]]; then RESULTS+=("skip  $name"); return 0; fi
  local log="$LOGDIR/$name.log"
  printf '==> %s\n' "$name"
  if "$@" >"$log" 2>&1; then
    RESULTS+=("ok    $name")
  else
    RESULTS+=("FAIL  $name  (log: $log)")
    FAILED=1
    tail -40 "$log" | sed 's/\x1b\[[0-9;]*m//g'
    return 1
  fi
}

rust_workspace() { cargo test --workspace; }
# The toolchain CI and the Docker image actually build with (Dockerfile
# FROM rust:X). The dev box runs whatever rustup's stable is, which once
# let a dependency that needed a newer compiler pass here and fail CI.
rust_pinned() {
  local v; v="$(sed -nE 's/^FROM rust:([0-9.]+)-.*/\1/p' Dockerfile | head -1)"
  [ -n "$v" ] || { echo "no FROM rust:<version> in Dockerfile"; return 1; }
  grep -q "rust-toolchain@.* # $v" .github/workflows/test.yml || { echo "CI pins a different toolchain than Dockerfile ($v)"; return 1; }
  rustup toolchain install "$v" --profile minimal >/dev/null 2>&1 || rustup toolchain install "$v.0" --profile minimal
  local tc; tc="$(rustup toolchain list | grep -oE "^$v(\.[0-9]+)?-" | head -1 | sed 's/-$//')"
  [ -n "$tc" ] || { echo "toolchain $v not installed"; return 1; }
  echo "building with $tc"
  cargo "+$tc" check --workspace --all-targets --locked
}
rust_conformance() {
  cargo test -p browserid-core --test audit_2026_11_ws2_generate --test audit_2026_11_ws2_runner -- --nocapture &&
  cargo test -p browserid-verifier --test audit_2026_11_ws2_runner -- --nocapture
}
node_suite() { (cd "$1" && node --test ${2:-}); }
python_suite() { (cd sdk/python-mcp-auth && python3 -m unittest discover -s tests); }
supply_chain() { scripts/supply-chain-audit.sh rust && scripts/supply-chain-audit.sh node && scripts/supply-chain-audit.sh python; }

# Playwright against a broker built from THIS tree, started fresh (empty
# database, empty throttle windows) on :3000. Anything already on :3000 is
# stopped first: a warm broker from an earlier run carries throttle state
# that hides or invents failures.
e2e() {
  cargo build -p browserid-broker || return 1
  local bin
  bin="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/browserid-broker"
  pkill -f "debug/browserid-broker" 2>/dev/null; sleep 1
  local work; work="$(mktemp -d)"
  # Started from the repo root (it finds browserid-broker/static relative
  # to cwd), with its database and key in a throwaway directory.
  (DISABLE_SMTP=1 AGENT_PROVISIONING=1 ADMIN_TOKEN=localtest-admin DATABASE_PATH="$work/browserid.db" BROKER_KEY_FILE="$work/broker-key.json" \
    nohup "$bin" >"$LOGDIR/e2e-broker.log" 2>&1 &)
  local i; for i in $(seq 1 60); do curl -sf http://localhost:3000/.well-known/browserid >/dev/null && break; sleep 1; done
  curl -sf http://localhost:3000/.well-known/browserid >/dev/null || { echo "broker did not come up"; return 1; }
  curl -sf http://localhost:3000/include.js >/dev/null || { echo "broker is up but does not serve its static files (started from the wrong directory?)"; pkill -f "debug/browserid-broker"; return 1; }
  local rc=0
  (cd e2e-tests && npx playwright test --reporter=line) || rc=1
  pkill -f "debug/browserid-broker" 2>/dev/null
  rm -rf "$work"
  return $rc
}

step rust-workspace    rust_workspace
step rust-pinned       rust_pinned
step rust-conformance  rust_conformance
step sdk-js            node_suite sdk/js
step sdk-agent         node_suite sdk/agent
step sdk-mcp-auth      node_suite sdk/mcp-auth 'test/*.test.mjs'
step sdk-gate          node_suite sdk/gate 'test/*.test.mjs'
step sdk-nextauth      node_suite sdk/nextauth 'test/*.test.mjs'
step sdk-express       node_suite sdk/express 'test/*.test.mjs'
step sdk-hono          node_suite sdk/hono 'test/*.test.mjs'
step sdk-fastify       node_suite sdk/fastify 'test/*.test.mjs'
step wallet-service    node_suite wallet-service
step python-mcp-auth   python_suite
step supply-chain      supply_chain
step e2e               e2e

# The Python run dirties tracked __pycache__ files; put them back.
git checkout -q -- sdk/python-mcp-auth 2>/dev/null || true

echo
echo "release-check summary ($(git rev-parse --short HEAD)):"
printf '  %s\n' "${RESULTS[@]}"
if [ "$FAILED" = 0 ] && [ -z "$(git status --porcelain)" ]; then
  echo "  tree clean after the run"
elif [ "$FAILED" = 0 ]; then
  echo "  FAIL  the run left the tree dirty:"; git status --short | sed 's/^/    /'; FAILED=1
fi
exit $FAILED
