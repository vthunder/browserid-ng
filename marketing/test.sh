#!/usr/bin/env bash
# Smoke test for the marketing site's agent-facing nginx behavior. Builds the
# real image and asserts the contract the Ora "Is Agentic" audit checks:
#   - markdown 404 with recovery links (real 404 status, text/markdown body)
#   - Accept: text/markdown content negotiation with Vary: Accept
#   - /openapi.json (valid JSON, CORS-open)
#   - structured JSON errors on /api/*
#   - llms.txt / robots.txt / sitemap.xml discoverability
#
# Usage: ./test.sh [existing-base-url]
#   With no argument: builds marketing/Dockerfile, runs it on an ephemeral
#   port, tests it, tears it down. With an argument (e.g.
#   https://www.browserid.me): tests that deployment instead.
set -euo pipefail
cd "$(dirname "$0")"

BASE="${1:-}"
CONTAINER=""
cleanup() { [ -n "$CONTAINER" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if [ -z "$BASE" ]; then
  docker build -q -t browserid-www-test . >/dev/null
  CONTAINER=$(docker run -d -p 127.0.0.1:0:80 browserid-www-test)
  PORT=$(docker port "$CONTAINER" 80 | head -1 | sed 's/.*://')
  BASE="http://127.0.0.1:$PORT"
  # nginx needs a beat to come up.
  for _ in $(seq 1 50); do
    curl -sf -o /dev/null "$BASE/" && break
    sleep 0.2
  done
fi

PASS=0; FAIL=0
check() { # check <desc> <actual> <expected-grep-ere>
  local desc="$1" actual="$2" expected="$3"
  if grep -qE "$expected" <<<"$actual"; then
    PASS=$((PASS+1)); echo "ok   - $desc"
  else
    FAIL=$((FAIL+1)); echo "FAIL - $desc"; echo "       wanted /$expected/, got: $(head -c 300 <<<"$actual")"
  fi
}

# --- agent-friendly 404 -----------------------------------------------------
check "404 status on unknown path" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/some-path-that-does-not-exist")" '^404$'
check "404 body is markdown with recovery links" \
  "$(curl -s "$BASE/some-path-that-does-not-exist")" 'llms\.txt'
check "404 content-type is text/markdown; charset=utf-8" \
  "$(curl -s -o /dev/null -w '%{content_type}' "$BASE/some-path-that-does-not-exist")" \
  '^text/markdown; charset=utf-8$'

# --- markdown content negotiation (acceptmarkdown.com) ----------------------
for page in / /developers /domains /demos /gate /mcp-demo; do
  check "markdown negotiation on $page" \
    "$(curl -s -o /dev/null -w '%{content_type}' -H 'Accept: text/markdown' "$BASE$page")" \
    '^text/markdown; charset=utf-8$'
done
# nginx's charset directive always covers text/html too, so HTML now carries
# an explicit (correct) charset.
check "HTML still default on /" \
  "$(curl -s -o /dev/null -w '%{content_type}' "$BASE/")" '^text/html(; charset=utf-8)?$'
check "Vary: Accept on / (html)" \
  "$(curl -s -D- -o /dev/null "$BASE/" | tr -d '\r' | grep -i '^vary:')" 'Accept'
check "Vary: Accept on / (markdown)" \
  "$(curl -s -D- -o /dev/null -H 'Accept: text/markdown' "$BASE/" | tr -d '\r' | grep -i '^vary:')" 'Accept'
check "Vary: Accept on /developers (html)" \
  "$(curl -s -D- -o /dev/null "$BASE/developers" | tr -d '\r' | grep -i '^vary:')" 'Accept'
check "markdown body is the page, not an error" \
  "$(curl -s -H 'Accept: text/markdown' "$BASE/developers")" '^# BrowserID for developers'

# --- OpenAPI ----------------------------------------------------------------
check "/openapi.json is 200 application/json" \
  "$(curl -s -o /dev/null -w '%{http_code} %{content_type}' "$BASE/openapi.json")" \
  '^200 application/json$'
check "/openapi.json parses and is OpenAPI 3.x" \
  "$(curl -s "$BASE/openapi.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["openapi"])')" '^3\.'
check "/openapi.json is CORS-open" \
  "$(curl -s -D- -o /dev/null -H 'Origin: https://x.example' "$BASE/openapi.json" | tr -d '\r' | grep -i '^access-control-allow-origin:')" '\*'

# --- JSON errors on API-shaped paths ----------------------------------------
check "/api/* returns JSON 404" \
  "$(curl -s -o /dev/null -w '%{http_code} %{content_type}' "$BASE/api/anything")" \
  '^404 application/json$'
check "/api/* error body is structured" \
  "$(curl -s "$BASE/api/anything" | python3 -c 'import json,sys; e=json.load(sys.stdin)["error"]; print(e["code"], bool(e["message"]), bool(e["hint"]))')" \
  '^not_found True True$'

# --- discoverability --------------------------------------------------------
check "llms.txt served" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/llms.txt")" '^200$'
check "llms.txt names the product and the OpenAPI spec" \
  "$(curl -s "$BASE/llms.txt")" 'BrowserID'
check "llms.txt links openapi.json" "$(curl -s "$BASE/llms.txt")" 'openapi\.json'
check "robots.txt served with sitemap" "$(curl -s "$BASE/robots.txt")" 'Sitemap:'
check "sitemap.xml served" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/sitemap.xml")" '^200$'
check "page titles carry the product name" "$(curl -s "$BASE/")" '<title>BrowserID'

# --- existing behavior preserved --------------------------------------------
check "clean URL /developers still serves HTML" \
  "$(curl -s -o /dev/null -w '%{http_code} %{content_type}' "$BASE/developers")" '^200 text/html(; charset=utf-8)?$'
check "/agents still 301s to /" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/agents")" '^301$'
check "/guestbook still 301s to /#guestbook" \
  "$(curl -s -o /dev/null -w '%{redirect_url}' "$BASE/guestbook")" '#guestbook$'
check "config.js still no-cache" \
  "$(curl -s -D- -o /dev/null "$BASE/config.js" | tr -d '\r' | grep -i '^cache-control:')" 'no-cache'

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
