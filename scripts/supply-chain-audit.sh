#!/usr/bin/env bash
# Dependency + secrets audit, the same gate locally and in CI (audit 2026-11
# WS7). Usage:
#
#   scripts/supply-chain-audit.sh [rust|node|python|secrets|all]   (default all)
#
# Policy (one place, so CI and `make audit` cannot drift):
#   rust    `cargo audit` fails on any RUSTSEC vulnerability not ignored in
#           .cargo/audit.toml (warnings for unsound/unmaintained are printed).
#   node    `npm audit --omit=dev` on every package with a lockfile; HIGH or
#           CRITICAL in production deps fails unless the GHSA id is listed in
#           .github/supply-chain/npm-ignore.txt. A package without a lockfile
#           but with registry deps is audited from a temporary lockfile.
#   python  `pip-audit` on python-mcp-demo/requirements.txt (the Python SDK
#           has no third-party dependencies); any vulnerability fails unless
#           listed in .github/supply-chain/pip-ignore.txt.
#   secrets `gitleaks git` over the full history with .gitleaks.toml.
#
# Tools: cargo-audit (`cargo install cargo-audit --locked`), npm, pip-audit
# (`uv tool install pip-audit` or pipx), gitleaks (brew install gitleaks).
# A missing tool fails the matching section rather than silently passing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
MODE="${1:-all}"
FAIL=0

# ids from an ignore file: first token of every non-comment, non-empty line.
ids_from() { grep -vE '^\s*(#|$)' "$1" 2>/dev/null | awk '{print $1}' || true; }

section() { printf '\n==> %s\n' "$*"; }

run_rust() {
  section "cargo audit"
  command -v cargo-audit >/dev/null || { echo "cargo-audit not installed"; return 1; }
  cargo audit
}

# Packages whose production dependency tree is audited. Lockfile-less packages
# with only registry deps get a throwaway lock in a temp dir.
NODE_PACKAGES=(
  wallet-service mcp-demo guestbook-mcp github-mcp wallet
  sdk/mcp-auth sdk/express sdk/js sdk/agent sdk/hono sdk/wallet sdk/gate
  sdk/nextauth sdk/fastify
  examples/rp-quickstart examples/mcp-agent-auth
  prototypes/menubar-wallet/app
)

run_node() {
  command -v npm >/dev/null || { echo "npm not installed"; return 1; }
  local ignore; ignore="$(ids_from .github/supply-chain/npm-ignore.txt | tr '\n' ' ')"
  local pkg dir tmp rc
  for pkg in "${NODE_PACKAGES[@]}"; do
    [ -f "$pkg/package.json" ] || continue
    section "npm audit: $pkg"
    dir="$ROOT/$pkg"
    if [ ! -f "$dir/package-lock.json" ]; then
      if node -e 'const p=require(process.argv[1]);const d=Object.assign({},p.dependencies,p.optionalDependencies);process.exit(Object.keys(d).length&&!Object.values(d).some(v=>/^(file|link):/.test(v))?0:1)' "$dir/package.json"; then
        tmp="$(mktemp -d)"; cp "$dir/package.json" "$tmp/"
        (cd "$tmp" && npm install --package-lock-only --ignore-scripts --no-audit --no-fund --silent)
        dir="$tmp"
        echo "(no lockfile: audited from a temporary lock)"
      else
        echo "(no lockfile and no registry deps or file: deps: skipped)"
        continue
      fi
    fi
    rc=0
    (cd "$dir" && { npm audit --omit=dev --json 2>/dev/null || true; } \
      | NPM_IGNORE="$ignore" PKG="$pkg" node -e '
        let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
          let r; try{ r=JSON.parse(s);}catch{ console.log("npm audit produced no JSON (registry unreachable?)"); process.exit(2);} 
          const ignore=new Set((process.env.NPM_IGNORE||"").split(/\s+/).filter(Boolean));
          const vulns=r.vulnerabilities||{}; let bad=0, shown=0;
          for (const [name,v] of Object.entries(vulns)) {
            const ids=(v.via||[]).filter(x=>typeof x==="object").map(x=>x.url?x.url.split("/").pop():x.source);
            const direct=(v.via||[]).filter(x=>typeof x==="object");
            if (!direct.length) continue;            // transitive marker only
            shown++;
            const gate=(v.severity==="high"||v.severity==="critical");
            const ignored=ids.length&&ids.every(i=>ignore.has(i));
            console.log(`${gate&&!ignored?"FAIL":"    "} ${v.severity.padEnd(8)} ${name}@${v.range}  ${ids.join(",")}${ignored?"  (ignored)":""}`);
            if (gate&&!ignored) bad++;
          }
          if (!shown) console.log("found 0 vulnerabilities");
          process.exit(bad?1:0);
        });') || rc=$?
    [ "$rc" -eq 0 ] || FAIL=1
  done
}

run_python() {
  section "pip-audit: python-mcp-demo/requirements.txt"
  local PA
  if command -v pip-audit >/dev/null; then PA=pip-audit
  elif command -v uvx >/dev/null; then PA="uvx pip-audit"
  else echo "pip-audit not installed"; return 1; fi
  local args=()
  local id; while read -r id; do [ -n "$id" ] && args+=(--ignore-vuln "$id"); done < <(ids_from .github/supply-chain/pip-ignore.txt)
  $PA -r python-mcp-demo/requirements.txt "${args[@]}"
  # sdk/python-mcp-auth: stdlib only (no [project].dependencies); nothing to audit.
}

run_secrets() {
  section "gitleaks (full history)"
  command -v gitleaks >/dev/null || { echo "gitleaks not installed"; return 1; }
  gitleaks git --no-banner --redact=90 --config .gitleaks.toml .
}

case "$MODE" in
  rust)    run_rust ;;
  node)    run_node ;;
  python)  run_python ;;
  secrets) run_secrets ;;
  all)
    run_rust    || FAIL=1
    run_node    || FAIL=1
    run_python  || FAIL=1
    run_secrets || FAIL=1
    ;;
  *) echo "usage: $0 [rust|node|python|secrets|all]" >&2; exit 2 ;;
esac
exit $FAIL
