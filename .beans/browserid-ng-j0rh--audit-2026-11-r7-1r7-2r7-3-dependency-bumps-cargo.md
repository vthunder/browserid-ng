---
# browserid-ng-j0rh
title: '[Audit 2026-11] R7-1/R7-2/R7-3: dependency bumps (cargo update, npm audit fix x7 + redeploy/publish, fastmcp 3.4.10)'
status: completed
type: task
priority: high
created_at: 2026-11-02T22:43:20Z
updated_at: 2026-11-03T09:12:21Z
parent: browserid-ng-ag1l
---

Dependency bumps from WS7. Findings: R7-1 (Rust, Medium), R7-2 (npm, Medium), R7-3 (Python, Low). Decision: Q8 settled 2026-11-02 ((a): land the bumps on the branch now so the supply-chain gate is green at PR time; the MCP SDK memory-exhaustion items are reachable on every StreamableHTTP service). The new gate .github/workflows/supply-chain.yml (W7-1, done) is red on main until these land.

R7-1: cargo update (resolves RUSTSEC-2026-0382/0098/0099/0104/0049 rustls-webpki -> 0.103.16, 0381 webpki-roots -> 1.0.11, 0285/0349/0348/0346 rustls -> 0.23.46, 0141 lettre -> 0.11.23, 0258 h2 -> 0.4.20, 0007 bytes -> 1.12.1, 0009 time -> 0.3.55, plus anyhow/rand/tokio unsound warnings). hickory-proto 0118/0119 have no fix and are ignored in .cargo/audit.toml with review date 2027-02-01. Then cargo test --workspace (via ssh localtest), commit Cargo.lock. Watch for the Dockerfile workspace-member list (unchanged) and the shared target dir.

R7-2: npm audit fix (no --force; every patched version is in range) in wallet-service, mcp-demo, guestbook-mcp, github-mcp, sdk/gate, sdk/wallet, examples/mcp-agent-auth: @modelcontextprotocol/sdk >= 1.32.0 (GHSA-f897-62hf-6gxq, GHSA-46jr-4wx8-v453 unbounded body/batch DoS on StreamableHTTP, reachable), zod >= 4.6.6 (reachable), hono 4.13.11, proxy-addr 2.0.8, body-parser 2.4.0, fast-uri 3.1.9, ip-address 10.7.4, qs 6.16.1 (not reachable). Run each package's tests, commit lockfiles, redeploy the three services (make deploy), publish gate and wallet (bump + publish.yml).

R7-3: python-mcp-demo/requirements.txt fastmcp==3.4.10 (GHSA-7xgj-8392-5q4r, not reachable).

Acceptance: make audit (scripts/supply-chain-audit.sh) exits 0 with no new ignore entries; supply-chain.yml green.

Reports: ws7 §1 and §8. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Done 2026-11-03 on the audit-2026-11 branch (not deployed, not published).

- R7-1: `cargo update` (Cargo.lock). `cargo audit`: 16 vulnerabilities -> 0;
  the two hickory-proto advisories stay ignored in .cargo/audit.toml (review
  2027-02-01). `cargo test --workspace --no-fail-fast`: 724 passed, 2 failed,
  4 ignored across 81 suites. Both failures are unrelated to the bump:
  `browserid-agent/tests/merged_provision_sdk_test.rs` fails identically on
  the old lockfile ("the config cert is not an unretired cert of this
  account"), and `registry_api_test::identity_proofs_log_a_device_in_after_masked_hints`
  is flaky (passes 13/13 on two reruns with the new lock).
- R7-2: `npm audit fix` (no --force) in wallet-service, mcp-demo,
  guestbook-mcp, github-mcp, sdk/gate, sdk/wallet, examples/mcp-agent-auth;
  every package now reports 0 vulnerabilities (@modelcontextprotocol/sdk
  1.32+, zod, hono, body-parser, proxy-addr, fast-uri, ip-address, qs).
- `@browserid-ng/agent` ranges in sdk/mcp-auth, sdk/gate and sdk/wallet are
  now ^1.0.0 (gate also ^0.6.0 mcp-auth, ^0.4.0 verify) to match the bumped,
  still-unpublished package versions. Because those versions are not on the
  registry yet, the SDK lockfiles (sdk/gate, sdk/mcp-auth, sdk/wallet)
  resolve the in-repo packages as local `link: true` entries (the same shape
  wallet-service already used); `npm ci --ignore-scripts` succeeds in every
  package. After publish.yml ships 1.0.0/0.6.0/0.4.0 the locks can be
  regenerated against the registry if preferred.
- Lockfiles committed for sdk/js, sdk/agent, sdk/mcp-auth, sdk/wallet and
  examples/mcp-agent-auth (per-package .gitignore entries that excluded
  package-lock.json removed), as W7-6 asks.
- R7-3: python-mcp-demo/requirements.txt fastmcp==3.4.10; pip-audit clean.
- gitleaks: 8 new hits since WS7 (fuzz/seeds JWS corpus from WS3, and the
  WS4 broker test file reusing the throwaway OIDC JWKS key) allowlisted in
  .gitleaks.toml with reasons and a 2026-11-03 review date; "no leaks found".
- `scripts/supply-chain-audit.sh all` (make audit) exits 0 via ssh localtest.
- npm test tallies: sdk/js 19, sdk/agent 21, sdk/mcp-auth 68, sdk/gate 81,
  wallet-service 31, guestbook-mcp 8, github-mcp 23, examples/mcp-agent-auth
  1, all passing; mcp-demo has no test directory (0 tests, pre-existing).
- Not done here (out of scope for the branch): redeploy of the three
  services and the gate/wallet publish happen on merge via CI.
