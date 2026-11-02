---
# browserid-ng-kgjr
title: 'Spec edits accepted from audit WS1: S1 S2 S5 S6 S9 S10 S13'
status: in-progress
type: task
priority: high
created_at: 2026-11-01T18:45:03Z
updated_at: 2026-11-02T10:26:50Z
parent: browserid-ng-ag1l
---

Spec changes Dan accepted 2026-11-01 from docs/security-audit-2026-11-ws1-spec-review.md §2. Spec first; code follows in the owning workstream.

- [x] S1 (spec done d221cb3) registry-api-v1 §4.2: login_page delivers the token only to an accepted return origin (loopback, custom scheme, issuer-trusted web wallets), enforced in the token-issuing handler; or bind the token to the opener's login-key pubkey. Code: WS5.
- [x] S2 (spec done d221cb3) one identity-comparison rule in core §5 (domain lowercased A-label, local part byte-exact); registry-api-v1 §2 references it instead of 'compare after lowercasing'. Code: D17 in WS4.
- [x] S5 (spec done d221cb3) core §4.7/§6.1 step 7: absent an implementation, any constraints claim rejects; define that a scopes allowlist applies to scope-less login warrants as []. Name conforming verifiers.
- [x] S6 (spec done d221cb3) core §6.1 steps 3/6 and §6.3: require iat <= exp and iat <= now + skew on every cert, warrant, assertion, and status list. Code: D16 in WS6/WS3.
- [x] S9 (spec + warrant.json done d221cb3; wallet/server regex convergence is code, WS4) one scope grammar, in registry-api-v1 §3, matching shipped SBO scope names (/ * @ +, <=128 bytes); update request-kinds/warrant.json; wallet and server regexes converge. 
- [x] S10 (spec done d221cb3) registry-api-v1 §5.2.4 restore path: when another account holds the identity, require confirm_takeover and a fresh config cert, matching §2/§5.2.1. Code: WS5.
- [x] S13 (done d221cb3) editorial pass: assertion typ, resolver transport failure in §3, cert ref uri host == iss in §6.3, PUT vs POST, claim of agent code, binding_id minting point, holder_mismatch name collision, §8 rule 1 wording, refless v1 revocation note in §6.4 1e.

- [x] S3 spec side done d221cb3; code steps (1)-(4) remain, routed WS2/WS6 — (decided 2026-11-01): drop v1 warrants, no sunset. Spec §5: remove the v1 compatibility paragraph; §6.1 step 1 and §6.4 1a accept only browserid-warrant-v2. Code order: (1) switch login-warrant signers to v2 + holder binding + allocate_status ref: broker static/dialog.js:796, wallet/src/login.js:29, wallet/src/mediator.js:53, scripts/e2e/smoke-prod-dc.mjs:58, prototypes/menubar-wallet/app/ceremony.js:238; (2) verifiers reject v1 (core device.rs TYP_WARRANT + v1 sugar at ~1145, hosted /verify, sdk/js, python, mcp-auth, gate); (3) regenerate test-vectors/device-cert-v1.json; (4) run Playwright locally (CI does not run e2e) before deploying dialog.js. Removes S3's unrevocable-record risk and closes D-class refless-v1 note in §6.4.

- [x] S4 spec side done d221cb3; code in WS6 (D15) — (decided 2026-11-01): NO RP-side registry allowlist (keeps registries permissionless). Core §6.3: (a) the §7.5 safe-fetch rules apply to every status-list fetch (no redirects, public unicast only, bounded size/time, fail-closed); (b) a status list at uri is valid only when signed by the DNSSEC-published key of uri's host. Code: browserid-rp status path (D15) and registrar validity bar must enforce (b); hosted verifier already does.

- [x] S7 spec side done d221cb3 (core §5 + warrant.json); code (D7 etc.) in WS6/WS4; browserid-pay bean still to create — (decided 2026-11-01): core §5 = generic parameter mechanism only (object entries, scope-string identity, stricter-wins, enforcing-role column, relay pass-through verbatim or reject, enforcers fail closed on own class, unknown-class params refused by all) + the single core parameter mode (wallet-enforced). Remove cap/counterparties/max_duration/min_reputation definitions from core §5; §6.1 step 9 returns scope ENTRIES verbatim. Code: core device.rs parser name-agnostic (keep shape validation + verbatim pass-through); hosted /verify and /validate-record return entries (D7); sdk/js, python, mcp-auth, gate surface entries; wallet label table sourced per scope family. Follow-up in ~/src/browserid-pay: write the pay-parameters spec (audience-enforced, orders, custodian checks) — create that bean in the pay repo when starting.

- [ ] S8 spec side done d221cb3; REMAINING: stale code comments api.rs:62,165 and registrar_glue.rs:1052 (deferred until WS5 agent finishes touching registrar) — (decided 2026-11-01, doc drift confirmed: /api/v1/token deleted deliberately in a8337d1, devices/register merged into attach): rewrite fallback-idp-api-v1 §4 as accounts/login/attach, fix the §3.3 and §7 decision-5 pointers; update stale comments naming devices/register in browserid-registrar/src/api.rs:62,165 and browserid-broker/src/registrar_glue.rs:1052.

- [x] S11 spec side done d221cb3; code rides with WS5 — (decided 2026-11-01, low): answer identically whether or not the thing exists. registry-api-v1 §5.2.8: at the open-approvals cap return the same 200 shape as an unknown account (never approve); code: the 'login key on another account' refusal in registrar account.rs:266-274 becomes a generic refusal. Code side rides with WS5.
