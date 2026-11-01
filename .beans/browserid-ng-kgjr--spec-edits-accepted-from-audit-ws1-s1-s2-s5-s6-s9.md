---
# browserid-ng-kgjr
title: 'Spec edits accepted from audit WS1: S1 S2 S5 S6 S9 S10 S13'
status: todo
type: task
priority: high
created_at: 2026-11-01T18:45:03Z
updated_at: 2026-11-01T18:50:01Z
parent: browserid-ng-ag1l
---

Spec changes Dan accepted 2026-11-01 from docs/security-audit-2026-11-ws1-spec-review.md §2. Spec first; code follows in the owning workstream.

- [ ] S1 registry-api-v1 §4.2: login_page delivers the token only to an accepted return origin (loopback, custom scheme, issuer-trusted web wallets), enforced in the token-issuing handler; or bind the token to the opener's login-key pubkey. Code: WS5.
- [ ] S2 one identity-comparison rule in core §5 (domain lowercased A-label, local part byte-exact); registry-api-v1 §2 references it instead of 'compare after lowercasing'. Code: D17 in WS4.
- [ ] S5 core §4.7/§6.1 step 7: absent an implementation, any constraints claim rejects; define that a scopes allowlist applies to scope-less login warrants as []. Name conforming verifiers.
- [ ] S6 core §6.1 steps 3/6 and §6.3: require iat <= exp and iat <= now + skew on every cert, warrant, assertion, and status list. Code: D16 in WS6/WS3.
- [ ] S9 one scope grammar, in registry-api-v1 §3, matching shipped SBO scope names (/ * @ +, <=128 bytes); update request-kinds/warrant.json; wallet and server regexes converge. 
- [ ] S10 registry-api-v1 §5.2.4 restore path: when another account holds the identity, require confirm_takeover and a fresh config cert, matching §2/§5.2.1. Code: WS5.
- [ ] S13 editorial pass: assertion typ, resolver transport failure in §3, cert ref uri host == iss in §6.3, PUT vs POST, claim of agent code, binding_id minting point, holder_mismatch name collision, §8 rule 1 wording, refless v1 revocation note in §6.4 1e.

- [ ] S3 (decided 2026-11-01): drop v1 warrants, no sunset. Spec §5: remove the v1 compatibility paragraph; §6.1 step 1 and §6.4 1a accept only browserid-warrant-v2. Code order: (1) switch login-warrant signers to v2 + holder binding + allocate_status ref: broker static/dialog.js:796, wallet/src/login.js:29, wallet/src/mediator.js:53, scripts/e2e/smoke-prod-dc.mjs:58, prototypes/menubar-wallet/app/ceremony.js:238; (2) verifiers reject v1 (core device.rs TYP_WARRANT + v1 sugar at ~1145, hosted /verify, sdk/js, python, mcp-auth, gate); (3) regenerate test-vectors/device-cert-v1.json; (4) run Playwright locally (CI does not run e2e) before deploying dialog.js. Removes S3's unrevocable-record risk and closes D-class refless-v1 note in §6.4.

- [ ] S4 (decided 2026-11-01): NO RP-side registry allowlist (keeps registries permissionless). Core §6.3: (a) the §7.5 safe-fetch rules apply to every status-list fetch (no redirects, public unicast only, bounded size/time, fail-closed); (b) a status list at uri is valid only when signed by the DNSSEC-published key of uri's host. Code: browserid-rp status path (D15) and registrar validity bar must enforce (b); hosted verifier already does.
