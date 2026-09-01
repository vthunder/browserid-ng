---
# browserid-ng-0c49
title: Build registry-api-v1 §5.6 account membership (attach/detach/transfer cascade)
status: todo
type: feature
priority: normal
created_at: 2026-08-30T18:01:42Z
updated_at: 2026-09-01T22:32:43Z
parent: browserid-ng-9yyk
---

THE RESUME POINTER for the account-membership thread (Dan asked 2026-08-30). Spec is SETTLED — registry-api-v1 §5.6 (synchronous attach/detach with inline browserid-membership-v1 records, transfer-on-proof with loser notification, revoke-and-drop of derived agent children) + §7.1 reasons + §10.8 decision log; design history and parity table live on bean 1sb3; reset-channel mitigations are bean dksx (explore separately).

Implementation checklist:
- [ ] Registrar: POST /api/v1/account/attach + /api/v1/account/detach; membership-record validation (config-cert bar, grantor ownership, subject match, ≤300s window, jti replay cache)
- [ ] Transfer cascade (shared core): hg2j-scoped cert revocation at the loser + grantor-warrant revocation + derived-agent revoke-and-drop (this also FIXES a93p for the shipped cookie transfer arms — wire them through the same core) + kind:'notice' inbox item + out-of-band notify SHOULD + emptied-account deletion
- [ ] Host/store capabilities: identity ownership moves, agent-children enumeration, notice items in the inbox shape (§5.1)
- [ ] Wallet: bootstrap flow gains 'add to existing account' — when the wallet already holds an anchor, second-identity bootstrap calls attach instead of letting the token exchange mint a parallel account; sign the membership record with the anchor config key
- [ ] Dialog/account page: per Dan's Q6 ruling the account-page email UI invokes the WALLET which talks to the registry — sequence with 71vt (blocked on 71vt's account/consent routing decision landing as implementation)
- [ ] Deployment note dksx-lite: ensure registry-attached rows don't silently join the reset-eligible set (full mitigation design in dksx)
- [ ] Tests: registry_api_test coverage for attach/detach/transfer incl. record replay, last_identity, agent-children cascade, no-existence-leak; SqliteStore test for the membership moves (memory-store rule)

Blocked-by: nothing hard; touches a93p (fixes it). Related: 71vt (surface retirement), dksx (reset hardening), 1sb3 (design record).

## Spec-patch rulings (Dan, 2026-09-01 discussion)

Agreed, pending the r3 spec patch:
1. Membership record DELETED. Instead the §3.2 request proof gains a body-hash claim; the proof (already signed per-call by the config cert the token was minted from) becomes the signed consent artifact for attach/detach. Kills browserid-membership-v1, grantor/subject/subject_config_key, record_* reasons, jti record cache.
2. register + attach take `certs: [<JWS>...]` (each cert self-describes flavor via purpose). No more device_cert/config_cert wire fields; pair-holder check dissolves. Single-flavor issuance (e.g. short-lived auth-only cert for shared computers) is supported policy.
3. POSSESSION REQUIRED (Dan ruling): the certs array carries { cert, proof } pairs — proof = the §3.2 request-proof shape signed by the cert's own key. Self-authenticating both directions (token+proof = account control; per-cert proof = cert control). Kills the RP-replay transfer attack. Freshness (iat ≤ ~300s on transfer-triggering certs) kept as defense in depth (fences a key-thief holding stale loot).
4. Terminology sweep: 'device cert' is the umbrella per core §4.1 (auth cert / config cert are flavors); no 'anchor' as account property — any identity's token can drive membership calls (all emails equal).
5. Condensation pass (~50%) as separate commit after semantic patches.
6. Auth-only devices (shared computer), CORRECTED per Dan 2026-09-01: the common flow is wildcard-holder warrants — trusted device signs+registers warrants matched to the account's browsers.* prefix; an auth-only device presents them with its own access cert (verifier matches holder). Works today via the dialog's cookie lane; MUST keep working. Phone-in-the-loop consent is only the optional fallback for un-warranted sites, not the primary flow.
6b. GAP: the token lane has no warrant-fetch path for auth-only devices (reads need a token, token needs a config cert). r3 adds a warrant-read endpoint authenticated by a possession-signed request from the auth cert (serves warrants whose holder matcher covers the cert's holder — same artifacts RPs already see). Device row recorded at first possession-proven contact (this fetch), not at consent approval. Never-used certs stay issuer-side; cert revocation is issuer-side regardless.
7. Consistency gap found 2026-09-01: /warrant/request (WarrantRequestBody, consent.rs:1271) accepts bare cert bytes with no possession signature — apply ruling 3 there too (fold into r3 or follow-up).

## Merged attach design (Dan + discussion, 2026-09-01, supersedes items 1-3/6 shapes above)

- register + §5.6.1 attach MERGE into one cert-authenticated endpoint, NO token: { account: <routing email>, certs: [{cert, proof}...] }; every proof = §3.2 request-proof shape signed by that cert's key; routing identity must belong to a possession-proven cert in the call.
- TWO-TIER AUTHORITY RULE (closes the stolen-auth-cert escalation: attacker attaches their own config cert to victim account -> mints account-wide token): cert identity already owned by routing account -> RECORDING, auth-cert possession suffices (grant-free; the shared-computer self-attach). Identity not owned (join/transfer) or account creation -> MEMBERSHIP CHANGE, requires config-cert possession from the routing account. purpose:authorization is the boundary marker.
- Account creation: only when array includes a config cert FOR the routing identity; else error (no surprise accounts).
- §3.1 token exchange STOPS auto-creating accounts — errors on never-seen identity ('attach first'). Kills the parallel-account trap structurally.
- detach: same cert-signed auth, config required.
- Transfer cascade, freshness (~300s), no-existence-leak on transfer vs new: unchanged.
- CONFIRMED by Dan 2026-09-02, with one amendment: the 'account' routing field is redundant — the header proof's signer (matched against the array's certs) routes the call; signer's cert must be in the array. r3 SPEC PATCH DRAFTED 2026-09-02 (registry-api-v1.md, uncommitted): §3.1 no-auto-create + no_account reason, §3.2 bh claim + possession-proof shape (shared jti rule), §5.3 register deleted, §5.6 rewritten flows-first (attach/transfer/detach/warrants-fetch/auth-only matrix), §7.1 reasons reworked, §8 invariants 2+7, §9 mapping, §10 decision 9. NOTE: the implementation checklist at the top of this bean predates r3 and needs rewriting after Dan reviews the spec patch (no membership record, no registrar attach-with-record endpoint; certs+proofs arrays instead). Condensation pass DONE 2026-09-02 (same working tree as the r3 semantic patch, uncommitted): 1030→627 lines, prose −42% while ADDING all decision-9 material; §7.1 reason tables now ARE the validation bars (§5.1/§5.6 point at them instead of restating). Field-guide artifact still shows the r2 attach design — update after Dan reviews.
