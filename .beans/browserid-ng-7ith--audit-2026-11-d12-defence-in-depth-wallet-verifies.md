---
# browserid-ng-7ith
title: '[Audit 2026-11] D12 (defence in depth): wallet verifies the stored grant signature before signing'
status: completed
type: bug
priority: normal
created_at: 2026-11-02T22:43:21Z
updated_at: 2026-11-03T08:39:42Z
parent: browserid-ng-ag1l
---

Findings: D12, refuted as a security finding (anyone who can write the safeStorage-encrypted store already holds configKey and can mint a fresh record); Low defence-in-depth residue. Decision: Q23 settled 2026-11-02 (add; it is cheap).

Where: wallet/src/request.js:166-190 (coveringRecord payload-decodes the stored grant without a signature check). What the lane does enforce is pinned (requester origin, holder matcher, exact audience, grantee == identity, sign:sbo scope, record expiry, unknown channel kinds, per-signature /status/check failing closed).

Change: verify the stored JWS against configKey.x in coveringRecord before signing.

Acceptance: un-skip wallet/test/audit_2026_11_ws4.test.mjs "D12 (defence in depth): a stored record whose signature is not the config key's is refused".

Reports: ws4 §1.4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.


## Summary of Changes

Committed together with bean 25lq (both change wallet/src/request.js and the same test file).

- D12 (7ith): wallet/src/crypto.js gains a synchronous `verifyJws(jws, x)` (node:crypto Ed25519 over `header.payload`); `coveringRecord` in wallet/src/request.js refuses (`no_grant`, "not signed by this wallet's config key") any stored grant whose signature is not the config key's before a single claim is read. Un-skipped "D12 (defence in depth): a stored record whose signature is not the config key's is refused".
- W4-20 (25lq): the native warrant prompt renders each entry through the wallet-owned label table (`BrowserIDScopeLabels` from browserid-broker/static/common/js/scope-labels.js, located like the SBO helpers via WALLET_SBO_DIR, with a raw fallback), one bullet per entry under its audience, and names the mode for signing scopes: "[auto mode: standing authority — signed without asking again until revoked]" vs "[prompt mode: asks you each time]"; parameters (caps, counterparties, durations, reputation) are part of the label. The prompt-mode signature summary now shows EVERY envelope field (all are signed), truncating long values for the card only. Un-skipped "W4-20: the native warrant prompt distinguishes a standing (auto) grant from a prompt-mode one"; the "what the warrant prompt does show" pin asserts the new two-line shape. GUI check of the dialog wording is for Dan locally (unobserved display here).
