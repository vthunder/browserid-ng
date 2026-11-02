---
# browserid-ng-7ith
title: '[Audit 2026-11] D12 (defence in depth): wallet verifies the stored grant signature before signing'
status: todo
type: bug
priority: normal
created_at: 2026-11-02T22:43:21Z
updated_at: 2026-11-02T22:43:21Z
parent: browserid-ng-ag1l
---

Findings: D12, refuted as a security finding (anyone who can write the safeStorage-encrypted store already holds configKey and can mint a fresh record); Low defence-in-depth residue. Decision: Q23 settled 2026-11-02 (add; it is cheap).

Where: wallet/src/request.js:166-190 (coveringRecord payload-decodes the stored grant without a signature check). What the lane does enforce is pinned (requester origin, holder matcher, exact audience, grantee == identity, sign:sbo scope, record expiry, unknown channel kinds, per-signature /status/check failing closed).

Change: verify the stored JWS against configKey.x in coveringRecord before signing.

Acceptance: un-skip wallet/test/audit_2026_11_ws4.test.mjs "D12 (defence in depth): a stored record whose signature is not the config key's is refused".

Reports: ws4 §1.4. Ledger: docs/security-audit-2026-11.md. Decisions: docs/security-audit-2026-11-decisions.md.
