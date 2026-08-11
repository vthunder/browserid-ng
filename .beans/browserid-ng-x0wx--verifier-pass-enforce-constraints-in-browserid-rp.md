---
# browserid-ng-x0wx
title: 'Verifier pass: enforce constraints in browserid-rp + core'
status: todo
type: task
created_at: 2026-08-11T12:29:56Z
updated_at: 2026-08-11T12:29:56Z
parent: browserid-ng-4vu7
---

Prereq for everything. browserid-core: parse `constraints` on access/config certs ({aud:{salt,hashes}, scopes, max-ttl} + unknown-key capture) and `managed` on device certs. browserid-rp Verifier: step 7 — RP audience vs salted SHA-256 aud allowlist, warrant.scopes ⊆ scopes, warrant exp−iat ≤ max-ttl, ANY unknown constraint key ⇒ reject (fail-closed). Tests: violation matrix, unknown-key reject, absent-constraints unchanged. Then: broker rebuild (hosted /verify-access, guestbook, fedcm inherit), mingo pin bump + deploy. JS/Python SDKs inherit via hosted endpoint. Separate: audit sbo on-chain verifier (own repo) for conformance.
