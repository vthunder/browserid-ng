---
# browserid-ng-t25u
title: 'Audit WS5: broker HTTP surface review + authz matrix test'
status: todo
type: task
priority: normal
created_at: 2026-11-01T12:40:56Z
updated_at: 2026-11-01T15:43:06Z
parent: browserid-ng-ag1l
---

All ~20 route modules: authz on every handler, CSRF, open redirect (return_origin), SSRF (verifier status fetch, dns_fetcher, proof_fetch), rate limiting, enumeration, cookie attrs, CSP hashes. Build durable authz matrix test: every route x principal (anon, user, other user, agent, tenant admin) asserting expected status. Re-verify July C1/H1/H2/M1-M9 and oawf deferred items.

## From WS1 — candidates to confirm/refute
D2 respond never checks config cert recorded/signed (consent.rs:457-465,551-561); D4 JIT request unsigned; D8 no rate limit on /api/v1 (approvals 30-bit code); D9 fetches before proof verification on accounts/lookup; D10 possession proofs not replay-cached; D11 cross-account attach row corruption (needs SqliteStore test); D18 JIT details. Also resolve the ytjn/dw35/7ww7 completed-vs-open discrepancy. Authz matrix from I22-I28. See docs/security-audit-2026-11-ws1-spec-review.md §1.
