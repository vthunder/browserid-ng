---
# browserid-ng-h2m1
title: 'mcp-auth: credential-less connection lane (capability detection, (binding.id, record)-bound bearers, freshness-backed mint)'
status: completed
type: task
priority: normal
created_at: 2026-08-14T16:48:57Z
updated_at: 2026-08-14T17:50:13Z
parent: browserid-ng-rjmm
blocked_by:
    - browserid-ng-qmvw
---

Phase-1 item 3 (build order in rjmm handoff), per spec §6.4 freshness-backed minting + §7.5 connection grant requests:

- [x] Capability detection (record-grants in /.well-known/browserid, 300s cache) with agent-credential fallback; credential now optional
- [x] Auth-code lane connection mode: record-request + handleAudienceProof + consent_uri redirect + poll; record validated at return leg; client_host binding enforced at return AND every mint
- [x] validateRecord/mintFromValidatedRecord on createMcpAuth; bearers carry bindingId+record
- [x] Bearers ≤1h (tokenTtlS 3600, capped by record exp); every mint/refresh calls /validate-record fail-closed; mrt_ refresh rotation + family burn on reuse
- [ ] Retain per-mint snapshot evidence for audit (SHOULD) — DEFERRED: needs /validate-record to return the signed status-list snapshot tokens (follow-up)
- [x] mcp-demo: lane unconditional, credential optional, audience-proof route added
- [x] Tests green (mcp-auth 40/40 incl. 5 new connection-lane tests; gate 56/56), version 0.3.0, d.ts updated
- [x] Deploy broker + mcp-demo (commits ea6475e/cb935aa/230d1a1; CI green; prod verified: record-grants advertised, /validate-record live, demo advertises refresh_token, live authorize → broker consent 302 + proof published + consent page 200)

## Summary of Changes

See commit cb935aa (mcp-auth 0.3.0) and the checklist above. Post-deploy fix 230d1a1: the unclaimed record-request row (user_id 0) hit the sqlite users(id) FK in prod — migration v29 drops the FK on the ephemeral warrant_requests table; sqlite-backed regression test added (the in-memory store had masked it). Deferred: per-mint snapshot retention (SHOULD). npm publish of @browserid-ng/mcp-auth still not done (pre-existing).
