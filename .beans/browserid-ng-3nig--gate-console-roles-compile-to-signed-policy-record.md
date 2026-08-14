---
# browserid-ng-3nig
title: 'Gate console: roles compile to signed policy records (retire config-row enforcement)'
status: completed
type: task
priority: normal
created_at: 2026-08-14T20:26:08Z
updated_at: 2026-08-14T21:27:58Z
parent: browserid-ng-rjmm
---

Dan's decision (2026-08-14): the roles/people UI stays as the editor, but enforcement moves to §6.5 signed records. Compiling saves into flat per-(email, mount) grants the admin signs at the broker authoring card; admission = record ∩ connection; /account revocation works; config-row enforcement retires for gateway mounts.

- [x] gate: file-backed policy store (gateHome()/policy.json, 600)
- [x] gateway: shared policy store + owners=[admin] on every mount; compile roles → flat grants; GET /admin/grants (desired vs signed diff), POST /admin/grants/sign (authoring ceremony; background wait stores rows; stale rows deleted), GET /admin/grants/status
- [x] mount: policy mode — grantor gate = owner or covering policy row (Lane A included, not just connection bearers); per-tool granted set derived from ctx.scopes; access-resolver retired for gateway mounts
- [x] console UI: grants banner + Sign flow (open consent card, poll status, refresh)
- [x] tests: record-broker fixture + roles.test signs compiled grants in before(); policy.test drives the identity-first flow; lifecycle/multimount moved to admin bearers; CRUD tests kept
- [x] broker consent page: real sign-in on the auth-gate + ceiling note (unpinned only); PINNED card renders the identity fixed; CSP hashes updated
- [x] suites green (54 Rust / 46 mcp-auth / 58 gate / 21 agent / e2e 105-0), commit, publish mcp-auth 0.5.0 + gate 0.7.0, deploy broker

## Summary of Changes

Scope grew mid-build per Dan: IDENTITY-FIRST connect (gate authenticates the user before raising any broker request). Broker: connection requests take an optional grantor pin (validated at respond like the JIT pin; pinned cards render the identity fixed, no selector); consent auth-gate got a real inline sign-in. mcp-auth 0.5.0: handleAuthorize(query, ctx) carries {grantor, scopes} — the request is pinned and scoped to the user entitlement; return leg enforces the pin; requestAuthoring delivery matching fixed to positional (audience alone collided for two grantees on one mount). gate 0.7.0: /connect/login member login (browserid dialog, origin-wide gate_user session → auto-bounce across mounts), mount /authorize demands login in policy mode and refuses unshared users BEFORE consent (noAccessPage), roles compile to signed records (32-row ceremony chunks), /admin/grants endpoints + console Sign flow, entitlement enforced for every bearer kind at /mcp with S ∩ S′ tool filtering. e2e drives the whole thing incl. the dialog-popup login and reconnect auto-bounce.
