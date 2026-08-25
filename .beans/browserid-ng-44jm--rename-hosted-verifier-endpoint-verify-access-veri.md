---
# browserid-ng-44jm
title: Rename hosted verifier endpoint /verify-access -> /verify (coordinated cutover)
status: completed
type: task
priority: high
created_at: 2026-07-24T13:43:05Z
updated_at: 2026-08-25T20:57:03Z
---

Dan (2026-07-24): the hosted verifier should live at browserid.me/verify — the tighter endpoint. The device-cert migration left it at /verify-access (the old /verify was the retired cert~assertion path; audit item D2 documents the drift; spec §6.1 already says /verify).

Coordinated cutover — consumers to sweep:
- [x] browserid-broker: make /verify the canonical route, keep /verify-access as a PERMANENT alias (decision 2026-08-25 — same handler, both routes; no retirement)
- [x] docs/specs: §6.1 already names /verify — this closes that divergence (update audit doc D2 note + ga3w work list)
- [x] browserid-rp: no hosted-verify client today, but kozn (extract verifier crate) and any hosted-verify helper should target /verify
- [ ] (moved to bean bhfi) browserid-bsky: pds-bridge verify_presentation POSTs {broker}/verify-access (routes.rs) + test mock route
- [ ] (moved to bean bhfi) mingo: check for /verify-access / /verify-assertion uses (mingo repo)
- [ ] (moved to bean bhfi) sbo: check daemon/attribution verify calls (sbo repo)
- [x] sdk/js @browserid-ng/verify: DEFAULT_VERIFIER -> https://browserid.me/verify (index.mjs, index.d.ts, README); check adapter READMEs (nextauth/express/hono/fastify)
- [x] docs/verify-quickstart.md: re-center on /verify AND fix the stale request shape — it documents an `assertion` field, but the endpoint takes `presentation` (plus `audience`, optional `accepted_fallbacks`); align the response fields (`grantee`/`holder`/`status_refs`) with routes/device.rs
- [x] e2e tests + examples (rp-quickstart, mcp-agent-auth mock-verifier)

- [x] openapi.json (browserid-broker/ + the byte-identical marketing/ copy): document /verify as canonical, list /verify-access as its deprecated-alias path; update tests/agent_surface_test.rs path assertions
- [x] marketing site: developers.html + developers.md code copy, llms.txt — point at /verify
- [x] verify /verify-access still answers after the cutover (alias regression test: test_verify_and_verify_access_are_the_same_endpoint; prod re-check after deploy)

Suggested order: add /verify as an alias at the broker first (deploy), flip all docs/SDK defaults to /verify, migrate consumers repo by repo. /verify-access is NEVER retired — it stays a permanent alias (2026-08-25).

**Decision (Dan, 2026-08-25):** /verify is the actual endpoint, /verify-access remains as an alias, and every doc everywhere points at /verify. Supersedes the "deprecation window" question above. Duplicate bean pl41 scrapped in favor of this one. Context: the agent-readiness pass (bean n1fa) published openapi.json on both origins documenting /verify-access — those are now consumers to update too.

## Decisions (2026-08-25, session start)

- Scope: this repo + SDK/docs/marketing/openapi in this push; browserid-bsky, mingo, sbo get follow-up beans (safe — /verify-access is a permanent alias).
- Build order confirmed: broker alias first (deploy), then flip docs/SDK defaults.

## Summary of Changes

Done 2026-08-25. Broker: /verify is the canonical route, /verify-access the permanent alias (same handler); alias regression test (agent_surface). openapi.json (both copies) documents /verify canonical + deprecated-flagged alias. Spec §6 mentions renamed with the alias noted at first mention. verify-quickstart.md rewritten to the actual wire shape (presentation/audience; grantee/holder/issuer/grantee_issuer/status_refs). Mechanical flip across sdk/* (DEFAULT_VERIFIER), examples, scripts/e2e, github-mcp, python-mcp-demo, wallet-service, marketing. All SDK + workspace tests green; deployed and verified on prod (both routes answer identically; openapi live). External repos (bsky/mingo/sbo) tracked in bean bhfi — nothing is broken meanwhile since the alias is permanent. npm publish of the new SDK defaults rides bean bf47.
