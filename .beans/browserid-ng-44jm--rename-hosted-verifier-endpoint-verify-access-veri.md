---
# browserid-ng-44jm
title: Rename hosted verifier endpoint /verify-access -> /verify (coordinated cutover)
status: todo
type: task
created_at: 2026-07-24T13:43:05Z
updated_at: 2026-07-24T13:43:05Z
---

Dan (2026-07-24): the hosted verifier should live at browserid.me/verify — the tighter endpoint. The device-cert migration left it at /verify-access (the old /verify was the retired cert~assertion path; audit item D2 documents the drift; spec §6.1 already says /verify).

Coordinated cutover — consumers to sweep:
- [ ] browserid-broker: route rename (routes/mod.rs /verify-access), serve /verify; decide whether to keep /verify-access as an alias for a deprecation window
- [ ] docs/specs: §6.1 already names /verify — this closes that divergence (update audit doc D2 note + ga3w work list)
- [ ] browserid-rp: no hosted-verify client today, but kozn (extract verifier crate) and any hosted-verify helper should target /verify
- [ ] browserid-bsky: pds-bridge verify_presentation POSTs {broker}/verify-access (routes.rs) + test mock route
- [ ] mingo: check for /verify-access / /verify-assertion uses (mingo repo)
- [ ] sbo: check daemon/attribution verify calls (sbo repo)
- [ ] sdk/js @browserid-ng/verify + verify-quickstart.md + README examples: confirm which endpoint the hosted-verify wrapper hits
- [ ] e2e tests + examples (rp-quickstart, mcp-agent-auth mock-verifier)

Suggested order: add /verify as an alias at the broker first (deploy), migrate consumers repo by repo, then retire /verify-access.
