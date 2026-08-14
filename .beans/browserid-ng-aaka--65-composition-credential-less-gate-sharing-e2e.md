---
# browserid-ng-aaka
title: §6.5 composition + credential-less gate + sharing e2e
status: in-progress
type: task
created_at: 2026-08-14T18:00:58Z
updated_at: 2026-08-14T18:00:58Z
parent: browserid-ng-rjmm
---

Dan's pre-test bar (2026-08-14): no manual testing until sharing works e2e through gate with zero infra identities.

- [ ] mcp-auth: policy layer — createPolicyStore, policy: {owners} option; requestAuthoring() helper (raise {type:authoring} ceremony, publish proof, poll, validate each delivered record via /validate-record, grantor MUST be a configured owner, store rows keyed (grantor, grantee, audience))
- [ ] mcp-auth: admission conjunction (§6.5) — connection mint/refresh: grantee ∈ owners passes (degenerate G=E), else a policy row must cover the grantee (exact / *@domain / *, §5 comparison); effective scopes = S ∩ S'; BOTH records revalidated fail-closed at every mint/refresh; bearer carries both records' status refs
- [ ] gate: credential-less (drop required credential; no infra identities), audience-proof route (mount subpath for single-server + gateway root fan-out), share/authoring surface returning consent_uri, owners from config
- [ ] Playwright e2e: owner shares to member email (authoring consent), member connects via simulated OAuth host (connection consent), tool call attributed to member under owner grant with S∩S', member revokes connection at /account (fail-closed), owner revokes policy record at /account (kills the member's access)
- [ ] All suites green; commit; deploy (mcp-demo picks up mcp-auth; broker unchanged)
