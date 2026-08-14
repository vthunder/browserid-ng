---
# browserid-ng-aaka
title: §6.5 composition + credential-less gate + sharing e2e
status: completed
type: task
priority: normal
created_at: 2026-08-14T18:00:58Z
updated_at: 2026-08-14T19:15:44Z
parent: browserid-ng-rjmm
---

Dan's pre-test bar (2026-08-14): no manual testing until sharing works e2e through gate with zero infra identities.

- [x] mcp-auth: policy layer — createPolicyStore, policy: {owners} option; requestAuthoring() helper (raise {type:authoring} ceremony, publish proof, poll, validate each delivered record via /validate-record, grantor MUST be a configured owner, store rows keyed (grantor, grantee, audience))
- [x] mcp-auth: admission conjunction (§6.5) — connection mint/refresh: grantee ∈ owners passes (degenerate G=E), else a policy row must cover the grantee (exact / *@domain / *, §5 comparison); effective scopes = S ∩ S'; BOTH records revalidated fail-closed at every mint/refresh; bearer carries both records' status refs
- [x] gate: credential-less (drop required credential; no infra identities), audience-proof route (mount subpath for single-server + gateway root fan-out), share/authoring surface returning consent_uri, owners from config
- [x] Playwright e2e: owner shares to member email (authoring consent), member connects via simulated OAuth host (connection consent), tool call attributed to member under owner grant with S∩S', member revokes connection at /account (fail-closed), owner revokes policy record at /account (kills the member's access)
- [x] All suites green (46 mcp-auth / 58 gate / 54 Rust / sharing e2e passes; 4 pre-existing e2e failures root-caused in zno8); commits 3e83ab5 + 6aa24de; deployed, CI green, prod verified

## Summary of Changes

mcp-auth 0.4.0: identityEq/granteeCovers, createPolicyStore, policy:{owners} on the lane, requestAuthoring() (ceremony + owner-anchored ingestion), conjoinPolicy at every connection mint/refresh (S ∩ S′, dual status refs, ctx.permittedBy). gate 0.6.0: credential optional everywhere + CLI skips provisioning when the broker advertises record-grants; owners option; audience-proof at mount + gateway origin fan-out; policy.test.mjs real-HTTP sharing loop. Broker: dev-localhost well-known serves its key (the zexp hardening had silently broken the dev_local_broker fallback — root cause of the e2e issuer-has-no-key error); prod still keyless (both postures tested). New e2e connection-sharing.spec.ts + gate-server fixture: the complete two-user sharing loop in real browsers, both revocation axes. Attribution: grantor=member under=owner tool=read_text_file.
