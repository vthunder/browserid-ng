---
# browserid-ng-0246
title: '[Audit 2026-11] D1 follow-up: hosted IdP issues agent auth certs for the sub-identity, never widens a base cert'
status: completed
type: bug
priority: high
created_at: 2026-11-03T08:41:54Z
updated_at: 2026-11-03T08:52:35Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-v8s0
---

Found while landing v8s0 (D1). Hosted-tenant agents mint via a BASE-identity auth cert covering base+tag (hosted_idp.rs:364-369 only issues for the session email; :538-552 then resolves dan+poster to roster user dan 'because the device cert already proved the base authorizes the subaddress'). That is the D1 wide mint; with v8s0 merged, hosted-tenant agents cannot mint (hosted_primary_test: agent_subaddress_mints_against_its_base_roster_user :268, managed_tenant_agent_subaddress_mints_per_audience :358 fail). The live github-mcp demo (an @sandmill.org tenant agent) depends on it.

Change (spec §4.6 model, same shape as the main broker's agent-provision path which already issues vec![agent_identity]): POST /idp/device_cert accepts an identity base+tag@tenant when the idp_session owns base@tenant (roster resolves the base; tag validated with the agent-name rules), issues the Authentication cert naming the sub-identity over the agent's key with the server-assigned holder (D3 bean 2lgy lands in the same handler). /idp/access_cert then matches exactly. Update the agent SDK / demo provisioning path that requests the hosted-tenant cert to ask for the sub-identity cert. Flip the two tests to assert the auth cert names the agent identity and the base cert does NOT cover it.

Deploy note: deploy the hosted IdP change and the agent-side change together and re-provision the github-mcp demo agent; until then the demo cannot mint. Run e2e locally (CI does not run e2e).

Acceptance: hosted_primary_test green with the inverted assertions; browserid-broker suite green.



## Summary of Changes

Spec §4.6 model: an auth cert mints exactly, so a hosted-tenant agent gets its own auth cert naming `base+tag@tenant`.

- routes/hosted_idp.rs `/idp/device_cert`: accepts `email = base+tag@tenant` when the idp session owns `base@tenant` (roster resolves the base; exactly one `+`, non-empty tag, the whole local part passes `browserid_registrar::registry::valid_agent_name`). The Authentication cert names the sub-identity (or the base, for the owner's own device / an as-you agent); the paired Authorization (config) cert names the BASE identity and `base+*` as before (§4.6: the owner's config cert signs for +tag grantors), so the approval page's deposited config cert stays the owner's. The holder is server-assigned (D3), with one issuer-side exception: when the co-located registrar's `agent-provision/prepare` assigned a holder for this exact device key, that holder is stamped (new `browserid_registrar::agent_provision::prepared_holder_for_pubkey`); any other page-sent holder is still ignored. `/idp/access_cert` is unchanged in code (it already required `authorizes_identity`, which is exact after D1; the roster check resolves the base); its stale comment is fixed.
- browserid-registrar/src/agent_provision.rs (another agent's crate, flagged to fix-registrar): one additive `pub fn prepared_holder_for_pubkey(pubkey_b64) -> Option<String>` after the statics. Nothing else touched; `complete_device_cert`'s existing `authorizes_identity(agent_email)` check now needs the sub-identity cert, which the page provides.
- static/authorize.html (agent-side path): the primary hop asks the IdP for the AGENT identity (`agentEmail`: base for as-you, `base+tag` for named) instead of the base; INLINE_SCRIPT_HASHES in routes/mod.rs updated for the new inline script hash.
- sdk/agent/src/device.mjs: `authorizesIdentity` is exact (no base-covers-tag); the skipped D1 client-mirror test in sdk/agent/audit_2026_11_ws4.test.mjs is un-skipped (SDK: 28 pass, 0 fail, 4 skipped).
- Tests: hosted_primary_test `agent_subaddress_mints_against_its_base_roster_user` and `managed_tenant_agent_subaddress_mints_per_audience` flipped — the agent cert names the agent identity, the base cert does NOT cover it, the agent cert does not cover the base, the config cert is the owner's, and another user's base / empty tag / two `+` / invalid tag are refused.

Deploy note: the hosted IdP (browserid-broker: /idp/device_cert + authorize.html) and the agent SDK change deploy together, and the github-mcp demo agent (`…+claude-github@sandmill.org`) must be re-provisioned afterwards (its stored cert names the base identity and no longer mints). authorize.html is an auth-flow page: run the Playwright e2e (agent provisioning + hosted IdP specs) before deploying; CI does not run e2e.
