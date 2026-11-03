---
# browserid-ng-0246
title: '[Audit 2026-11] D1 follow-up: hosted IdP issues agent auth certs for the sub-identity, never widens a base cert'
status: todo
type: bug
priority: high
created_at: 2026-11-03T08:41:54Z
updated_at: 2026-11-03T08:41:54Z
parent: browserid-ng-ag1l
blocked_by:
    - browserid-ng-v8s0
---

Found while landing v8s0 (D1). Hosted-tenant agents mint via a BASE-identity auth cert covering base+tag (hosted_idp.rs:364-369 only issues for the session email; :538-552 then resolves dan+poster to roster user dan 'because the device cert already proved the base authorizes the subaddress'). That is the D1 wide mint; with v8s0 merged, hosted-tenant agents cannot mint (hosted_primary_test: agent_subaddress_mints_against_its_base_roster_user :268, managed_tenant_agent_subaddress_mints_per_audience :358 fail). The live github-mcp demo (an @sandmill.org tenant agent) depends on it.

Change (spec §4.6 model, same shape as the main broker's agent-provision path which already issues vec![agent_identity]): POST /idp/device_cert accepts an identity base+tag@tenant when the idp_session owns base@tenant (roster resolves the base; tag validated with the agent-name rules), issues the Authentication cert naming the sub-identity over the agent's key with the server-assigned holder (D3 bean 2lgy lands in the same handler). /idp/access_cert then matches exactly. Update the agent SDK / demo provisioning path that requests the hosted-tenant cert to ask for the sub-identity cert. Flip the two tests to assert the auth cert names the agent identity and the base cert does NOT cover it.

Deploy note: deploy the hosted IdP change and the agent-side change together and re-provision the github-mcp demo agent; until then the demo cannot mint. Run e2e locally (CI does not run e2e).

Acceptance: hosted_primary_test green with the inverted assertions; browserid-broker suite green.
