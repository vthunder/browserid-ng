---
# browserid-ng-qfeu
title: Managed per-audience hosted-tenant agents can't mint (device cert managed marker / SDK audience)
status: in-progress
type: bug
priority: high
created_at: 2026-08-12T08:57:21Z
updated_at: 2026-08-12T09:35:34Z
---

Live github-mcp demo, 2026-08-12: an agent identity on a managed hosted tenant (sandmill.org, managed identities + per_audience ON) fails at the access mint with 'audience required: this managed identity mints per-audience access certs'. The broker honors a per-audience request only when the access request carries an audience AND the device cert is stamped managed:true. Either (a) the agent's device cert isn't getting the managed marker in the agent-provision path (the primary-signed cert comes from /idp/device_cert for a hosted tenant), or (b) the agent SDK / hosted wallet doesn't pass the audience on mint. Third in a series of hosted-tenant+agent gaps (serving-host mint origin, +tag roster resolution both fixed). Fix with a local repro + tests, then deploy.

## Root cause (2026-08-12): stale pre-managed credential, NOT a code bug

Reproduced the full managed-agent path in a local test (managed_tenant_agent_subaddress_mints_per_audience): a managed per-audience tenant issues a managed:true device cert to the base roster user and the agent +tag subaddress mints per-audience successfully. PASSES — the issuance + mint + SDK are all correct.

The prod failure was the agent holding a device cert issued BEFORE sandmill.org enabled managed identities: no managed marker → the SDK (correctly) never sends an audience → the per-audience mint rejected with the opaque 'audience required'. A device cert is fixed at provision; the SDK only re-mints access certs, so a stale device cert can't self-heal — re-provisioning is the only recovery.

Fix shipped: the mint now detects the non-managed-cert-on-managed-tenant case and returns an ACTIONABLE error ('this credential predates managed-identity settings for <domain>; sign out and provision the identity again') instead of 'audience required'. Two regression tests added. The demo unblocks by re-provisioning the agent fresh.

## ACTUAL root cause (2026-08-12, round 2): stale PUBLISHED @browserid-ng/agent

Fresh re-provision gave a managed:true cert (confirmed: mint returned the OLD 'audience required', not my new pre-managed message → cert IS managed). Yet the wallet still didn't send the mint audience. Cause: the managed-identities commit a04ddf7 added per-audience minting to sdk/agent/src/device.mjs but NEVER bumped the version — npm @browserid-ng/agent@0.3.0 predates it (published from 0879a38). The local wallet runs via npx and pulls the stale 0.3.0, which never sends the audience → managed tenant rejects. Would bite every external managed-tenant user.

Fix: @browserid-ng/agent 0.3.0→0.4.0 (per-audience mint), @browserid-ng/wallet 0.4.4→0.4.5 (dep bumped to ^0.4.0). Needs republish + wallet connector restart.
