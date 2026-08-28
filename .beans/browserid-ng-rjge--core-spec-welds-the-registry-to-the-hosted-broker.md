---
# browserid-ng-rjge
title: Core spec welds the registry to 'the hosted broker' — reword for role separation
status: completed
type: task
priority: normal
created_at: 2026-08-28T20:13:02Z
updated_at: 2026-08-28T21:36:25Z
parent: browserid-ng-9yyk
---

Impact analysis of d0xb (2026-08-28): fallback-idp-api-v1 commits to four independently-operable roles (RP/wallet/IdP/registry) with identical APIs regardless of operator, but browserid-ng-protocol.md repeatedly hardcodes the registry as 'the hosted broker's'. Normative spots to reword to 'the registry (registry-api-v1)': §5 warrant status claim 'rooted at the hosted broker's warrant registry' (~line 392); §6.3 revocation authority + per-grant allocation (~763-776); §7.5 'stored in the hosted-broker registry' (~1169) and 'A broker that serves such holders MUST host it and the warrant registry' (~1192); §1.3 (~55-63) and §8 (~1350-1354) hosted-component definitions. Also §3 (~90-92): AD-unset DNS 'handled via the broker (§8)' conflates the wallet's routing choice with one specific fallback — should be 'the wallet's configured fallback IdP'. Mechanism-neutral wording fixes (the warrant status.uri already names whichever registry allocated it), but until they land the core spec literally contradicts the role separation. Also decide: core §3.1 marks device-cert REQUIRED for every IdP, but the fallback contract lists only device-authorization+access-cert once /auth/device_cert (2jfh) retires — qualify the REQUIRED for the fallback role.

## Summary of Changes

All cited welds reworded in browserid-ng-protocol.md: §1.3 broker/registry role split (registry-api-v1 named); §3 AD-unset routing now 'the wallet's configured fallback IdP'; §5 warrant status ref rooted at 'the user's warrant registry' (uri names the allocator); §6.1 step 8 + §6.3 authorities + per-grant allocation now name the allocating registry; §6.2 revocation-ledger wording; §7.5 storage + 'a registry that serves such holders MUST host this flow'; §8 browserid.me = reference fallback + reference registry, two independently replaceable roles. §3.1 device-cert REQUIRED qualified: primaries only; a fallback MAY satisfy issuance via device-authorization + access-cert (post-2jfh contract). §7.5's remaining 'broker' mentions are the flow host (spec placement tracked by 9mfw), left as-is.
