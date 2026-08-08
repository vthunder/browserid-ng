---
# browserid-ng-7sew
title: IdP-led auth-only issuance (gate config cert behind 2FA)
status: todo
type: feature
priority: normal
created_at: 2026-08-08T14:37:00Z
updated_at: 2026-08-08T14:37:00Z
---

The IdP-enforced counterpart to client-chosen auth-only login: an IdP MAY refuse to issue an authorization (config) cert unless a stronger check is satisfied — e.g. 2FA / step-up auth — while still issuing an auth cert for ordinary login. This makes 'can authorize new grants' a privilege the IdP gates, independent of what the client requests.

Spec basis: browserid-ng-protocol.md §7.1 (a batch MAY return an auth cert alone), §7.5 (only a config-cert holder can create warrants). The spec already permits an IdP to withhold the config cert; this bean is the enforcement policy.

## Approach (IdP-led)
- On the device-cert issuance endpoint, treat the authorization-purpose cert as a privileged issuance: require step-up (2FA / recent strong auth) before signing it; otherwise return only the auth cert.
- Signal to the client why the config cert was withheld (e.g. needs_2fa) so the dialog can prompt for step-up and retry, rather than the login appearing to silently downgrade.
- Policy is per-IdP (the reference broker's own policy, and a knob federated IdPs like mingo-idp / sandmill can adopt).

## Notes
- Pairs with the client/broker-led bean (a checkbox): the two are independent levers (client opt-out vs IdP enforcement) and can coexist.
- Consider interaction with the batch-issuance flow (device-authorization page) and the quota on config-cert-bearing devices.
