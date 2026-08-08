---
# browserid-ng-ra9i
title: Broker support for auth-only login (no config cert)
status: todo
type: feature
priority: normal
created_at: 2026-08-08T14:37:00Z
updated_at: 2026-08-08T14:37:00Z
---

Support a login that issues only an auth cert (no config cert), so the resulting device can sign into sites with a preexisting warrant covering its holder category (e.g. browsers.*) but cannot mint new warrants itself. Spec: browserid-ng-protocol.md §7.1 (issuance MAY return an auth cert alone), §7.3 step 2 (auth-only holder presents a preexisting warrant), §7.5 (capability split by whether the holder has a config cert). This is the least-privilege / shared-machine case.

## Approach (client/broker-led)
- Add a control in the login dialog (e.g. a checkbox 'this is a shared or untrusted device') that opts OUT of config-cert issuance for this login. DEFAULT: request a config cert (current behavior), so most logins are unaffected.
- When unchecked-for-config: the batch device-cert request omits the authorization purpose; the broker issues/receives only the auth cert.
- Login then relies on preexisting warrants whose holder-matcher covers the browser holder; if none exists for the target RP, surface the just-in-time consent flow (§7.5) rather than silently failing.
- UX: make clear what an auth-only login can and cannot do (can sign in where already warranted; cannot authorize new grants).

## Notes
- Complements the IdP-led approach (separate bean): here the client chooses; there the IdP enforces (e.g. 2FA-gated config cert).
- No protocol change needed — the spec already allows this; this is broker/dialog implementation.
