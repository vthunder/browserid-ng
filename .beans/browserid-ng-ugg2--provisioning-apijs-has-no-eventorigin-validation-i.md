---
# browserid-ng-ugg2
title: provisioning_api.js has no event.origin validation (IdP-side cert-forgery vector)
status: completed
type: bug
priority: high
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-11T23:06:02Z
parent: browserid-ng-8u60
---

IdP-side shim provisioning_api.js does no event.origin check on inbound browserid:provisioning:response and sends outbound targetOrigin '*' (lines 29,37,42-50). A page framing it and posting forged responses can drive beginProvisioning/genKeyPair with attacker-chosen email + pubkey into IdP signing. Original Persona used jschannel (validated parent origin).
- [x] Validate event.origin against expected opener/IdP origin
- [x] Stop using targetOrigin '*' for provisioning responses

## Summary of Changes

provisioning_api.js now pins the embedding broker origin (window.location.ancestorOrigins[0], unforgeable in Blink/WebKit; falls back to the subframe referrer on Firefox), targets all outbound postMessages at that origin instead of *, and rejects inbound messages unless event.source === window.parent and (when pinned) event.origin matches. This closes the cert-forgery vector (a framing page could previously post a forged beginProvisioning response with an attacker-chosen email/pubkey) and stops registerCertificate leaking the signed cert to *. The broker-side handler (provisioning.js) already validated origin. The e2e mock IdP was updated to mirror the hardening so the cross-origin provisioning flow exercises it; added a test asserting the shim pins the parent origin (not *). Full 90-test e2e green; deployed to browserid.me and verified live.
