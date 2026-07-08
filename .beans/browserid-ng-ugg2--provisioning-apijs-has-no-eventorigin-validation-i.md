---
# browserid-ng-ugg2
title: provisioning_api.js has no event.origin validation (IdP-side cert-forgery vector)
status: todo
type: bug
priority: high
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-08T06:13:39Z
parent: browserid-ng-8u60
---

IdP-side shim provisioning_api.js does no event.origin check on inbound browserid:provisioning:response and sends outbound targetOrigin '*' (lines 29,37,42-50). A page framing it and posting forged responses can drive beginProvisioning/genKeyPair with attacker-chosen email + pubkey into IdP signing. Original Persona used jschannel (validated parent origin).
- [ ] Validate event.origin against expected opener/IdP origin
- [ ] Stop using targetOrigin '*' for provisioning responses
