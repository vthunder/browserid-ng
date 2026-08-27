---
# browserid-ng-bw9q
title: 'Registry lane for native wallets: device-cert-authenticated approvals inbox (+ client-supplied holder)'
status: todo
type: feature
created_at: 2026-08-27T08:57:24Z
updated_at: 2026-08-27T08:57:24Z
---

The menubar-wallet prototype exposed that every registry operation is session-cookie-only, so a native wallet is a second-class registry client standing on borrowed cookies:

- **Approvals inbox**: /wsapi/warrant_requests requires a broker session; the wallet polls it with a persisted Electron session that dies with the cookie. Clean fix: a device-cert-authenticated inbox — e.g. POST /warrant/inbox { device_cert } returning the same PendingRequestInfo set for the cert's account. The auth primitive already exists in warrant_request (consent.rs ~1219: parse cert, verify against IdP key, purpose Authentication, unexpired, unrevoked, authorizes identity) and store.list_pending_warrant_requests(user_id) is already the backing query.
- **Client-supplied holder on the fallback lane** is the sibling gap, already tracked in kmvm.

Bigger picture (client-broker vs server-broker delineation, recorded on 7v5l): making registry operations cert-authed is what turns the wallet into a first-class registry client, and is the prerequisite for anyone self-hosting the registry role.
