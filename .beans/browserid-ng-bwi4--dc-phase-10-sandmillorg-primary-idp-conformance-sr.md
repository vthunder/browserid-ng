---
# browserid-ng-bwi4
title: DC Phase 10 — sandmill.org primary IdP conformance (~/src/sandmill)
status: todo
type: task
created_at: 2026-07-18T21:13:48Z
updated_at: 2026-07-18T21:13:48Z
parent: browserid-ng-oup3
---

Bring sandmill.org (Laravel/PHP, deploy dokku@sandmill.org:sandmill) to device-cert conformance so danmills@sandmill.org logs in via the real primary path. Today App\Http\Controllers\BrowserIdController serves /.well-known/browserid, POST /api/browserid/cert_key (24h identity certs), and /browserid/{provision,auth} hidden-iframe pages (routes/web.php:194-266). Add: device-cert issuance (both purposes, subjects user/agent, batch), the headless access-cert mint API, config-cert issuance — signed with its existing IdP key (_browserid.sandmill.org); update discovery; replace the iframe provision page with popup+HTTP issuance. PHP Ed25519 JWS output MUST be byte-compatible with browserid-core device/access/config-cert + warrant claim shapes. Deploy via dokku. Gates the faithful primary demo. See docs/plans/2026-07-18-device-cert-model-migration-plan.md P10.
