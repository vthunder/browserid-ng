---
# browserid-ng-wuoc
title: Sibling-spec drift after registry-api-v1 r5 (fallback-idp, core §3.1/§7.5/§9, request ids)
status: todo
type: task
priority: normal
created_at: 2026-09-06T11:08:58Z
updated_at: 2026-09-07T19:14:28Z
parent: browserid-ng-0c49
---

From the 2026-09-06 adversarial review (coherence 6–10). Dan: open beans, settle once registry-api-v1 is final.

- [ ] fallback-idp-api-v1 §4: still registers via `POST /api/v1/token` and `POST /api/v1/devices/register` (both deleted); rewrite to `attach` (§5.6.1); cites the `browser` object as registry §5.5 (now §5.1); `device_authorization` vs key `device-authorization`
- [ ] core §7.5 line ~1194: "a registry that serves such holders MUST host this flow alongside the warrant registry" vs registry-api-v1 declaring the request/poll lanes out of scope (bean 9mfw) — one must move
- [ ] request ids: registry uses `code` for every kind; core uses `request_id` for connection/authoring requests. Registry should state the mapping (core wire is deployed)
- [ ] core §3.1: add the `registry` key and the ignore-unknown-keys rule the registry spec attributes to it; `browser` keys (`account`, `guard`)
- [ ] error format citation: registry §7 cited "core §9" (the RP grant exchange); now cites RFC 6749 §5.2 — confirm core has no error-format section to point at
- [ ] guard page fragment shape (`pubkey`, `identity`, `return_url`, `return_origin`) vs fallback-idp §4 sign-in page — keep them identical

2026-09-07: round-3 coherence additions — fallback-idp §4/§5/§7 cite POST /api/v1/token and devices/register (deleted) and 'registry §5.5 reserves browser' (now §5.1); holder assigner drifts (issuer in R/F, client broker in core §4.1/§4.5); core cites to fix from R: 'core §5.5' nonexistent, login is core §7.3, status list core §6.3, external holder core §6.6; page-guard fragment (certs, identity, return_url, return_origin) vs sign-in page (email, device_pubkey, config_pubkey); core §7.5 'deny-only for unknown holder' MUST → wallet SHOULD; core §7.5 'registry MUST host the lanes' vs R's separate-document framing; grantor/grantee names now match core.
