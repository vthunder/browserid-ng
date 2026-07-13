---
# browserid-ng-kt5y
title: 'Auth-origin CSP tightening: script-src ''self'' + inline hashes, connect-src ''self'''
status: todo
type: task
priority: normal
created_at: 2026-07-13T09:16:37Z
updated_at: 2026-07-13T09:16:37Z
blocked_by:
    - browserid-ng-cn1q
---

Follow-up to the origin split (browserid-ng-cn1q). Add a real script CSP to the auth origin, replacing today's frame-ancestors-only policy in routes/mod.rs::deny_framing (rename to a general security-headers layer).

Target: script-src 'self' + 'sha256-...' hashes for the inline scripts (index.html if still served locally, consent.html, account.html, the sign_in_return inline script), and connect-src 'self'.

CARE: a strict CSP can break the primary-IdP cross-origin provisioning iframe flow (dialog embeds the IdP's /provision at a different origin) and the fallback provisioning. connect-src is client-fetch scoped (dialog fetches /wsapi same-origin — fine), but verify nothing client-side fetches cross-origin. frame-src/child-src must still allow the provisioning iframe origins. Keep frame-ancestors 'none' with the existing /communication_iframe,/relay,/provision exceptions.

Use the e2e suite (primary-idp.spec.ts, accepted-fallbacks.spec.ts, sign-in, dialog) as the regression net. Roll out report-only first (Content-Security-Policy-Report-Only) if practical.
