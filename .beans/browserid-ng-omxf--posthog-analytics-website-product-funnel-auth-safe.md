---
# browserid-ng-omxf
title: 'PostHog analytics: website + product funnel, auth-safe integration'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-13T07:47:22Z
updated_at: 2026-07-13T11:12:52Z
blocked_by:
    - browserid-ng-93z2
---

Set up PostHog (project 509769, us.i.posthog.com) for browserid-ng.

Goals:
- Website analytics: landing page, guestbook
- Product analytics: onboarding conversion funnel, account page usage
- Stuck-detection: see where users drop off / get stuck

Constraint: browserid is a web auth platform — third-party JS and cookies on security-critical pages (fallback IdP, cert/keystore) are a real supply-chain risk. Evaluate mitigations: reverse-proxied/self-hosted posthog-js, cookieless mode, server-side capture on sensitive flows, splitting fallback IdP to a dedicated subdomain, CSP tightening.

## Todo
- [x] Map frontend surface + existing CSP/cookies
- [x] Security analysis of integration options
- [ ] Discuss options with Dan, pick approach
- [ ] Implement chosen integration
- [ ] Dashboards/funnels in PostHog (API key available)

## Key findings (2026-07-13)

- Single origin serves everything: landing, guestbook, dialog, consent, account, fallback-IdP auth, signer. No page is low-risk for third-party JS — same-origin script can use the non-extractable signing keys in IndexedDB (keystore.js), read the JS-visible CSRF token, and drive wsapi.
- No script-src/connect-src CSP exists (only frame-ancestors none). Session cookie is well-hardened (HttpOnly, host-only, SameSite=Lax).
- No shared page layout — snippet would need per-page insertion; guestbook page is server-rendered in guestbook.rs.
- Recommendation under discussion: Phase 1 = server-side capture from axum handlers + CSP hardening (zero browser risk); Phase 2 = origin split (id.browserid.me for key-custody pages) then locked-down self-hosted posthog-js on marketing origin only.

## Parked (2026-07-13)

Dan decided to reverse the order: do the origin-split spike first (browserid-ng-93z2) before any PostHog integration, since the split is the load-bearing unknown — browserid's RP flows depend on complex cross-origin interactions (hidden iframes, first-party popups) that the split may break. PostHog work resumes after the spike's findings.
