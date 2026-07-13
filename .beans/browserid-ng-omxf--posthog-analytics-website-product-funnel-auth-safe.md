---
# browserid-ng-omxf
title: 'PostHog analytics: website + product funnel, auth-safe integration'
status: completed
type: feature
priority: normal
created_at: 2026-07-13T07:47:22Z
updated_at: 2026-07-13T13:12:42Z
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
- [x] Discuss options with Dan, pick approach (hybrid: client on www, server-side on broker)
- [x] Implement chosen integration
- [x] Dashboards/funnels in PostHog (2 dashboards, 12 insights — see below)

## Key findings (2026-07-13)

- Single origin serves everything: landing, guestbook, dialog, consent, account, fallback-IdP auth, signer. No page is low-risk for third-party JS — same-origin script can use the non-extractable signing keys in IndexedDB (keystore.js), read the JS-visible CSRF token, and drive wsapi.
- No script-src/connect-src CSP exists (only frame-ancestors none). Session cookie is well-hardened (HttpOnly, host-only, SameSite=Lax).
- No shared page layout — snippet would need per-page insertion; guestbook page is server-rendered in guestbook.rs.
- Recommendation under discussion: Phase 1 = server-side capture from axum handlers + CSP hardening (zero browser risk); Phase 2 = origin split (id.browserid.me for key-custody pages) then locked-down self-hosted posthog-js on marketing origin only.

## Parked (2026-07-13)

Dan decided to reverse the order: do the origin-split spike first (browserid-ng-93z2) before any PostHog integration, since the split is the load-bearing unknown — browserid's RP flows depend on complex cross-origin interactions (hidden iframes, first-party popups) that the split may break. PostHog work resumes after the spike's findings.


## SHIPPED (2026-07-13) — hybrid analytics live in production

Two parts, both deployed and verified:

### Part A — www (marketing) client analytics
- Self-hosted, pinned posthog-js 1.399.2 (marketing/vendor/posthog.js, array.full.no-external — no runtime CDN/chunk loads). Loaded on landing + guestbook only.
- Ingestion reverse-proxied first-party via nginx /ingest -> us.i.posthog.com (marketing/nginx.conf). No third-party connection; ad-blockers don't eat it.
- Lockdown (marketing/analytics.js): autocapture off, session recording off, surveys off, advanced_disable_flags (kills remote-config/site-app injection), disable_external_dependency_loading, persistence localStorage (0 cookies), cross_subdomain_cookie false, person_profiles identified_only, before_send email/OTP redaction.
- Events: $pageview/$pageleave + explicit CTA events (audience_toggle, hero_cta_click, guestbook_link_click, guestbook_setup_expand).
- Verified: bundle loads (200), init clean (no JS errors, 0 cookies), bot-filter active, reverse-proxy delivers to project 509769 (proxy_smoke_test received).

### Part B — broker (auth origin) server-side funnel
- NO analytics JS on the auth origin. browserid-broker/src/analytics.rs: fire-and-forget PostHog capture, enabled iff POSTHOG_TOKEN set.
- PII-safe: users keyed by opaque sha256(email) -> u_<hex>; only email_domain sent; raw emails/codes/IPs never leave the process. Verified against a local mock (mixed-case input -> hashed id, domain only) and 3 unit tests.
- Events wired: signup_started (stage_user), signup_completed (complete_user_creation), email_verified (complete_email_addition), guestbook_signed (guestbook::sign, keyed by human principal).
- Verified in prod: "PostHog server-side analytics enabled" in logs; real signup_started landed in project 509769 with the exact expected hashed distinct_id, no raw email, no capture errors.

### Deploy
- www app redeployed (force-push, analytics assets).
- broker deployed to id (commit 443bf57), then config:set id POSTHOG_TOKEN=phc_... to enable. Disk held (~6.3G free; dep layer cached).
- e2e: 18/18 green (marketing-split, dialog-loads, new-user-signup) — no regression from the AppState.analytics field.

### Notes / follow-ups
- Client (anonymous www visitors) and server (hashed-email funnel) are NOT stitched — separate funnels by design. Stitching would need a distinct_id passed through the dialog; out of scope.
- IP: /ingest forwards X-Forwarded-For (geo for marketing analytics). Easy to strip for stricter privacy.
- Dashboards/funnels in PostHog UI still to be built (events are flowing; funnels can be assembled from signup_started -> signup_completed, and website analytics from pageviews).
- Auth-origin CSP tightening still tracked separately (browserid-ng-kt5y) — would add script-src/connect-src on browserid.me; not required for this since no analytics JS runs there.


## Dashboards (2026-07-13)
Created via API (project 509769):
- Product funnel (server-side): https://us.posthog.com/project/509769/dashboard/1839868
  — signup funnel (started→completed), new accounts/day, started-vs-completed, guestbook signings/day, emails verified/day, signups by email domain.
- Website (www): https://us.posthog.com/project/509769/dashboard/1839869
  — pageviews/day, unique visitors/day, top pages, landing→guestbook click funnel, CTA clicks/day, referrers.
Verified: tiles attached, queries compute against live data (6 pageviews, funnel step counts resolve). One synthetic signup_started (hello+phverify… prod test) is in the data — a single point, ignorable.

## Summary of Changes
Shipped hybrid PostHog analytics: locked-down self-hosted client on the www marketing origin (pageviews + CTAs), PII-safe server-side funnel from the broker on the auth origin (no analytics JS there), and starter dashboards. All verified in production. Follow-up: auth-origin CSP tightening (browserid-ng-kt5y). Client/server funnels intentionally not stitched.
