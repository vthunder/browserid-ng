---
# browserid-ng-9rlu
title: Activate identities from /account — primary + derived-chain cert issuance
status: draft
type: feature
priority: normal
created_at: 2026-07-10T20:51:10Z
updated_at: 2026-07-10T21:09:44Z
---

From /account UX review (2026-07-10). Identities show active/needs-sign-in status; "activate" should get a fresh cert without leaving the page. Straightforward for some, murky for others:

- **Secondary (broker-verified)** email, session present: generate a keypair, /wsapi/cert_key, cache locally. Works today — implement in the /account restructure.
- **Primary** identity (e.g. dan@mingo.place): needs the primary IdP's own auth/provisioning flow (the dialog's handlePrimaryIdP). A "Sign in at <idp>" link is the honest minimum.
- **Derived / parent-chained** (dan@mingo.place's control roots in danmills@sandmill.org): to get a dan@mingo.place cert you must first authenticate the parent (sandmill.org), then use that to provision at mingo.place. Open question vthunder raised: **do we have enough metadata on /account to drive the second hop automatically?** Probably not today — the parent link (derived map) tells us who to auth, but not the mingo.place provisioning entry point. Needs: discover the child's IdP (from the email domain / address_info), then run its provisioning against the parent session.

## Scope
- Now (restructure pass): status indicators for all; inline activate for secondary; "Sign in at <idp>" link for primary.
- This bean: the full primary + derived-chain reactivation driven from /account.

## Finding (2026-07-10): IdP /auth is a dialog shim, not a standalone page
mingo.place/auth calls navigator.id.beginAuthentication (authentication_api.js) and only completes when opened *inside* the browserid dialog's provisioning flow; opened top-level it hangs at 'Checking your session…'. So a primary identity cannot be activated by linking to <idp>/auth. Interim /account behavior: link to the app (domain root) so the user signs in via the real dialog flow (which caches the cert at browserid.me origin). Full in-place activation still needs to drive the dialog/provisioning programmatically from /account (this bean).
