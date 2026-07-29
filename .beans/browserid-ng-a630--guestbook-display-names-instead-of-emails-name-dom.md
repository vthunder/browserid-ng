---
# browserid-ng-a630
title: 'Guestbook: display names instead of emails (name ✓ + domain tooltip)'
status: completed
type: feature
priority: normal
created_at: 2026-07-29T11:08:45Z
updated_at: 2026-07-29T11:45:22Z
---

Per discussion 2026-07-29:
- sign_guestbook gains optional `name` (free text per post); if omitted the broker defaults to the identity's stored pairing display name, falling back to email local-part.
- Display is ALWAYS just the agent name (on-behalf-of variant dropped from display; grantor still recorded internally).
- Rendered as '<name> ✓' with tooltip 'verified identity at <domain>'. Feed JSON carries name + domain, NEVER emails (raw emails stay server-side in guestbook.json for accountability).
- Strip checkmark glyphs from names so nobody renders a fake badge.

- [x] Broker: SignRequest.name, name resolution (param → stored display_name → local-part), Entry name/domain fields, feed JSON shape without emails, fallback page render
- [x] Marketing guestbook.html: render name ✓ + domain tooltip from new feed shape
- [x] Wallets (sdk/wallet + wallet-service): optional name param on sign_guestbook, description tells agent to default to pairing name / discuss with human
- [x] Tests: broker guestbook tests updated + name sanitization; wallet-service tests
- [x] Deploy broker + marketing + hosted wallet

## Summary of Changes

Shipped in 76fd310 + deployed 2026-07-29: broker (CI image), marketing (subtree push to www), hosted wallet (CI image), local wallet published as @browserid-ng/wallet 0.4.3.

- Broker guestbook: SignRequest.name (optional, per-post), resolution name -> pairing display_name -> local-part, sanitize_name strips controls/whitespace/checkmark glyphs + 48-char cap; Entry gains name/domain; feed serves PublicEntry (name, domain, scopes, at) — emails never leave the server (verified live: 0 entries contain @). SignResponse adds name (signer-private attribution kept). Unit tests added; full broker suite green.
- Broker fallback page + marketing guestbook.html: render name + badge with tooltip "verified identity at <domain>"; on-behalf-of display dropped (grantor still recorded server-side).
- Wallets: sign_guestbook name param + guidance to default to pairing name / agree with human on new names.
- e2e guestbook.spec.ts updated to assert the email-free feed shape.

Legacy entries derive name from email local-part at read time (live entries show e.g. danmills+claude until re-signed under a display name).
