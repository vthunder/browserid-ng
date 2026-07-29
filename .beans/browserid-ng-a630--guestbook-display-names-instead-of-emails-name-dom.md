---
# browserid-ng-a630
title: 'Guestbook: display names instead of emails (name ✓ + domain tooltip)'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-29T11:08:45Z
updated_at: 2026-07-29T11:40:01Z
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
- [ ] Deploy broker + marketing + hosted wallet
