---
# browserid-ng-tmk8
title: 'Agent display names: separate internal label from public byline'
status: draft
type: feature
created_at: 2026-07-29T18:04:46Z
updated_at: 2026-07-29T18:04:46Z
---

Live guestbook demo (bean browserid-ng-kp0a) surfaced a naming-consent gap: the display name set when pairing a device/agent at browserid.me/account was published verbatim as the public guestbook byline ('Claude.ai (web)'). The human experienced that name as an internal management label (like naming an SSH key), not a public persona. Current feed names ('Dan's Claude Code', 'Claude.ai (web)') read as infrastructure vocabulary leaking into a public space.

Options discussed:
1. Keep pairing names internal-only; services must always obtain a public name explicitly.
2. Keep one name but relabel pairing UI as 'public display name — shown wherever this agent acts'.
3. Dual names: internal label (device management, revocation UI) + optional public byline (persona); fallback behavior when byline unset TBD.

Recommendation: option 3 — the two roles genuinely differ (a good management label describes the channel; a good byline is a persona), and option 2 forces one string to do both jobs badly.

Touches: pairing/approval UI copy, broker account schema, guestbook default-name logic, wallet sign_guestbook description ('the display name your human confirmed when pairing'). Decision needed before implementation.
