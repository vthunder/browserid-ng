---
# browserid-ng-lfpu
title: Per-holder / per-warrant last-used tracking (recency for the account roster)
status: todo
type: feature
created_at: 2026-07-29T23:03:59Z
updated_at: 2026-07-29T23:03:59Z
---

The redesigned /account roster sorts actors by recency and shows "last active …" per actor, and the inactive drawer should auto-demote actors unused for >90 days ("unused for 13 months"). The current API only exposes issued_at (device_certs, holders) and signed_at (warrants) — no usage timestamps.

Needed (per the design handoff's State Management section):
- [ ] Record last-used per holder: touch on access-cert mint (/access/mint), auth_with_presentation, and warrant registration/verification paths where the holder is known
- [ ] Record last-used per warrant: touch on verify-access / status checks where the warrant is identified
- [ ] Expose in /wsapi/holders (per HolderView) and /wsapi/warrants (per warrant): last_used_at (RFC3339, nullable)
- [ ] Frontend: switch the roster recency column + sort from issued_at to last_used_at, add "active now"/"N hours ago" formatting, and enable the >90-day auto-demotion rule for the Inactive drawer

Until then account.html deliberately degrades: shows added-on dates, sorts by issued_at, inactive = revoked-only.
