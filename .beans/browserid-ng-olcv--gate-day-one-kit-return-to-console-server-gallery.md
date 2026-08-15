---
# browserid-ng-olcv
title: 'Gate day-one kit: return-to-console, server gallery, /shared member landing'
status: completed
type: task
created_at: 2026-08-15T15:41:47Z
updated_at: 2026-08-15T15:41:47Z
parent: browserid-ng-rjmm
---

Dan's UX round (2026-08-15), commit 7877552, gate 0.10.0 + mcp-auth 0.5.1:

- [x] Authoring ceremony return_url -> admin lands back in the console after signing
- [x] Curated server gallery (8 self-host-worthy MCP servers with title/description/repo/command/env notes; Use-this prefills the add dialog; startup command print still the review gate)
- [x] /shared member landing: one shareable url; members sign in (identity-first machinery) and see their servers with connector URLs + per-agent instructions (Claude web, Claude Code, Cursor) + account switch; mode-unified entitlement; connect/shared reserved slugs; sign-in card links non-admins there
- [x] Earlier same day: authoring pin (signed-by fixed to admin), grants liveness (broker-revoked grants resurface as pending + stop admitting), sync-pill grants status, connect interstitial, signed-grants deployment option (local default)

Remaining ideas parked: first-run checklist strip, per-person connected/last-used status, share-card mailto invites, npx demo command.
