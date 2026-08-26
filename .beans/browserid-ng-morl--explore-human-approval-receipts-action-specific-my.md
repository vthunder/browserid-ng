---
# browserid-ng-morl
title: 'Explore: human-approval receipts — action-specific ''my human approved this'' in a presentation'
status: draft
type: feature
created_at: 2026-08-26T23:21:52Z
updated_at: 2026-08-26T23:21:52Z
---

## Idea

The constructive counterpart to principle 5's negative claim ("no protocol can tell which actors are human"). Sites usually don't need "the actor is human" — they need "a human approved this specific action." The consent ceremony already exists; extend it so a wallet can attach a fresh, action-specific human-approval signature to a presentation: "my human clicked yes on this purchase / post / booking."

No CAPTCHA can express this, it's agent-friendly by construction, and it demos well: agent browses and drafts freely, but checkout requires the human-approval bit.

## Open questions

- Binding semantics: what exactly is approved — a canonical, human-readable action description whose digest is signed? Who authors that description (site proposes, wallet displays verbatim)?
- Approval fatigue: this only works if reserved for consequential actions; how does a site request it (a scope flag like approval:required on specific operations)?
- Freshness/replay: receipt must be single-use and bound to the action instance (jti + tight expiry).
- Relation to warrant-v2 signing grants: grants are consent-minted standing authority; this is per-action elevation on top — same ceremony, different lifetime.
- Where the human is: the approval has to reach them (ties into the wallet push channel — see the native-wallet exploration).

## First steps

- [ ] Design sketch: presentation extension + site-side request flow
- [ ] Demo shape: guestbook or mingo action that requires a receipt while everything else flows free
