---
# browserid-ng-850o
title: Re-offer a moved/removed device's grants when it re-registers
status: draft
type: feature
created_at: 2026-07-22T20:49:35Z
updated_at: 2026-07-22T20:49:35Z
parent: browserid-ng-oup3
---

Dan (2026-07-22): when a device with grants is MOVED to another namespace, its isolated (<id>) warrants necessarily die (new holder id). It would be nice to offer re-creating all its previous grants the next time that device signs in.

Sketch: at move time, snapshot the holder's isolated grants (audience+scopes+delegator) alongside the holder_moves redirect row. When the device completes the move (re-issues under the target holder), the dialog/account surface offers "restore N grants?" — re-signing each with the config cert (the same client-side signing path as consent), matcher = the new <id>. Needs: a place to stash the snapshot (holder_moves table or a sibling), a UI surface (the dialog post-reissue, or a badge/prompt on /account), and the signing flow wiring. Note removal cleanup now revokes+deletes isolated warrants at forget/move-completion time, so the snapshot must be taken BEFORE cleanup.
