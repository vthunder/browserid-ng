---
# browserid-ng-xcy6
title: 'Dialog: atproto sign-in lane'
status: todo
type: feature
priority: normal
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T20:35:08Z
parent: browserid-ng-tsqk
blocked_by:
    - browserid-ng-5kf3
---

A third lane beside secondary-password and primary-popup. Mechanically the redirect/popup shape already built for primary IdPs, so most of primaryPopupFlow / primaryRedirectHop applies.

- [ ] Route to the bridge authorize page on the new address_info state
- [ ] Reuse the popup + redirect lanes (incl. the OAuth-redirect resume handback)
- [ ] Default the label to me@<handle> at claim time
