---
# browserid-ng-h3u3
title: 'Mobile: primary IdP auth fails due to popup blocking'
status: todo
type: bug
created_at: 2026-07-13T08:26:55Z
updated_at: 2026-07-13T08:26:55Z
---

Observed by Dan while testing on mobile (2026-07-13): primary IdPs don't work on mobile because the browser blocks the popup. Likely the popup open happens outside (or too long after) the user-gesture window, or mobile browsers are stricter about window.open during the auth handoff to the primary IdP.

Debug later:
- Reproduce on iOS Safari / Android Chrome
- Check where window.open is called for the primary IdP flow relative to the user gesture
- Consider fallback: same-tab redirect flow when popup is blocked, or detect blocked popup and show a tap-to-continue affordance
