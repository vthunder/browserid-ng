---
# browserid-ng-a2eu
title: Dialog popup hangs silently when window.open is blocked (WinChan handshake lost)
status: todo
type: bug
priority: normal
created_at: 2026-07-13T19:06:06Z
updated_at: 2026-07-13T19:06:06Z
blocked_by:
    - browserid-ng-h3u3
---

Root-caused during FedCM testing (browserid-ng-mhyp): when the sign-in popup is blocked by the browser (or opened late via the popup-blocker toolbar), the dialog HANGS on 'Loading…' forever. Cause: /sign_in redirects to /dialog/dialog.html WITHOUT an ?origin param (mod.rs SIGN_IN_HTML), so the dialog relies entirely on the WinChan.onOpen handshake with its opener (dialog.js:1553-1573). A blocked/re-opened popup is no longer the window WinChan is talking to, so onOpen never fires / throws ('WinChan not available: undefined'), init() never runs, and the dialog is stuck.

Same fragility class as the mobile primary-IdP popup bug (browserid-ng-h3u3): a blocked popup fails silently.

Fix options:
- Dialog: if neither ?origin nor a WinChan handshake arrives within a short timeout, show an actionable error ('popup was blocked — click to retry') instead of hanging.
- Preserve origin across the /sign_in -> /dialog redirect so the dialog can init even without WinChan.
- Broader: a redirect-based (same-window) sign-in flow as a popup-blocker-proof fallback (ties into h3u3).

Not caused by FedCM, but FedCM's post-gesture popup fallback newly triggered it on desktop Chrome — since removed (include.js now uses FedCM exclusively when opted in, no post-gesture popup).
