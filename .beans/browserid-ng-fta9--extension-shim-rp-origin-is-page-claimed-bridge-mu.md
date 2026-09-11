---
# browserid-ng-fta9
title: 'Extension shim: RP origin is page-claimed; bridge must use sender.origin'
status: todo
type: bug
priority: high
created_at: 2026-09-11T12:37:14Z
updated_at: 2026-09-11T13:12:10Z
blocking:
    - browserid-ng-g69e
---

wallet/extension/shim.js sends origin: location.origin via postMessage; relay.js only checks ev.source === window; background.js forwards msg.payload.origin and ignores sender; wallet/src/server.js /login documents the origin as caller-claimed. Any page script can obtain a presentation for aud = another origin (assertion theft within the assertion window). Fix: background.js derives origin from sender (sender.origin / new URL(sender.tab.url).origin), refuses non-top frames or carries the frame origin explicitly, drops payload.origin; the wallet treats only extension-supplied origins as authenticated. Blocks any non-login kind riding the bridge (g69e, request lanes design).
