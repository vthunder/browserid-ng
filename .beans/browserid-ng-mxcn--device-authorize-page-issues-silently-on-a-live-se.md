---
# browserid-ng-mxcn
title: device-authorize page issues silently on a live session - no consent gesture
status: todo
type: bug
priority: high
created_at: 2026-08-28T21:33:59Z
updated_at: 2026-08-28T21:34:07Z
parent: browserid-ng-9yyk
---

Follow-up to 9it0 (found while fixing it). The 9it0 same-origin rule stops the mismatched-lane exfiltration, but the ceremony page still auto-issues via the /idp/whoami session-skip: a victim with a live tenant/IdP session who merely LOADS the page (e.g. a link with attacker pubkeys + attacker return_origin AND matching return_url, or an attacker-opened popup using the postMessage lane) gets certs minted for the attacker's keys with NO user gesture. The first-party sign-in is the residual guard, and the session-skip removes it exactly when the victim is warmest. Fix direction: when the session-skip fires (no password typed this visit), require an explicit in-page consent click (Authorize this device for email?) before issueCerts; keep silent reissue only for the wallet's embedded-partition case if it can be distinguished (or accept one click there too). Applies to the shared page, so it covers hosted tenants today and the fallback role when it mounts (d0xb).
