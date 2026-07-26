---
# browserid-ng-f7i8
title: 'www.browserid.me refresh: bsky demo featured, content aligned to grantor/grantee model'
status: in-progress
type: task
priority: normal
created_at: 2026-07-26T00:42:41Z
updated_at: 2026-07-26T01:12:58Z
---

Dan's ask (2026-07-25): feature the Bluesky demo as THE way to test; keep other demos (guestbook, mingo) as additional; audit all landing content against the current protocol/UI; verify the guestbook demo still works.

Stale content found in marketing/index.html:
- Hero consent mock predates the k0s9 card redesign (no For/By, no fingerprint; 'researcher@browserid.me' is a bare top-level agent handle that the current model doesn't mint — agents are +tag sub-addresses)
- 'For apps' code: who.agent?.parent —现actual model is attributed identity (grantor) + actor (grantee); should read as attribution
- 'For agents' code: provision({as}) / obtainWarrant pseudo-API vs real @browserid-ng/agent requestProvision/grants
- No Bluesky bridge anywhere; guestbook is the featured demo
- [ ] verify guestbook demo (feed + MCP sign) still works
- [x] rewrite index.html: bsky featured, aligned copy/mocks/code — plus the guestbook merged onto the homepage as a live wall (Dan's call); deployed via subtree push to dokku www (21608e7)
- [x] deploy www app + live check (new sections live; /guestbook intact; feed CORS verified)

## Guestbook verification findings

The mechanism works but surfaced two real bugs, both fixed today: the wallet crashed on legacy pre-device-model credentials (0.2.1, needs npm publish) and /warrant/request rejected primary-issued agent certs, locking every primary-rooted user out of the consent flow (fixed in 5fe419c, deployed). Production wall was empty (guestbook.json never created on the current mount); first signed entry pending Dan's consent approval — which is also the first live render of the new B1 card.
