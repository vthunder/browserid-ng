---
# browserid-ng-v96n
title: Move the guestbook out of the broker
status: todo
type: feature
priority: normal
created_at: 2026-08-06T15:03:49Z
updated_at: 2026-08-06T15:03:49Z
---

The guestbook is a demo/marketing feature living inside the identity broker. It should not be there.

## Why this is wrong
The broker (`id`, browserid.me) is the most security-critical service we run — it holds the root signing key and every account. It currently also:
- serves `GET /guestbook/feed` and the sign endpoint,
- stores guestbook entries as `guestbook.json` on its own persistent mount (alongside `broker-key.json` and `browserid.db`),
- redirects `GET /guestbook` (308) to the marketing site.

So an unauthenticated, world-readable, user-writable feature shares a process and a storage volume with the root key. Nothing has gone wrong, but the coupling is indefensible: every future guestbook change is a change to the broker, and any guestbook bug is a broker bug.

Related: `guestbook-mcp` (guestbook-mcp.browserid.me) is the MCP face of the same feature and holds no state of its own — it depends on the broker's API too.

## Where it should live
Either part of the marketing site (`marketing/`, deployed as `www`) with its own small backend, or a standalone demo app. It needs a store of its own; `guestbook.json` must migrate out of the broker's volume.

Keep it on a `browserid.me` name (the domain is the trust boundary — see sandmill-infra README), so it stays on the identity host; the win here is process/volume separation, not host separation.

## Scope
- [ ] Decide host app: marketing backend vs standalone demo service
- [ ] Move the feed/sign endpoints out of browserid-broker
- [ ] Migrate guestbook.json off the broker's storage mount to the new app's own
- [ ] Repoint guestbook-mcp and the marketing page at the new origin
- [ ] Keep the 308 from the apex, or retire it
- [ ] Remove the guestbook code and its storage from the broker

## Context
Surfaced 2026-08-06 while deciding host placement for the identity split (browserid-ng-gzq7). The related XSS-escaping gap in the guestbook page was fixed separately at that time.
