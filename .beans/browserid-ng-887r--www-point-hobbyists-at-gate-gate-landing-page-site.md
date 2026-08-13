---
# browserid-ng-887r
title: 'www: point hobbyists at gate — /gate landing page + site-wide placement'
status: completed
type: feature
created_at: 2026-08-13T09:40:27Z
updated_at: 2026-08-13T09:40:27Z
---

Gate is the first genuinely-useful (not demo) browserid app; the site now treats it as a product.

## Summary of Changes
- NEW /gate landing page: hero + install command, real console screenshots (light+dark, theme-swapped), why-not-a-key trio, sharing/roles split, 3-step quickstart, get-it CTA (README/npm). Restart/staging deliberately not mentioned (usage detail, per Dan).
- marketing/img/gate/: 4 real screenshots generated via Playwright against a live gateway (clean in-sync state, funnel-style host, role-foot restart caption removed for the roles shot)
- index.html: "Beyond demos · gate" split section (before Bluesky) with screenshot + CTA; theme-swap CSS
- demos.html: ★ row "Not a demo — publish your own" with install command
- developers.html: Thread 2 now leads with the zero-code gate path
- llms.txt: gate entry first in "What problems this solves"
- nav on all pages: Gate spoke; nginx.conf clean URL for /gate
