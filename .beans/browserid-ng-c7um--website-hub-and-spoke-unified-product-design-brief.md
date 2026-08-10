---
# browserid-ng-c7um
title: 'Website: hub-and-spoke unified product (design brief + build)'
status: in-progress
type: feature
priority: normal
created_at: 2026-08-10T12:18:12Z
updated_at: 2026-08-10T12:35:15Z
---

Expand www into hub-and-spoke unified product: home hub + /agents, /developers, /domains spokes, demos index, docs router. Design brief to feed Claude Design; then build.

## Progress (2026-08-10)

Design brief written: docs/plans/2026-08-10-website-design-brief.md.

Built (marketing/):
- Shared design system extracted to site.css (+ hub-and-spoke component styles);
  shared behaviors in site.js. index.html now links both.
- Home hub: kept agent-first hero + replay animation, added "one primitive,
  three doors" audience router + persistent DNS trust band; removed the deep
  #rp/#agents/#people sections (now on spokes).
- /agents spoke (agents.html): PAT-vs-warrant contrast lead, revoke-kills-agent
  trust band, live MCP demo section (JS+Python), JS/Python integration snippet
  (tabbed), Bluesky/guest-wall attributed-actions thread, wallet+revoke, GitHub
  flagship [coming soon].
- /developers spoke (developers.html): "email you already have" hero, 4 adapter
  cards, verify-in-one-call codebox, Google-claim section (live), trust band.
- /domains spoke (domains.html): "one DNS record" hero, DNS record codebox with
  off-ramp woven in, Workspace/Google section (live), per-tenant-key trust band,
  directory-sync + self-host-kit [coming soon].
- nginx.conf clean URLs for /agents /developers /domains; Dockerfile ships the
  new files.

All pages serve 200 locally; assets resolve; sections balanced.

TODO next:
- [ ] Owner eyeball / tweak copy
- [ ] Demos index page + Docs router (deferred; nav Docs → GitHub for now)
- [ ] Deploy www (CI/dokku) after review
