---
# browserid-ng-jubb
title: Publish /principles page + align README/site copy with the principles
status: in-progress
type: task
priority: normal
created_at: 2026-08-26T18:29:50Z
updated_at: 2026-08-26T18:32:16Z
---

Follow-up to bean 0med (principles first cut) and the holistic principles audit. Approved scope:

- [x] /principles on www: verbatim docs/principles.md content, html + md mirror, canonical, nginx clean URL, Dockerfile COPY, sitemap entry, footer link on all pages, llms.txt link
- [x] Last-updated timestamp on docs/principles.md and the page
- [x] README: link principles near the top; fix "nothing breaks if browserid.me disappears" overclaim (→ scaffolding is replaceable even if browserid.me disappears); remove "humans-only" language (→ delegated grants opt-in)
- [x] Sweep any other "humans-only" phrasing in repo copy (only README was live copy; two docs/plans hits are archival)
- [x] /developers: one-sentence honest note that the hosted verifier sees sign-ins; self-host to avoid
- [ ] test.sh coverage for /principles; run tests, deploy, verify prod

Explicitly deferred: /about rework (bean yvld, needs Dan's "why I built this" input). Google/OIDC bridge copy left as-is (status quo defensible per Dan; generic OIDC bridge is roadmap).
