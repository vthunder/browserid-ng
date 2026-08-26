---
# browserid-ng-jubb
title: Publish /principles page + align README/site copy with the principles
status: completed
type: task
priority: normal
created_at: 2026-08-26T18:29:50Z
updated_at: 2026-08-26T18:35:25Z
---

Follow-up to bean 0med (principles first cut) and the holistic principles audit. Approved scope:

- [x] /principles on www: verbatim docs/principles.md content, html + md mirror, canonical, nginx clean URL, Dockerfile COPY, sitemap entry, footer link on all pages, llms.txt link
- [x] Last-updated timestamp on docs/principles.md and the page
- [x] README: link principles near the top; fix "nothing breaks if browserid.me disappears" overclaim (→ scaffolding is replaceable even if browserid.me disappears); remove "humans-only" language (→ delegated grants opt-in)
- [x] Sweep any other "humans-only" phrasing in repo copy (only README was live copy; two docs/plans hits are archival)
- [x] /developers: one-sentence honest note that the hosted verifier sees sign-ins; self-host to avoid
- [x] test.sh coverage for /principles; run tests, deploy, verify prod

Explicitly deferred: /about rework (bean yvld, needs Dan's "why I built this" input). Google/OIDC bridge copy left as-is (status quo defensible per Dan; generic OIDC bridge is roadmap).

## Summary of Changes

Shipped in 3df60b6; deploy-www green, prod verified 2026-08-26 (54/54 asserts vs prod, /principles serves html + markdown negotiation, timestamp present).

- /principles: verbatim docs/principles.md in the house page style (Why now + seven principles), md mirror, canonical, nginx clean URL, Dockerfile COPY, sitemap lastmod entry, footer link on all 10 pages, llms.txt link, closing link back to the repo file.
- Timestamps: *Last updated: 2026-08-26* on docs/principles.md, the md mirror, and the page hero.
- README: principles linked under the lede; overclaim fixed ("every hosted piece is scaffolding you can replace, even if browserid.me disappears"); "humans-only by default" -> "delegated agent grants opt-in".
- /developers: "One honest note: the hosted verifier sees which of your users sign in - run your own if you'd rather it didn't." (html + md).
- Deliberately unchanged: Google sign-in copy (status quo defensible per Dan; generic OIDC bridge is roadmap); /about rework deferred to bean yvld.

Note: marketing/principles.md + principles.html now DUPLICATE docs/principles.md by hand - no sync test exists (unlike openapi.json). If the principles get edited again, update all three or consider adding a sync check.
