---
# browserid-ng-yvld
title: Rework /about, /contact, /privacy page content
status: in-progress
type: task
priority: normal
created_at: 2026-08-26T13:46:09Z
updated_at: 2026-08-26T19:57:41Z
---

The trust pages shipped in bean 1w4g (commit 4018a11) were first-draft copy written to satisfy the Is Agentic audit (real pages, ≥500 chars, honest content). Dan wants to rework the content on all three.

Constraints to keep when rewriting:
- [x] Rework /about copy (about.html + about.md) — v2 shipped: minimal first-person story + principles spirit + try-it CTA; pricing reduced to a clause; heading/who-runs-it/pricing-section/design-paragraph all cut per Dan
- [ ] Rework /contact copy (contact.html + contact.md)
- [ ] Rework /privacy copy (privacy.html + privacy.md)
- [ ] Keep html and md mirrors in sync (Accept: text/markdown negotiation serves the .md)
- [ ] Keep the anchors/claims tests rely on: marketing/test.sh asserts canonical + ≥500 chars of text per page, "Everything is free" on /about, and the /about#pricing anchor is linked from llms.txt
- [ ] Privacy claims must keep matching the implementation (PostHog posture, broker data inventory, deletion via /account); update "Last updated" date on change
- [ ] Run marketing/test.sh before deploying

## Direction from Dan (2026-08-26) — /about rework

Cut entirely: current heading + subheading (off-putting); "Who builds and runs it" section; the Pricing section (came from the is-agentic checklist, Dan hates it here); "The design in one paragraph".
Keep/rework: "Where it comes from" is more or less ok, keep some.
New structure: (1) backstory — why Dan is building this; (2) lean hard on the principles (summarize/paraphrase/link to /principles). That's about it.

Open dependency: pricing must find a new home before the /about section is removed — test.sh asserts "Everything is free" on /about, llms.txt links /about#pricing, and JSON-LD offers reference it conceptually. Candidates: footer line only, or a line on /developers.
