---
# browserid-ng-yvld
title: Rework /about, /contact, /privacy page content
status: todo
type: task
created_at: 2026-08-26T13:46:09Z
updated_at: 2026-08-26T13:46:09Z
---

The trust pages shipped in bean 1w4g (commit 4018a11) were first-draft copy written to satisfy the Is Agentic audit (real pages, ≥500 chars, honest content). Dan wants to rework the content on all three.

Constraints to keep when rewriting:
- [ ] Rework /about copy (about.html + about.md)
- [ ] Rework /contact copy (contact.html + contact.md)
- [ ] Rework /privacy copy (privacy.html + privacy.md)
- [ ] Keep html and md mirrors in sync (Accept: text/markdown negotiation serves the .md)
- [ ] Keep the anchors/claims tests rely on: marketing/test.sh asserts canonical + ≥500 chars of text per page, "Everything is free" on /about, and the /about#pricing anchor is linked from llms.txt
- [ ] Privacy claims must keep matching the implementation (PostHog posture, broker data inventory, deletion via /account); update "Last updated" date on change
- [ ] Run marketing/test.sh before deploying
