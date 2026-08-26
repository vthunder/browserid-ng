---
# browserid-ng-fip9
title: Guardrails against principles three-copy drift
status: completed
type: task
priority: normal
created_at: 2026-08-26T19:19:30Z
updated_at: 2026-08-26T19:20:19Z
---

docs/principles.md is duplicated by hand into marketing/principles.md and marketing/principles.html (bean jubb). Add drift locks:

- [x] Rust test (agent_surface_test.rs, runs in the always-on CI test workflow): docs/principles.md byte-identical to marketing/principles.md
- [ ] test.sh: principles.html must contain every paragraph of docs/principles.md (tags stripped, whitespace/punctuation normalized)
- [x] Run both suites, commit, CI green

## Summary of Changes

Two-layer drift lock, mirroring the openapi.json pattern:
- cargo test `test_principles_doc_matches_marketing_mirror` (agent_surface_test.rs) pins docs/principles.md == marketing/principles.md byte-for-byte; runs in the always-on CI test workflow, so a docs-only edit fails CI even if no www deploy happens.
- marketing/test.sh: byte-compare of the mirror plus a normalized-text containment check that principles.html carries every paragraph of the doc (tags stripped, backticks/asterisks dropped, whitespace + space-before-punctuation normalized). Negative-tested: a one-word mutation in the html is caught.

56/56 marketing asserts + 15/15 agent_surface tests green.
