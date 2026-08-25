---
# browserid-ng-n1fa
title: Agent readiness fixes for browserid.me (Ora audit 62/100)
status: completed
type: feature
priority: normal
created_at: 2026-08-25T19:23:10Z
updated_at: 2026-08-25T19:48:51Z
---

Improve agent readiness of https://browserid.me per Ora "Is Agentic" audit (62/100).

- [x] 1. Agent-friendly 404: markdown body with recovery links (llms.txt, sitemap, docs)
- [x] 2. Publish OpenAPI spec at /openapi.json
- [x] 3. JSON error responses for API paths
- [x] 4. Markdown content negotiation (acceptmarkdown.com: Accept: text/markdown + Vary: Accept)
- [x] 5. Developer resource discoverability (llms.txt links, titles/headings, predictable URLs)
- [x] Tests for every changed behavior
- [x] Deploy + verify all public endpoints

## Summary of Changes

Shipped in f82a08a; both images released by CI and verified on prod 2026-08-25.

**www (marketing/, nginx):** `Accept: text/markdown` negotiation on all six pages (.md variants reuse page copy; `text/markdown; charset=utf-8` + `Vary: Accept` per acceptmarkdown.com); markdown 404 (`404.md`) with recovery links; `/openapi.json` (CORS-open); JSON 404s on `/api/*`; `robots.txt` + `sitemap.xml`; llms.txt expanded (API section, markdown-mirror note, product name); page titles now carry "BrowserID". `marketing/test.sh` (29 asserts) gates the deploy-www workflow.

**broker (apex):** axum fallback 404 — markdown site map by default, structured JSON (`{error:{code,message,hint,docs}}`) for /wsapi//api/fedcm//idp or Accept: application/json, HTML for browsers, `Vary: Accept`; `/openapi.json` compiled in (byte-sync with marketing copy enforced by test); `/llms.txt` 308s to the marketing origin; malformed bodies on /verify-access, /validate-record, /status/check now return JSON 400s (`error.bad_request_json`) instead of axum plain-text. Root Dockerfile copies `browserid-broker/openapi.json` (include_str). 8 new tests in `tests/agent_surface_test.rs`; full broker suite + marketing-split e2e green.

**Known non-issues:** HTML responses on www now carry `charset=utf-8` (nginx charset always covers text/html). Prod shows two Vary headers (proxy adds Accept-Encoding) — legal, semantically merged.

**Left for product decisions:** verify-quickstart.md still documents a `/verify` endpoint with an `assertion` field, but the real route is `/verify-access` with `presentation` (spec follows the code); search-engine indexing of the new titles/sitemap takes time — the "discoverability by name" audit item re-scores only after crawlers pick it up.
