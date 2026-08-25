---
# browserid-ng-n1fa
title: Agent readiness fixes for browserid.me (Ora audit 62/100)
status: in-progress
type: feature
priority: normal
created_at: 2026-08-25T19:23:10Z
updated_at: 2026-08-25T19:40:39Z
---

Improve agent readiness of https://browserid.me per Ora "Is Agentic" audit (62/100).

- [x] 1. Agent-friendly 404: markdown body with recovery links (llms.txt, sitemap, docs)
- [x] 2. Publish OpenAPI spec at /openapi.json
- [x] 3. JSON error responses for API paths
- [x] 4. Markdown content negotiation (acceptmarkdown.com: Accept: text/markdown + Vary: Accept)
- [x] 5. Developer resource discoverability (llms.txt links, titles/headings, predictable URLs)
- [x] Tests for every changed behavior
- [ ] Deploy + verify all public endpoints
