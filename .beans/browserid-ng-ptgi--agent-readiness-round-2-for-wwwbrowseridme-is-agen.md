---
# browserid-ng-ptgi
title: Agent readiness round 2 for www.browserid.me (Is Agentic 93/100)
status: in-progress
type: feature
priority: normal
created_at: 2026-08-26T10:44:01Z
updated_at: 2026-08-26T10:51:15Z
---

Second Is Agentic audit round (93/100). Items 1–2 (search discoverability) are SEO/time-bound; actionable items:

- [x] JSON-LD structured data (SoftwareApplication) on the homepage, incl. offers (free) + sameAs
- [x] rel=canonical on all www pages (supports brand/domain discoverability)
- [x] "When to use" agent-instruction section in llms.txt
- [x] Pricing clarity: free/open-source statement in llms.txt, JSON-LD offers, openapi description
- [x] API versioning + deprecation policy: declare v1 stability + Deprecation/Sunset policy in openapi.json (both byte-synced copies); API-Version response header on broker public API endpoints
- [x] Tests: marketing/test.sh asserts for JSON-LD/canonical/llms.txt sections; broker agent_surface_test for API-Version header + spec sync
- [ ] Verify locally (test.sh, cargo test), deploy, verify prod endpoints
