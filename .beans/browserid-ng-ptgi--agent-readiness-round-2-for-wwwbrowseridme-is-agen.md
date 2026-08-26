---
# browserid-ng-ptgi
title: Agent readiness round 2 for www.browserid.me (Is Agentic 93/100)
status: completed
type: feature
priority: normal
created_at: 2026-08-26T10:44:01Z
updated_at: 2026-08-26T11:01:12Z
---

Second Is Agentic audit round (93/100). Items 1–2 (search discoverability) are SEO/time-bound; actionable items:

- [x] JSON-LD structured data (SoftwareApplication) on the homepage, incl. offers (free) + sameAs
- [x] rel=canonical on all www pages (supports brand/domain discoverability)
- [x] "When to use" agent-instruction section in llms.txt
- [x] Pricing clarity: free/open-source statement in llms.txt, JSON-LD offers, openapi description
- [x] API versioning + deprecation policy: declare v1 stability + Deprecation/Sunset policy in openapi.json (both byte-synced copies); API-Version response header on broker public API endpoints
- [x] Tests: marketing/test.sh asserts for JSON-LD/canonical/llms.txt sections; broker agent_surface_test for API-Version header + spec sync
- [x] Verify locally (test.sh, cargo test), deploy, verify prod endpoints

## Summary of Changes

Shipped in 0c60c2f; deploy-www + deploy-broker CI green, prod verified 2026-08-26.

**www (marketing/):** homepage JSON-LD (`@graph`: WebSite + SoftwareApplication with `offers` price 0, MPL-2.0 license, sameAs GitHub, softwareHelp → llms.txt/openapi.json); `rel=canonical` on all six pages; llms.txt gains `## When to use BrowserID` (use cases, not-a-fit list, how-to-call), `## Pricing` (free, no API keys/billing, self-hostable, basics intended to stay free), and a versioning/deprecation bullet. test.sh: 7 new asserts (36 total), green locally and against prod.

**broker:** /verify, /validate-record, /status/check grouped into a versioned sub-router stamping `API-Version: 1` on every response (SetResponseHeaderLayer). openapi.json (both byte-synced copies): info.version 1.1.0; info.description declares the policy (paths stable as published, breaking changes only under a new prefix, `deprecated: true` + Deprecation/Sunset headers ≥90 days before removal, RFC 9745/8594) and `Pricing: free`; API-Version documented on the three endpoints via components.headers.ApiVersion. 2 new agent_surface_test cases; full broker suite green.

**Not addressed in code (SEO/time-bound):** brand + developer-resource search discoverability re-scores only after crawlers index the round-1 titles/sitemap; JSON-LD sameAs/canonical from this round help. Product-decision items: the 90-day deprecation window and the pricing wording ("basics intended to stay free") are commitments the user may want to adjust; visible on-page pricing/FAQ copy was deliberately left out to preserve the design.
