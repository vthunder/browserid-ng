---
# browserid-ng-1w4g
title: 'Agent readiness round 3: trust pages, Organization JSON-LD, rate-limit headers, sitemap hardening (Is Agentic 95/100)'
status: completed
type: feature
priority: normal
created_at: 2026-08-26T12:07:21Z
updated_at: 2026-08-26T12:29:48Z
---

Third Is Agentic round (95/100). Item 1 (search discoverability) stays SEO/time-bound. Actionable:

- [x] Sitemap hardening: lastmod dates, new pages listed; broker 308s /sitemap.xml + /robots.txt to marketing (auditor may have probed the apex)
- [x] Trust anchor pages /about, /contact, /privacy (≥500 chars each, honest content), html + md mirrors, canonical, nginx clean URLs, footer links
- [x] Human-visible pricing copy (footer line + about page section) — report keeps flagging pricing
- [x] Organization JSON-LD with contactPoint (email); postal address deliberately omitted pending product decision
- [x] Rate limiting on verification API with real RateLimit-Limit/Remaining/Reset headers + Retry-After on 429; documented in openapi + llms.txt
- [x] Tests: marketing/test.sh new asserts; broker tests for redirects + rate-limit headers
- [x] Verify locally, deploy, verify prod

## Summary of Changes

Shipped in 4018a11; deploy-www + deploy-broker green, prod verified 2026-08-26.

**Trust pages:** /about (lineage, maintainer, visible Pricing section), /contact (GitHub issues, code@sandmill.org, [security] reporting lane), /privacy (plain-language: marketing PostHog posture incl. PostHog Inc. US processing, broker data inventory, public-by-design surfaces, deletion via /account, self-hosting escape hatch). Each: html + md mirror, canonical, clean URL in nginx, Dockerfile COPY, sitemap entry (all entries now carry lastmod). Footer sitewide: About · Contact · Privacy links + "Free — no paid tiers".

**JSON-LD:** homepage @graph gains a Person node (Dan Mills, mailto:code@sandmill.org, github.com/vthunder) as WebSite.publisher and SoftwareApplication.author — per user decision a real Person, NOT an invented Organization; postal address deliberately omitted. The audit's literal "Organization with contactPoint + PostalAddress" check will still fail — honesty over the point.

**Rate limiting:** new routes/rate_limit.rs — per-IP fixed window (300/60s, in-memory single-instance like the house throttles) on /verify, /validate-record, /status/check; RateLimit-Limit/Remaining/Reset on every response; structured JSON 429 (error.rate_limited) + Retry-After; API-Version layer outermost so 429s carry it. Documented in openapi.json 1.2.0 (info.description, per-endpoint headers, shared RateLimited response) and llms.txt.

**Apex crawl files:** broker /sitemap.xml + /robots.txt now 308 to the marketing origin (the audit found "no sitemap" because it probed the apex).

**Tests:** marketing/test.sh 36→50 asserts (green vs container AND prod); agent_surface_test 11→14; full broker suite green.

**Remaining / product decisions:** search discoverability items re-score only after indexing (Search Console submission + GitHub repo website field would help, need credentials); PostalAddress omitted by choice; rate-limit constant lives in rate_limit.rs (LIMIT) — keep openapi/llms.txt in sync if changed.
