---
# browserid-ng-1w4g
title: 'Agent readiness round 3: trust pages, Organization JSON-LD, rate-limit headers, sitemap hardening (Is Agentic 95/100)'
status: in-progress
type: feature
priority: normal
created_at: 2026-08-26T12:07:21Z
updated_at: 2026-08-26T12:22:17Z
---

Third Is Agentic round (95/100). Item 1 (search discoverability) stays SEO/time-bound. Actionable:

- [x] Sitemap hardening: lastmod dates, new pages listed; broker 308s /sitemap.xml + /robots.txt to marketing (auditor may have probed the apex)
- [x] Trust anchor pages /about, /contact, /privacy (≥500 chars each, honest content), html + md mirrors, canonical, nginx clean URLs, footer links
- [x] Human-visible pricing copy (footer line + about page section) — report keeps flagging pricing
- [x] Organization JSON-LD with contactPoint (email); postal address deliberately omitted pending product decision
- [x] Rate limiting on verification API with real RateLimit-Limit/Remaining/Reset headers + Retry-After on 429; documented in openapi + llms.txt
- [x] Tests: marketing/test.sh new asserts; broker tests for redirects + rate-limit headers
- [ ] Verify locally, deploy, verify prod
