---
# browserid-ng-kc7g
title: 'Marketing site v3: implement Claude-design handoff (IA restructure)'
status: completed
type: feature
priority: normal
created_at: 2026-08-11T20:18:00Z
updated_at: 2026-08-11T20:33:57Z
---

Implement the v3 marketing site design from the handoff bundle (~/BrowserID refresh mockup review.zip → design_handoff_site_v3/).

IA changes:
- [x] Rebuild index.html per Homepage v3 (keep hero+approval card + problem section from production; guestbook section; Bluesky level-up; door cards; new footer)
- [x] Rebuild developers.html per Developers v3
- [x] Rebuild domains.html per Domains v3
- [x] New demos.html per Demos v3
- [x] Delete agents.html; add /agents → / redirect in nginx.conf (also deleted guestbook.html; /guestbook → /#guestbook per owner decision in handoff)
- [x] Ship llms.txt at site root as text/plain (nginx location if needed)
- [x] Nav on all pages: Developers · Domains · Demos · Docs · Sign in
- [x] New footer on all pages (llms.txt line)
- [x] Keep theme toggle/light theme, analytics, config.js authOrigin, guestbook feed JS, copy buttons
- [x] Update e2e marketing tests (/agents removed, /demos added, nav/demo link targets)
- [x] Verify locally (serve + check pages, both themes)

## Summary of Changes

Implemented the v3 marketing-site design from the Claude-design handoff bundle (design_handoff_site_v3), section-for-section against the four .dc.html references, copy ported verbatim, both themes via the existing site.css tokens.

- **index.html** rebuilt: hero + approval card and problem section carried over from production unchanged; new #try/#guestbook section (wallet tabs + prompt + live wall, no Full-guestbook link); Level-up Bluesky section; two door cards (Developers/Domains); new footer with llms.txt line. Wall error fallback no longer links /guestbook.
- **developers.html** rebuilt: hero → #signin verify split → #adapters (4 cards) → #mcp (PAT-contrast lede, JS/Python code tabs reusing the agents.html tab JS) → #claim (3-bullet sign-in hierarchy, trimmed mock) → crosslinks.
- **domains.html** rebuilt: managed identities first (4 bullets incl. per-tenant keys), #how with the new from-setup-to-exit 3-step card (replaces the DNS snippet), roadmap cards, crosslinks. No Google Workspace section, no trust band.
- **demos.html** NEW: setup-once wallet panel + numbered rows (guestbook / Bluesky / revoke-kills-an-agent / mingo.place / FedCM / build-your-own); cyan/gold/muted numbering.
- **agents.html + guestbook.html deleted**; nginx.conf: /agents → 301 /, /guestbook → 301 /#guestbook, clean URLs now (developers|domains|demos), llms.txt no-cache location. Dockerfile COPY list updated.
- **llms.txt** shipped as-is at the site root.
- **site.css**: hero-lite rescaled to v3 (38px), new .doors/.door, .demorows/.demorow, .setup-panel, .flow-card components, .textlink, checklist.cyan, btn-ghost.cyan; wall check now green per mockup; dead hub-and-spoke CSS removed (.router/.rcard, .contrast/.ccol, .trustband, .why3, .wall-more).
- **analytics.js**: dead selectors (.aud-toggle, .try summary, a[href=/guestbook]) replaced with v3 hooks (guestbook_link_click on /#guestbook, wallet_tab_click, door_click); #bskyCta id kept on the home CTA.
- **e2e**: marketing-split.spec.ts updated — wall tests target index #wall, new v3 nav/redirect test, test server mirrors the nginx redirects. All 6 pass against a local broker.

Verified: full-page screenshots of all four pages in dark + light (no console/page errors), Playwright suite green. Not done here (out of scope): the broker legacy static pages (browserid-broker/static/agents.html etc., served only when MARKETING_URL is unset) still exist; docker build not run locally (no docker; CI builds the image).
