---
# browserid-ng-gsnm
title: Agent identity v3 — warrants, revocation, registrar unbundling
status: completed
type: epic
priority: high
created_at: 2026-07-10T15:23:20Z
updated_at: 2026-07-11T00:41:00Z
---

Umbrella for the agent-identity v3 design agreed 2026-07-10. Canonical plan: docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md. Ratified decisions: agent-ness protocol-visible (invisible mode removed), parent disclosure default-on, delegation-time-only scoping, per-audience user-signed warrants (audience privacy preserved structurally), agent-cert typ + warrant-in-chain (fail-closed), layered revocation (TTL + registry revoke + IETF status list), endorser role becomes registrar defaulting to the IdP itself (managed registrar = hosted product). Children: warrants (5zdh), revocation (egr7), registrar unbundling (1pnf), JIT consent flow (pz0f, blocked by 5zdh). GTM siblings outside the epic: landing repositioning (w7xu), verifier SDKs (exj6). Sequencing: spec v0.4 first (one coherent rev), then core/registrar/agent/rp implementation, then GTM claims flip on.

## Summary (2026-07-11)

All four children complete: capability constraints (5zdh), credential revocation + status lists (egr7), JIT consent flow (pz0f, incl. anti-phishing review), and registrar unbundling into the browserid-registrar component (1pnf). Agent identity v3 shipped end-to-end and deployed to browserid.me. The GTM-track beans (verifier availability exj6, DNSSEC host certs dff5) live independently and remain open.
