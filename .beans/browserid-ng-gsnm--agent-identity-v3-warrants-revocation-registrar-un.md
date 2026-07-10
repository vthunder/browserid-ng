---
# browserid-ng-gsnm
title: Agent identity v3 — warrants, revocation, registrar unbundling
status: todo
type: epic
priority: high
created_at: 2026-07-10T15:23:20Z
updated_at: 2026-07-10T15:24:54Z
---

Umbrella for the agent-identity v3 design agreed 2026-07-10. Canonical plan: docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md. Ratified decisions: agent-ness protocol-visible (invisible mode removed), parent disclosure default-on, delegation-time-only scoping, per-audience user-signed warrants (audience privacy preserved structurally), agent-cert typ + warrant-in-chain (fail-closed), layered revocation (TTL + registry revoke + IETF status list), endorser role becomes registrar defaulting to the IdP itself (managed registrar = hosted product). Children: warrants (5zdh), revocation (egr7), registrar unbundling (1pnf), JIT consent flow (pz0f, blocked by 5zdh). GTM siblings outside the epic: landing repositioning (w7xu), verifier SDKs (exj6). Sequencing: spec v0.4 first (one coherent rev), then core/registrar/agent/rp implementation, then GTM claims flip on.
