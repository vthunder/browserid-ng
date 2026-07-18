---
# browserid-ng-0iwl
title: Phase 5 — Consumer migration (mingo parallel; SBO no-op)
status: scrapped
type: task
priority: normal
created_at: 2026-07-17T23:05:30Z
updated_at: 2026-07-18T19:40:38Z
parent: browserid-ng-oup3
---

SBO: verifier-only, unaffected (possible browserid-core pin bump only if JWS shape changes -- it does not per D1). mingo CLI: endpoint unification when browserid-agent collapses self/agent onto one mint (pin bump, not rewrite). mingo-idp/mingo-web: PARALLEL migration -- its own hidden-iframe/postMessage/SameSite=None/FedCM silent stack (provision.html, provisioning_api.js, routes.rs:279-291, mingo-web/app.js) undergoes the same browser-as-first-agent treatment; mingo-idp/agent.rs is already the mint endpoint to unify onto. See docs/plans/2026-07-18-model-a-browser-first-agent-migration-plan.md §5.

## Required-subjects migration (2026-07-18)
subjects/subject are REQUIRED with no deprecation window: existing agent P_certs (mingo CLI) stop working on ship. Action: bump browserid-agent to emit subjects:[agent]; coordinate mingo CLI re-bootstrap (it re-mints on demand, needs a fresh P_cert).

## Reasons for Scrapping
Superseded by the device-cert model migration plan (docs/plans/2026-07-18-device-cert-model-migration-plan.md). Re-scoped into new device-cert phase beans under oup3.
