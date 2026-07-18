---
# browserid-ng-6gs4
title: Phase 4 — Iframe retirement
status: scrapped
type: task
priority: normal
created_at: 2026-07-17T23:05:30Z
updated_at: 2026-07-18T19:40:38Z
parent: browserid-ng-oup3
blocked_by:
    - browserid-ng-8fq2
---

DELETE the ITP-dead hidden-iframe/postMessage cert flow: static/provisioning.js, provisioning_api.js, common/js/provisioning.js (clean); communication_iframe.html + communication_iframe/start.js (conditional); rework include.js comm-iframe injection (~1171) + watch() reliance (ties to bean 1sy5). PREREQUISITE: SBO signSboEnvelope relocation must land first (see blocking task). See docs/plans/2026-07-18-model-a-browser-first-agent-migration-plan.md §3-4.

## Reasons for Scrapping
Superseded by the device-cert model migration plan (docs/plans/2026-07-18-device-cert-model-migration-plan.md). Re-scoped into new device-cert phase beans under oup3.
