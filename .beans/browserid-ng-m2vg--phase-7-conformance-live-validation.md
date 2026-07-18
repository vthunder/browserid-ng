---
# browserid-ng-m2vg
title: Phase 7 — Conformance & live validation
status: scrapped
type: task
priority: normal
created_at: 2026-07-17T23:05:30Z
updated_at: 2026-07-18T19:40:38Z
parent: browserid-ng-oup3
---

Guardrail tests: cant-mint-self-without-capability; revoked-P_cert-cant-mint (logout-everywhere); RP-verification-unchanged; fail-closed-on-unknown-constraint-axis. Live test on sandmill.org + mingo. Conformance: browserid without the mint verb is non-conformant; conformant login is cookie-free + iframe-free. See docs/plans/2026-07-18-model-a-browser-first-agent-migration-plan.md §7.

## Reasons for Scrapping
Superseded by the device-cert model migration plan (docs/plans/2026-07-18-device-cert-model-migration-plan.md). Re-scoped into new device-cert phase beans under oup3.
