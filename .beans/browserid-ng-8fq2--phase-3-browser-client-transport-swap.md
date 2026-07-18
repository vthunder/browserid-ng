---
# browserid-ng-8fq2
title: Phase 3 — Browser client (transport swap)
status: completed
type: task
priority: normal
created_at: 2026-07-17T23:05:30Z
updated_at: 2026-07-18T19:40:37Z
parent: browserid-ng-oup3
blocked_by:
    - browserid-ng-wid3
---

Change consent.html same-tab return leg to deposit a reusable provisioning credential (delegation) instead of a one-shot cert; add browser mint client (self-mode). EXTRACT existing client-side P_cert signing (account.html:706-712) + mint driver (account.html:670-719) to a shared module -- NOT new crypto. Assemble /bootstrap from existing consent.html+account.html pieces. Replace dialog.js generateCertificate + handlePrimaryIdP. Explicit self-consent UI. CSP INLINE_SCRIPT_HASHES recompute (guard test mod.rs:497-521; run broker tests before dokku push). See docs/plans/2026-07-18-model-a-browser-first-agent-migration-plan.md §3.

## Progress (2026-07-18 overnight)
Built + committed the hosted demo (/demo-self-login + external JS, Strict CSP). Server-side loop proven by self_mode_mint_issues_plain_login_cert + agent_only_credential_cannot_self_mint (17/17 broker agent tests). Full workspace regression clean except pre-existing flake 7v1h (consent_flow csrf race — unrelated). Deploy pushed to dokku (sha 29bbd9c); Rust host build in progress (slow). Prod has AGENT_PROVISIONING=1. Prod end-to-end smoke test (scratchpad/smoke.mjs) ready to run once the build swaps in. Guaranteed deliverable (server-side self-mint) done + tested; hosted demo pending deploy completion.

## Summary — LIVE + PROVEN IN PROD (2026-07-18)
Deployed to browserid.me (sha 29bbd9c). /demo-self-login + /demo-self-login.js serve 200. End-to-end prod smoke test (scratchpad/smoke.mjs, driving the exact demo HTTP sequence) PASSED:
cert_key -> register(self-only) -> endorse -> mint(subject:self) => PLAIN login cert (principal=email, typ=none, agent=no) -> /verify status:okay. The browser mints its own login cert via the agent endpoint; result verifies as an ordinary login. Left a sanctioned @example.com test account (modela-smoke@example.com) on prod.

## SUPERSEDED (2026-07-18)
Model pivoted to the device-cert design (docs/plans/2026-07-18-device-cert-model-migration-plan.md). This work targeted the earlier user-signed-provisioning-cert model; kept as historical record, replaced by the new device-cert phases. Not reverted (additive, harmless).
