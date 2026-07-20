---
# browserid-ng-ykjk
title: 'Holder-based authorization model (replace subject + as: with opaque holders)'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-20T18:12:28Z
updated_at: 2026-07-20T22:41:54Z
parent: browserid-ng-oup3
---

Design settled in discussion 2026-07-20, written up in docs/plans/2026-07-20-holder-authorization-model.md. Replaces subject:user|agent (a self-asserted false hint) and any as:/warrant-delegator notion with an opaque, broker-assigned, IdP-passthrough, mint-copied HOLDER id on device+access certs, organized into user-private randomized namespaces. Warrants bind via a matcher: * (identity-wide, reusable — logins), <ns>.* (category), or <id> (isolated — a specific service). Fixes warrant fungibility, blocks durable brand-gatekeeping (only escapable guess-block remains), keeps owner=you for both browser-signing (A) and service posting (D), and enables the config-cert-withholding less-trusted-device model. D (mingo-poster) is built on this.

Blocks: the device-model D (poster re-enable). A (browser signing) is already live and unaffected.

- [x] Review + red-pen the design note with Dan (2026-07-20 session: rulings folded in)
- [x] browserid-core: holder on DeviceCert/AccessCert + AccessRequest; warrant HolderMatcher (*/ns.*/id); renamed Subject→Holder; verify holder-match; conformance tests (matcher semantics, passthrough+copy, fail-closed); golden vectors regenerated
- [~] broker 2a DONE: device_issue/fallback/fedcm assign broker holder; mint copies verbatim; namespaces table (prefix storage); login warrants <prefix>.*; gates dropped. 2b TODO: account holder-registry UI (list/labels/adopt/re-categorize)
- [x] registrar/warrant flow (stage 3): namespace holder assignment via broker registry + hint; warrant_request persists agent holder; respond validates matcher covers holder + rejects bare *; consent.html signs <id> matcher (widenable <ns>.*); consent.html subject:'agent' fixed
- [x] sbo (stage 4): device_attribution DeviceAttribution.subject->holder (from access_cert.holder); authorize unchanged (keys off email/owner); core rev bumped b2e4f82->b8526f6; sbo-core+daemon green. Committed sbo main 55314e9. Deploy (SBO_REV bump) pairs with stage 5 D.
- [ ] D: mingo-poster as a warranted holder, owner=you
- [ ] conformance: holder passthrough+copy; monitor over-broad mints

## Stage 3 known-broken (pending): consent.html signWarrant still emits subject:'agent' (no holder matcher) — the agent-authorization consent flow is malformed against new core. Fix as part of stage 3 (registrar warrant matcher + D). agent_provision.rs also mints an inline agents.<rand> placeholder holder. Both to be rerouted through the broker namespace registry with <id> matchers when D is built.
