---
# browserid-ng-ykjk
title: 'Holder-based authorization model (replace subject + as: with opaque holders)'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-20T18:12:28Z
updated_at: 2026-07-20T21:46:18Z
parent: browserid-ng-oup3
---

Design settled in discussion 2026-07-20, written up in docs/plans/2026-07-20-holder-authorization-model.md. Replaces subject:user|agent (a self-asserted false hint) and any as:/warrant-delegator notion with an opaque, broker-assigned, IdP-passthrough, mint-copied HOLDER id on device+access certs, organized into user-private randomized namespaces. Warrants bind via a matcher: * (identity-wide, reusable — logins), <ns>.* (category), or <id> (isolated — a specific service). Fixes warrant fungibility, blocks durable brand-gatekeeping (only escapable guess-block remains), keeps owner=you for both browser-signing (A) and service posting (D), and enables the config-cert-withholding less-trusted-device model. D (mingo-poster) is built on this.

Blocks: the device-model D (poster re-enable). A (browser signing) is already live and unaffected.

- [x] Review + red-pen the design note with Dan (2026-07-20 session: rulings folded in)
- [x] browserid-core: holder on DeviceCert/AccessCert + AccessRequest; warrant HolderMatcher (*/ns.*/id); renamed Subject→Holder; verify holder-match; conformance tests (matcher semantics, passthrough+copy, fail-closed); golden vectors regenerated
- [~] broker 2a DONE: device_issue/fallback/fedcm assign broker holder; mint copies verbatim; namespaces table (prefix storage); login warrants <prefix>.*; gates dropped. 2b TODO: account holder-registry UI (list/labels/adopt/re-categorize)
- [ ] registrar/warrant flow: matcher in request+registry
- [ ] sbo: authorize/device_attribution on holders, no subject
- [ ] D: mingo-poster as a warranted holder, owner=you
- [ ] conformance: holder passthrough+copy; monitor over-broad mints
