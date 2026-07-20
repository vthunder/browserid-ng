---
# browserid-ng-ykjk
title: 'Holder-based authorization model (replace subject + as: with opaque holders)'
status: draft
type: feature
created_at: 2026-07-20T18:12:28Z
updated_at: 2026-07-20T18:12:28Z
parent: browserid-ng-oup3
---

Design settled in discussion 2026-07-20, written up in docs/plans/2026-07-20-holder-authorization-model.md. Replaces subject:user|agent (a self-asserted false hint) and any as:/warrant-delegator notion with an opaque, broker-assigned, IdP-passthrough, mint-copied HOLDER id on device+access certs, organized into user-private randomized namespaces. Warrants bind via a matcher: * (identity-wide, reusable — logins), <ns>.* (category), or <id> (isolated — a specific service). Fixes warrant fungibility, blocks durable brand-gatekeeping (only escapable guess-block remains), keeps owner=you for both browser-signing (A) and service posting (D), and enables the config-cert-withholding less-trusted-device model. D (mingo-poster) is built on this.

Blocks: the device-model D (poster re-enable). A (browser signing) is already live and unaffected.

- [ ] Review + red-pen the design note with Dan
- [ ] browserid-core: holder on DeviceCert/AccessCert; warrant matcher; drop Subject; verify holder-match
- [ ] broker: device_issue/fallback/primary-device-auth accept broker-assigned holder; mint copies it; account holder-registry (namespaces/labels/adopt/re-categorize); login warrants default *
- [ ] registrar/warrant flow: matcher in request+registry
- [ ] sbo: authorize/device_attribution on holders, no subject
- [ ] D: mingo-poster as a warranted holder, owner=you
- [ ] conformance: holder passthrough+copy; monitor over-broad mints
