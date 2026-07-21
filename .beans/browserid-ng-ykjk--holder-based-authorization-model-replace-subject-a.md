---
# browserid-ng-ykjk
title: 'Holder-based authorization model (replace subject + as: with opaque holders)'
status: in-progress
type: feature
priority: normal
created_at: 2026-07-20T18:12:28Z
updated_at: 2026-07-21T00:38:10Z
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

## Migration deployed (2026-07-20/21)
Holder model built + deployed across all services:
- browserid-ng: core/broker/registrar/rp/agent + client JS (dialog.js, sbo-signer.js, account.html, consent.html) all holder; workspace clean of Subject. Deployed browserid.me. Branch holder-authorization-model (b8c35b4), pushed origin.
- sandmill (PHP primary IdP): holder-bearing device/access certs. Deployed.
- sbo: device_attribution holder. Pushed origin main 55314e9.
- mingo-idp: holder port. Deployed mingo.place.
- sbo-daemon: SBO_REV bumped to 55314e9, CI deploy.
VERIFIED: prod holder chain smoke green (device_issue->mint copy->login <ns>.* warrant->verify okay, holder 5c3idfa4.7yaiasyth7).

## Remaining
- [ ] D: mingo-poster live posting (re-enable stubbed poster as warranted <id> service; unify mingo sbo dep to holder rev). Feature, not migration.
- [ ] sandmill primary-login redirect bug (danmills stuck): PRE-EXISTING, static paths correct, needs browser repro (redirect-mode/session). Independent of holders.
- [ ] adopt-after-wipe + re-categorize UI (deferred client-provisioning work).
- [ ] cleanup: stale pre-migration holder='user' rows show as Uncategorized.

## Session 2 (2026-07-21) — deployed + hardened
- FIXED sandmill mis-deploy (was pushed to master; dokku deploys from main) — was running old subject code -> 'subject mismatch'. Redeployed to main.
- FIXED client-JS warrant builders (dialog.js, sbo-signer.js) still emitting subject -> holder.
- FIXED /account primary sign-in: was location.href=info.auth (dead classic /browserid/auth); now routes through the dialog redirect-mode (cross-origin mint needs the open-connect tier). No dialog/CSP changes.
- §3 + cleanup: auth_with_presentation records primary-IdP config-cert holders on join (best-effort); migrate_v17 purges stale holder IN('user','agent') rows.
- VERIFIED live: danmills@sandmill.org dialog login (mingo.place) works; browser SBO signing (dan@mingo.place) posts ON-CHAIN via holder model (full chain incl sbo-daemon holder verify).
- Deployed: browserid.me (multiple), sandmill (main), mingo-idp, sbo-daemon (CI).

## Still open
- [ ] group primary holders by issuer namespace (they land in Uncategorized now)
- [ ] delete sandmill dead legacy /browserid/auth + auth-complete views (unreachable now)
- [ ] prefill email in /account->dialog handoff (minor UX)
- [ ] D: mingo-poster server-side posting (browser signing works; server-side stubbed)
