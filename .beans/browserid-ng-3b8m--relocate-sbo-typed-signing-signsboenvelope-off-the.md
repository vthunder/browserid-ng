---
# browserid-ng-3b8m
title: Relocate SBO typed-signing (signSboEnvelope) off the hidden iframe
status: in-progress
type: task
priority: normal
created_at: 2026-07-17T22:29:06Z
updated_at: 2026-07-21T21:52:53Z
parent: browserid-ng-oup3
blocking:
    - browserid-ng-oup3
    - browserid-ng-6gs4
    - browserid-ng-4qmg
---

Hard PREREQUISITE for Model A Phase 4 (iframe retirement). browserid-broker/static/communication_iframe/start.js:156-241 hosts the live SBO envelope-signing capability (signSboEnvelope + loadSboWasm) layered on the SAME hidden iframe as the ITP-dead silent-refresh path. Deleting the iframe (Model A) silently breaks SBO signing unless this is relocated first.

## Task
- Move signSboEnvelope / loadSboWasm to the same-tab/popup typed-signing surface (coordinate with docs/plans/2026-06-24-typed-signing-extension-design.md).
- Verify SBO envelope signing still works end-to-end after the move (mingo/sbo consumers).
- Only then can Model A Phase 4 delete communication_iframe.html + communication_iframe/start.js.

## Context
Surfaced by the Model A migration audit (see docs/plans/2026-07-18-model-a-browser-first-agent-migration-plan.md §4 + risk register). Blocks epic browserid-ng-oup3 Phase 4.

## Scoped (session 4): A == this bean on the device model
Design decision: A (per-action broker typed-signing) is the wallet pattern; D/E (server-side/agent) for delegated posting. Relocating signSboEnvelope onto the device model IS 3b8m. Existing partial relocation surface: static/sign.html + common/js/sbo-signer.js + sbo-sign.js (classic — signs with identity Certificate). Device-model port: mint access cert over a fresh signing key, sign the envelope with it, assemble access_cert~assertion~warrant(typed scopes)~config_cert — exactly what sbo verify_device_attribution now accepts. Steps: (1) port sbo-signer/sbo-sign to device model (reuse dialog buildPresentation), (2) per-action approve+render mode (wallet security surface), (3) redirect-fallback the signer surface, (4) delete communication_iframe + classic common/js stack. Open decisions with Dan: per-action-mint TTL, typed-render ownership (broker-generic vs RP-template), whether a wallet demo is in scope now. Gated on the sbo verifier (now landed).

## Iframe deleted (session 4) — d9a6baf, deploying
Removed communication_iframe.html + start.js + the entire classic common/js Persona stack (browserid/class/crypto-loader/helpers/mediator/network/provisioning/user/xhr_transport/storage + lib/models/modules); include.js stripped of the jschannel Channel + _open_hidden_iframe + commChan (WinChan/FedCM/redirect-delivery intact); routes + CSP tier cleaned. Login e2e (popup+redirect) + 29 broker suites green. UNBLOCKS 6gs4, 4qmg. Remaining for full A: port the /sign signer surface (sbo-signer.js/sbo-sign.js) from classic-cert to the device model (mint access cert -> presentation, matching sbo verify_device_attribution), + redirect-fallback it. No live browser-signing consumer today (mingo posting = D, stubbed).

## A (browser signing) built + deploying (session 4)
- Signer ported to device model (browserid.me d7f0717, deployed): sbo-signer.js mints an access cert + builds the presentation, signs the envelope with the access key, returns the 4-object presentation as Auth-Cert. sbo-sign.js unchanged (generic). /sign joined the Dialog CSP tier. e2e green (presentation verifies via /verify-access, envelope-key binding intact).
- mingo app.js rewired (3277ba9): signEnvelope carries the SBO db audience (sbo+raw://avail:turing:506/); certIssuer parses the presentation. Deploy pending the daemon.
- sbo-daemon: SBO_REV bumped to ac48868 (device verifier), CI deploy in flight (run 29739911561).
REMAINING for A end-to-end: daemon deploy lands -> deploy mingo-idp -> human test browser posting on mingo.

## A LIVE end-to-end (session 4)
Deployed + version-verified across the chain: broker signer (device-model sbo-signer.js, /sign connect-src open) on browserid.me d7f0717; sbo-daemon on the device verifier (ac48868, CI success, /health 200); mingo-idp+web a9a4a3e (dbAudience wired). Browser SBO posting on mingo.place is ready for a human test (sign in → post; signs via /sign popup on the device model). The iframe is gone and A is its device-model replacement — 3b8m's relocation goal is met. D (poster) is the remaining posting path, blocked on a design decision: the device warrant dropped the classic delegator/acting-for field, so restoring classic D (fixed mingo-poster service, user-authorized on-chain, owner=user) needs that delegation re-added to browserid-core Warrant + the verifier + sbo authorize. Awaiting Dan's go.

## D blocked on the holder model (2026-07-20)
D (mingo-poster / service posting) is blocked on the holder-based authorization redesign (browserid-ng-ykjk, docs/plans/2026-07-20-holder-authorization-model.md): the device warrant dropped the delegator/as: field, and the settled fix is opaque broker-assigned holders + warrant matchers (*/ns.*/id) rather than re-adding as:. D builds on that. A (browser signing) is live and independent.

## Agent/D phase handoff (2026-07-21)
Holder migration fully deployed+verified; D unblocked. Start here: docs/plans/2026-07-21-HANDOFF-agent-d.md (merged one-approval provisioning -> mingo-poster as warranted <id> service holder -> handle bootstrap; mingo sbo dep bump a92886c->55314e9 first).

## D rebuilt (session 5, 2026-07-21) — poster on the holder model, ready to deploy
Design correction settled from the holder-model doc: the poster is an AS-YOU SERVICE — warrant identifier IS the user (owner == attributed identity, no as: scope, no mingo-poster@ identity); isolation comes from the broker-assigned services holder. sbo authorize is strict-equality on attributed email, which forced this reading (and is what the doc specified all along).

Built:
- browserid-ng (branch holder-authorization-model, pushed): merged one-approval provisioning (browserid-ng-dzq8) incl. as-you requests, primary-signed cert acceptance in complete (issuer-consistency: config_cert.iss == access_cert.iss makes broker-signed certs unverifiable for primary-domain identities), account.html approval hop to the primary's device-authorize (agent mode), SDK request_provision/wait/into_agent + assertion_with_access_seed.
- mingo 58ed2ea: poster.rs rebuilt (enable -> merged request; poll -> stores device_seed/cert/holder/idp + warrant tail; submit -> DeviceAgent access mint + envelope-key-bound SBO wire + fail-closed dnssec refresh); /agent_device_cert + device-authorize agent mode; store migrated; mingo-idp pinned browserid-ng 645d7c9 + sbo 55314e9 (crate-local).
All tests green both repos (broker merged_provision_test 4, agent SDK roundtrip, mingo-idp 21).

- [ ] deploy browserid.me (dokku push branch)
- [ ] deploy mingo-idp
- [ ] human test: enable poster on mingo.place -> approve once at browserid.me -> server-side post lands on-chain owned by dan@mingo.place
- [ ] follow-up: mingo-app CLI still classic (pins 3b6189e + workspace sbo a92886c) — needs its own device-model migration (request_provision SDK path)
