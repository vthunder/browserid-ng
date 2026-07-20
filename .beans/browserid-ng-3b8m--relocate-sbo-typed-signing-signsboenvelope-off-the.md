---
# browserid-ng-3b8m
title: Relocate SBO typed-signing (signSboEnvelope) off the hidden iframe
status: todo
type: task
priority: normal
created_at: 2026-07-17T22:29:06Z
updated_at: 2026-07-20T11:12:41Z
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
