---
# browserid-ng-3b8m
title: Relocate SBO typed-signing (signSboEnvelope) off the hidden iframe
status: todo
type: task
priority: normal
created_at: 2026-07-17T22:29:06Z
updated_at: 2026-07-18T19:41:27Z
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
