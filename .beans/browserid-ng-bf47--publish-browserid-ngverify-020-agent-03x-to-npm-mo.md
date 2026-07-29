---
# browserid-ng-bf47
title: 'Publish @browserid-ng/verify 0.2.0 + agent 0.3.x to npm; move wallet-service off file: deps'
status: todo
type: task
created_at: 2026-07-29T09:17:46Z
updated_at: 2026-07-29T09:17:46Z
---

wallet-service uses file:../sdk/agent and file:../sdk/js because @browserid-ng/verify 0.2.0 (device-model verify-access API) is unpublished (npm has only 0.1.0). Publish both SDKs, then switch wallet-service/package.json to registry versions — which also lets the Dockerfile build from wallet-service/ context alone.
