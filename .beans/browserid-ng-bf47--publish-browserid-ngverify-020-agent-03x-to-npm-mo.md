---
# browserid-ng-bf47
title: 'Publish @browserid-ng/verify 0.2.0 + agent 0.3.x to npm; move wallet-service off file: deps'
status: todo
type: task
priority: normal
created_at: 2026-07-29T09:17:46Z
updated_at: 2026-08-26T23:07:16Z
---

wallet-service uses file:../sdk/agent and file:../sdk/js because @browserid-ng/verify 0.2.0 (device-model verify-access API) is unpublished (npm has only 0.1.0). Publish both SDKs, then switch wallet-service/package.json to registry versions — which also lets the Dockerfile build from wallet-service/ context alone.

**Audit note 2026-08-27:** publishing half done and exceeded — npm has @browserid-ng/verify 0.3.1 and @browserid-ng/agent 0.5.1, with CI auto-publish via OIDC (a758b66, 7127ee5). Remaining scope is only the migration half: wallet-service/package.json still uses file:../sdk/* deps and the Dockerfile still COPYs sdk/agent + sdk/js.
