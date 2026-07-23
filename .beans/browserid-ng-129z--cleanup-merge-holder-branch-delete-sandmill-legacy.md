---
# browserid-ng-129z
title: 'Cleanup: merge holder branch; delete sandmill legacy auth views'
status: in-progress
type: task
priority: normal
created_at: 2026-07-21T21:02:32Z
updated_at: 2026-07-23T10:59:37Z
parent: browserid-ng-oup3
---

1) Merge browserid-ng holder-authorization-model -> main (prod deploys from the branch today). 2) sandmill: delete the dead classic /browserid/auth + auth-complete blade views (auth-complete loads the deleted authentication_api.js; nothing routes there since /account primary sign-in went through the dialog).
