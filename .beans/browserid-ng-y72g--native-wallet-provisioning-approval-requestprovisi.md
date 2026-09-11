---
# browserid-ng-y72g
title: 'Native wallet: provisioning approval (request("provision") answered natively)'
status: todo
type: feature
created_at: 2026-09-11T14:11:48Z
updated_at: 2026-09-11T14:11:48Z
---

Today the native wallet answers unsupported_kind for provision and the page falls back to the approval link. Needed: agent-provision prepare/complete on the registry token lane (/api/v1, ApiUser) so a wallet without the broker cookie session can approve; then either host authorize.html bridge-aware (like consent.html under jo0m) or a native card. Parent epic g69e.
