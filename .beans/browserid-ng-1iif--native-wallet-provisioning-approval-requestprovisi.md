---
# browserid-ng-1iif
title: 'Native wallet: provisioning approval (request("provision") answered natively)'
status: todo
type: feature
created_at: 2026-09-11T14:12:22Z
updated_at: 2026-09-11T14:12:22Z
---

Today the native wallet answers unsupported_kind for provision and the page falls back to the approval link. Needed: agent-provision prepare/complete on the registry token lane (/api/v1, ApiUser) so a wallet without the broker cookie session can approve; then either host authorize.html bridge-aware (like consent.html under jo0m) or a native card. Related epic g69e.
