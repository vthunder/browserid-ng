---
# browserid-ng-dj9p
title: Escrow / trust-by-bond model for agent identities
status: draft
type: feature
priority: deferred
created_at: 2026-07-08T21:47:34Z
updated_at: 2026-07-08T21:47:34Z
---

Deliberately deferred from browserid-ng-l8lw (agent-native browserid), which shipped attribution-first trust. Escrow/stake — trust-by-bond — is a separate future product: an agent (or its operator) posts a bond that an RP can claim on misbehavior, giving RPs a trust signal beyond attribution. Needs its own design work: custody of the bond, adjudication, integration with the l8lw provisioning API. See docs/plans/2026-07-08-agent-native-browserid-design.md.
