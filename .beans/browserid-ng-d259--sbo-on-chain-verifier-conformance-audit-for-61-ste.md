---
# browserid-ng-d259
title: 'SBO on-chain verifier: conformance audit for §6.1 step 7 (constraints)'
status: todo
type: task
priority: low
created_at: 2026-08-11T14:15:09Z
updated_at: 2026-08-11T14:15:09Z
---

The sbo repo's on-chain/detached-proof verifier must enforce cert constraints (spec §4.7 / §6.1 step 7: salted-hash aud allowlist, warrant scopes/max-ttl, MUST-reject unknown constraint keys) or a constrained presentation verifies on-chain that a conforming verifier would refuse. Managed tenants are opt-in and none exist yet, so not urgent — but land before promoting managed identities. Context: epic browserid-ng-4vu7 (all four phases deployed at a04ddf7).
