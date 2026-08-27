---
# browserid-ng-hd63
title: Signature-algorithm agility / post-quantum review (registry proofs + protocol-wide)
status: todo
type: task
priority: deferred
created_at: 2026-08-27T14:14:54Z
updated_at: 2026-08-27T14:14:54Z
---

registry-api-v1 §3.2 pins the request-proof alg to EdDSA (Ed25519), matching device keys — deliberate for v1. Revisit for algorithm agility and post-quantum migration: the proof typ is versioned (browserid-registry-proof-v2 can switch algs), but the protocol's whole signature suite (device certs, warrants, assertions, DNSSEC root) needs a coordinated PQ story. Separate, later effort per Dan (2026-08-28); this bean is the scheduled reminder.
