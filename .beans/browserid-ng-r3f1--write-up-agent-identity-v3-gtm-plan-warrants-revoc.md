---
# browserid-ng-r3f1
title: Write up agent-identity v3 + GTM plan (warrants, revocation, registrar, positioning)
status: completed
type: task
priority: normal
created_at: 2026-07-10T15:21:43Z
updated_at: 2026-07-10T15:25:06Z
---

Capture the 2026-07-10 strategy/design discussion as a plan doc in docs/plans/ and restructure beans accordingly (rewrite 5zdh/egr7, new beans for registrar unbundling, JIT consent flow, landing repositioning, verifier SDKs).

## Summary of Changes

- Wrote the canonical plan: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` — positioning decision (agents-first), 7 ratified design decisions, warrant model, fail-closed cert typ + warrant-in-chain, JIT consent flow, layered revocation stack, registrar unbundling, GTM track, sequencing, remaining open questions.
- Beans restructured: epic gsnm created; 5zdh and egr7 rewritten with converged designs and moved draft→todo under the epic; new beans 1pnf (registrar unbundling), pz0f (JIT consent, blocked by 5zdh), w7xu (landing repositioning), exj6 (verifier SDKs).
