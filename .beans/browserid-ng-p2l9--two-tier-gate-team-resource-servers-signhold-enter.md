---
# browserid-ng-p2l9
title: 'Two-tier gate: team resource servers sign+hold, enterprise gateway enforces at ingress'
status: draft
type: feature
created_at: 2026-08-15T07:22:09Z
updated_at: 2026-08-15T07:22:09Z
---

Direction Dan liked (2026-08-15, from the signed-grants trust discussion): split gate into (a) an enterprise gateway a company runs once — the tool-ingress enforcement point — and (b) per-team resource servers that own policy: users sign records at the team level, and the SAME records are enforced at the enterprise gateway, because §6.5/§6.4 records are protocol artifacts any party can validate (/validate-record needs no relationship with the signer's box). This is the concrete form of 'verification travels down the stack' and the reason signed grants stay in gate as the --signed-grants mode even though self-hosted defaults to local roles. Design questions: record distribution between tiers (registry pull vs push), audience semantics when ingress origin != team origin, and whether ingress enforces conjunction itself or delegates to team servers per call.
