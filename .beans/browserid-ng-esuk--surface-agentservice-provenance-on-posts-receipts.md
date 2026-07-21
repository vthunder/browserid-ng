---
# browserid-ng-esuk
title: Surface agent/service provenance on posts (receipts + warrant hints)
status: draft
type: feature
created_at: 2026-07-21T22:35:59Z
updated_at: 2026-07-21T22:35:59Z
parent: browserid-ng-oup3
---

Dan (2026-07-22, after the first live poster post): a server-side (poster) post's receipt looks identical to a user posting — no hint it was made via an agent/service, and nothing shows the warrant. Consider how to use hints to show this was done via an agent.

Raw material already on the wire: the presentation in auth_cert carries the HOLDER (opaque), the warrant (scopes, status ref, matcher) and the config cert. But holder namespaces are deliberately private-random, so a third-party viewer cannot classify browsers-vs-services from the holder alone.

Directions to weigh (needs a design ruling):
- Message.creator: the poster could set creator to a service marker while owner stays the user — an honest, public, on-chain signal. Needs daemon/spec rules for creator semantics.
- Attribution surface: sbo DeviceAttribution already returns holder+scopes; the daemon/read API could expose "attributed via warrant w/ scopes [...]" per object, and mingo-web could render a badge + warrant details on the receipt.
- Scope heuristic: service warrants are action:-scoped, browser logins are login-scoped — weak/implicit, probably not enough alone.
- Public holder class: a namespace-class prefix on holders (brw/svc/agt) would make provenance third-party-visible but cuts against the private-namespace design (guess-block). Explicit trade-off to decide.
- Self-view only: mingo tags posts it made server-side in its own store — cheap, but not protocol-level and invisible to other clients.
