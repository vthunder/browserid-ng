---
# browserid-ng-9wiq
title: 'Landing page: visceral consent hero + nuts-and-bolts Why section'
status: completed
type: task
priority: high
created_at: 2026-07-11T23:39:56Z
updated_at: 2026-07-11T23:44:28Z
---

User feedback on browserid.me landing (index.html):
1) Hero card currently shows an abstract verification cascade (domain->email->agent). Replace with something visceral: the CONSENT moment, e.g. 'agent researcher@identity.com wants to act for you at https://api.example.com — Approve / Deny'. Show the experience, not the data structure.
2) The 'Why' section leads with lofty ideas (universality, open spec, cryptographically provable). Reframe nuts-and-bolts / dev-centric: 'as a dev I do X,Y,Z and then users AND agents use my app/APIs with cryptographic proof of identity'. Keep lofty ideas (no lock-in) but ground them; they're weaker standalone.

- [x] Replace hero card with a consent-screen visual
- [x] Rewrite Why section dev-centric (do X -> get Y), ground the lofty claims
- [x] Deploy + eyeball light/dark

## Summary of Changes

index.html hero: swapped the abstract verification-cascade credential card for an interactive agent-consent screen (researcher@browserid.me wants to act for you at https://api.example.com, post/read scopes, Approve/Deny). Approve signs the warrant and reveals the attribution/revocable payoff; Deny stops it. Why section recast as In practice: three concrete dev-centric pillars (you add one /verify call; you skip registration/secrets/lock-in; you can trust offline cryptographic proof), grounding the former lofty claims. Screenshotted light+dark, deployed to browserid.me, verified live.
