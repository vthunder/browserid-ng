---
# browserid-ng-0ijs
title: 'Grantee-side scope attenuation: mint reduced-scope sub-grants'
status: draft
type: feature
priority: low
created_at: 2026-08-24T19:32:59Z
updated_at: 2026-08-24T19:32:59Z
---

From the 2026-08-24 authorization-language comparison (Macaroons/Biscuit/UCAN all have offline attenuation): a warrant holder cannot narrow its own grant and hand the slice on. Concrete scenario: an orchestrator agent holding a 10-scope warrant wants to give a subagent a 2-scope slice; today that is a full consent ceremony per slice.

We have half the mechanism: holders are the sub-delegation axis (an agent can mint sub-holder keys within its matcher), but holders narrow WHICH KEYS, not which scopes. Scope-narrowing by the grantee is pure attenuation — passes every invariant, keeps user-rooted attribution — but has no operation.

Design questions: is this a wallet operation (grantee asks its wallet to derive a narrowed record), what signs the derived record, and how does the registry/ledger show parent↔child. See docs/warrant-use-cases.md (Known limits).
