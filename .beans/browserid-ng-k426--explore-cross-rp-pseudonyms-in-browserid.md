---
# browserid-ng-k426
title: Explore cross-RP pseudonyms in browserid
status: draft
type: feature
priority: deferred
created_at: 2026-07-14T16:51:11Z
updated_at: 2026-07-14T16:51:11Z
---

Idea surfaced while redesigning mingo's mobile signing. mingo handles
(handle@mingo.place) exist to give users pseudonyms within mingo. That's a
per-RP solution to a general problem: users often want a stable pseudonymous
identity that isn't their real email.

Explore making pseudonyms a first-class browserid feature so they work
cross-RP (one pseudonym usable at many sites), instead of every RP reinventing
handles. This would let RPs like mingo drop bespoke handle systems.

Deferred: not needed for the immediate mingo mobile-signing work (which keeps
mingo handles as-is and adds a delegated poster agent). Revisit later.

## Open questions
- [ ] What issues a cross-RP pseudonym cert? (browserid itself? a pseudonym IdP?)
- [ ] How is unlinkability preserved (pseudonym must not leak the real email)?
- [ ] Relationship to the agent/warrant model and to per-RP scoping.
- [ ] Migration path for existing mingo handles.
