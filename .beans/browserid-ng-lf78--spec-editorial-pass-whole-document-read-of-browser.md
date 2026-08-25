---
# browserid-ng-lf78
title: 'Spec editorial pass: whole-document read of browserid-ng-protocol.md'
status: todo
type: task
priority: normal
created_at: 2026-08-25T19:16:31Z
updated_at: 2026-08-25T19:16:41Z
---

A full editorial pass over docs/specs/browserid-ng-protocol.md — the spec has grown by accretion (v1 → warrant v2 → admission/composition → signing grants) and deserves one holistic read for voice, length, and placement, rather than section-local patches.

Carried in from the ttn3 review (Dan, 2026-08-25):
- [ ] Verbosity: several signing-grants additions (§5 requester prose, honesty tier, labeled doors, scope parameters) may belong partly in design notes rather than normative text — decide what is spec vs rationale
- [ ] Placement: consider splitting §5's warrant section (it now covers format, bindings, matchers, scopes, signing grants, status, v1 compat)
- [ ] DECISION: break the wire format vs keep the singular-binding shorthand — single-user pre-launch, could wipe and re-consent; deleting the shorthand is ~20min of code (BindingSet::One + tests) plus one re-consent of deployed records
- [ ] Editorial: define login as the degenerate signing grant rather than a parallel form (docs/warrant-use-cases.md 'Known limits' records the observation)
- [ ] General: terminology consistency (wallet / custodian / holder / broker), cross-reference hygiene, whether §6.6's 14 invariants should be grouped by concern
