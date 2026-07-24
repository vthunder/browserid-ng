---
# browserid-ng-wwec
title: Approval UI can't express grantor != grantee (the delegation axis is invisible)
status: todo
type: feature
priority: high
created_at: 2026-07-24T22:02:14Z
updated_at: 2026-07-24T22:02:14Z
---

Raised by Dan 2026-07-25, testing the bsky on-behalf flow.

The plumbing supports the full grantor/grantee matrix (RequestBody.grantor /
.grantee pins in browserid-registrar/src/agent_provision.rs; warrants carry
both). The UI does not let a human express or even SEE the distinction between
two materially different approvals:

  A) grantor = danmills@sandmill.org, grantee = danmills+foo@sandmill.org
     "my root identity delegates to this actor; posts are attributed to ME,
      written by foo" -> ON-BEHALF-OF

  B) grantor = grantee = danmills+foo@sandmill.org, signed by
     danmills@sandmill.org (which owns danmills+*@ and may therefore sign)
     "foo acts as itself; attribution is foo" -> AS-ITSELF

Both are legitimate and they mean different things to a reader of the
resulting post — A says Dan said it, B says foo said it.

Observed failure: with `grantee: "*"` and grantor left open, the page used the
ONE identity the human picked for BOTH sides, silently producing B when A was
requested. The requester got an as-itself warrant with no indication that its
grantee pin had been collapsed. An agent then discovers this two steps later
as an unrelated-looking 403 from the RP.

Dan's read, which I share: this is a genuinely hard UI question, not a missing
checkbox. The concepts (who is responsible vs who typed it) are unfamiliar,
and getting it wrong silently is worse than refusing.

Sketches worth weighing:
- State it as a sentence the human completes: "Posts will be attributed to
  [picker] and written by [picker]", so the two roles are visibly separate and
  a same-value choice is a deliberate act.
- When a request pins `grantee: "*"`, ask outright: "Should this act AS you,
  or as a separate actor you own?" — the distinction, in the requester's terms.
- Never silently collapse a pin: if the page cannot honor grantor/grantee as
  asked, it should REFUSE and say why, so the requester learns at approval
  time instead of at the RP.

Blocks the on-behalf half of browserid-bsky-nr8p. Related: browserid-ng-y9xm
(the picker only lists root identities, so A is unapprovable whenever the
grantor is a sub-identity).
