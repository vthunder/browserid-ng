---
# browserid-ng-wwec
title: Approval UI can't express grantor != grantee (the delegation axis is invisible)
status: todo
type: feature
priority: high
created_at: 2026-07-24T22:02:14Z
updated_at: 2026-07-24T22:48:11Z
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

## CORRECTION 2026-07-25 — the UI does expose the axis; my request was wrong

Dan: the approval page offers "as me" vs "with its own handle". That IS the
grantor/grantee axis, so the original framing ("the UI cannot express it") is
wrong and this bean is NOT a blocker on its own.

What actually happened: the provisioning request left `grantor` OPEN (absent →
`*`). Omitting `grantee` pins grantee ≡ grantor but says nothing about WHICH
identity fills both slots, so "with its own handle" legitimately minted
danmills+bluesky2@ and used it for both. No silent collapse of a pin — there
was no pin to collapse. The requester's bug, not the page's.

What remains genuinely worth doing, downgraded from "missing feature":
- When a request PINS `grantor`, the page should say so and constrain the
  choice, rather than letting the human pick an identity that will fail
  check_grantor_pin() at complete-time.
- "as me" / "with its own handle" is good phrasing for the axis, but it does
  not say what it MEANS for attribution — a reader of the resulting post sees
  either "Dan said this" or "this agent said this". Worth surfacing.
- Still worth refusing rather than proceeding when a pin cannot be honored.

The hard blocker is browserid-ng-y9xm alone (cannot approve AS a sub-identity,
so an account owned by one can never delegate).

## Superseded for the design question 2026-07-25

The full delegation-shape design now lives in browserid-ng-8v6c (four shapes,
intent-first UI, the server changes each needs). Keep THIS bean for the
narrower rule it states: a request's grantor/grantee pins must be honoured or
REFUSED, never silently substituted, and the refusal reason must reach the
requester (today a policy failure reaches the client as "expired", which is
how we lost 15 minutes and a real diagnosis).

New evidence for that: pinning grantee=danmills+bsky@sandmill.org routed into
the FOREIGN path (agent_name_allowed() makes "owned" narrower than "+tag of a
verified email") and failed at complete-time with "a foreign grantee must
supply its holder" — after the human had already approved.
