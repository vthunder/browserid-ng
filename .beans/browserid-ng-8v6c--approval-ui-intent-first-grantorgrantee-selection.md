---
# browserid-ng-8v6c
title: 'Approval UI: intent-first grantor/grantee selection (4 delegation shapes)'
status: completed
type: feature
priority: high
created_at: 2026-07-24T22:48:01Z
updated_at: 2026-07-25T22:17:56Z
---

Design with Dan 2026-07-25, after the bsky on-behalf test hit a wall. Parent
problem: the approval page has ONE identity picker and a single boolean
(account.html: `asMe ? 'self' : 'handle'`), so of the delegation shapes the
protocol supports, only two are reachable.

## The three axes (naming these makes case 2 tractable)

- ATTRIBUTION = the warrant's `grantor`. Who is answerable for the action.
- ACTOR = the warrant's `grantee`. Who performed it.
- RESOURCE = whose stuff is touched. NOT in the warrant — each RP derives it.
  The bsky bridge derives it from the grantor (account bound to grantor email),
  which is why attribution and resource are welded together there.

## The shapes (Dan's list, refined)

1. "An agent acts on my behalf / uses my stuff" — grantor = an identity I
   choose, grantee = an agent identity (chosen or created), DISTINCT.
   Expressible in the protocol today; NOT reachable in the UI. This is the
   important one and the flagship bsky demo needs it.

2. "The agent acts as itself, but attributed to me" — Dan: the protocol
   doesn't neatly allow this. Agreed, and the axes say why. It splits in two:
   2a. Reader sees the agent as executor, action lands in MY account,
       attribution mine -> that IS shape 1. What people usually mean.
   2b. Action lands in the AGENT's OWN account while claiming my
       authorization -> needs the RP to decouple RESOURCE from ATTRIBUTION.
       Not a warrant shape and not a UI gap; the bridge deliberately binds the
       account to the grantor. Out of scope for the UI.
   So the UI should NOT offer 2 as a mode. It should make shape 1's DISPLAY
   explicit ("written by X, attributed to you"), which is what 2 is reaching
   for.

3. "The agent acts as itself, no attribution to me" — grantor == grantee == an
   agent sub-identity. Legitimate; the blast-radius argument is real. Honest
   caveat worth showing: a `+tag` of the user's address is PSEUDONYMOUS, not
   anonymous — anyone who knows the convention reads the base identity off it.
   This is what the current "with its own handle" produces.

4. "The agent impersonates me" — grantor == grantee == a root / non-agent
   identity. Today's "as me". Must warn, and the warning should say what is
   actually lost: nothing can distinguish the agent's actions from the human's
   afterwards, and revoking the agent means revoking themselves.

Plus the EXTERNAL variant of 1: grantee is an identity the approver does NOT
own (a service holding its own cert from its own issuer). Same shape as 1,
but the page must collect/resolve `grantee_holder`, and no cert is minted.

## Why this bit us

Also note "owned" is NARROWER than "a +tag of my verified email":
approver_owns_identity() additionally requires agent_name_allowed(tag), so
`danmills+bsky@sandmill.org` was FOREIGN, and the approval failed at
complete-time with "a foreign grantee must supply its holder". The page should
tell the user that up front ("that's an external service, not you") instead of
failing after they approve.

## UI proposal: ask the INTENT, then only the identities it needs

Two pickers presented cold make the user solve a 2-axis puzzle. Instead:

Step 1 — pick a shape in plain language, each with its consequence:
  - "Act on my behalf"      -> a post will say: written by <agent>, attributed to <you>
  - "Act as its own identity" -> nothing traces back to you (pseudonymous, not anonymous)
  - "Act as me"             -> ⚠ indistinguishable from you; revoking it revokes you
  - "Grant to an external service" -> <service> acts, attributed to <you>
Step 2 — show ONLY the pickers that shape needs; each with use-existing /
  create-new inline (creation is why sub-identities exist).
Step 3 — confirm with a sentence, not field names:
  "Posts will be attributed to danmills@sandmill.org and written by
   danmills+poster@sandmill.org. You can revoke this at any time."

Requester pins: when a request pins grantor/grantee, preselect and LOCK them,
name who must approve, and REFUSE IMMEDIATELY with a reason if the signed-in
user cannot satisfy the pin — never silently substitute, and never leave the
requester polling for 15 minutes (what happened today: the failure surfaced as
"expired").

## Server changes this needs

1. agent_provision.rs:953 — the owned path hardcodes
   `validate_grant_warrants(..., &agent_email, &agent_email, ...)`, so a named
   agent ALWAYS acts as itself. It must pass grantor = identity_email,
   grantee = agent_email (equal only in the self/as-me mode), and the page
   must sign the warrant to match (warrants are signed client-side).
2. `grantee: "*"` should mean "mint a distinct agent identity" (shape 1) —
   today it collapses to shape 3.
3. Sub-identities must be selectable as the DELEGATING identity (bean y9xm).
4. Validate a foreign grantee's holder at /agent-provision/request time, so
   the requester learns before the human is asked.
5. The poll's terminal states should carry `reason` so a client can report it.

Blocks the on-behalf half of browserid-bsky-nr8p. Supersedes the framing in
browserid-ng-wwec (keep that for the pin-honouring detail).

## Server + page fix LANDED 2026-07-25 (shapes 1/3/4 reachable)

complete_device_cert no longer collapses the grantor. `identity_mode` now has
three values and the grantor follows it:
  self       -> agent_email == identity_email (grantor == grantee)
  handle     -> grantor = the approving human, grantee = the agent (ON BEHALF OF)
  standalone -> grantor == grantee == the agent (segregated identity, shape 3)

account.html signs to match and offers the choice as a CONSEQUENCE, not
protocol vocabulary:
  "On my behalf — attributed to <you>, done by the agent"
  "On its own — attributed to the agent, not to me"
plus the honest note that the agent's handle still contains the user's address,
so the link is guessable by anyone who reads handles.

Warrants are signed client-side, so page and registrar had to move together —
the SDK round-trip test (browserid-agent/tests/merged_provision_sdk_test.rs)
was signing the old shape and caught exactly that. It now asserts BOTH roles:
verified.email == the approving identity, verified.grantee == the agent.
New registrar unit test pins the mode -> grantor mapping.

Note browserid-core already modelled the two roles correctly
(VerifiedAccess.email = attributed, .grantee = actor). Only the registrar was
conflating them, so no core change was needed.

Also: an RP that read `verified.email` expecting the AGENT's identity will now
see the human's for a named agent. That is the point, but it is a
behaviour change for existing consumers.

STILL OPEN here: the intent-first UI rework (ask the shape in plain language,
then show only the pickers it needs), the pin-honouring rules (bean wwec),
sub-identity as delegator (y9xm), and validating a foreign grantee's holder at
request time instead of after approval.

NOT YET TESTED LIVE: browserid.me was 136 commits behind; the deploy is in
flight (on-host Rust build, 2h+ — hence the new CI image pipeline in
094cfc0). The on-behalf test resumes once it lands.

## Verified live 2026-07-25

The fix is deployed on browserid.me and produced a real on-behalf warrant from
a normal choice ("Do things for me"), not a workaround:
  grantor danmills@sandmill.org, grantee danmills+bsky@sandmill.org
The bsky bridge accepted it, the verifier passed all 12 checks, and the labeler
emitted browserid-on-behalf (browserid-bsky-nr8p).

The intent-first card is live too: three intents (attributed to you /
attributed to the agent / indistinguishable from you), the agent identity as a
separate choice (new sub-handle, existing agent, or top-level — Dan: a
top-level handle is a FORM the grantee identity takes, not a fourth shape), and
a live summary sentence.

STILL OPEN, and now the priority: the card is functional but nearly unusable —
9 inputs, 8 labels, protocol vocabulary. Design brief written at
docs/design/2026-07-25-approval-dialog-brief.md, to be taken to design. That
brief supersedes the UI sketches in this bean.

Also still open here: pin-honouring (wwec), sub-identity as delegator (y9xm),
and validating a foreign grantee's holder at request time — that one bit us
live, failing AFTER approval with "a foreign grantee must supply its holder".

## Closed 2026-07-26 — UI rework shipped (browserid-ng-k0s9)

The 'nearly unusable' card is replaced: the design round produced the 'Agent flows' board (A0–A8 / B1–B4) and k0s9 implemented it — on-behalf is the silent default, branches are server facts, pins lock or refuse (never substitute), and the as-you shape is a guarded danger path. Pin-honouring from wwec is in (A3/A4/A6). A foreign grantee without its holder now surfaces on the card BEFORE approval (info exposes grantee_holder); true request-time validation for the requester is follow-up bean form: see k0s9 summary. Sub-identity as delegator remains open as y9xm.
