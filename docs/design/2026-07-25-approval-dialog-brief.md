# Design brief: the agent authorization dialog

**Surface:** `browserid.me/account`, the "Authorize an agent" card
(`browserid-broker/static/account.html`, `#provision`). A sibling surface,
`consent.html` ("Agent consent"), handles later permission requests for an
agent that already exists — a redesign should decide whether these become one
pattern.

**Problem:** 9 inputs and 8 labels in one card, several only meaningful in
combination, phrased in protocol vocabulary. It is nearly unusable. It is also
the single highest-stakes screen in the product: everything downstream is
"the human approved this".

## Who is here, and why

An AI agent asked for permission. It cannot proceed without a human. The
person lands here from a link the agent showed them (or by typing a short
code), often with no idea what browserid is. They want to get back to what
they were doing. They may be on a phone.

They are approving something a bit unusual: not "log in with X", but "let this
software act, with consequences attached to my name".

## The one decision that matters

Everything else is detail. The user is choosing **whose name is on what the
agent does**:

| Shape | Meaning to a reader of the result | Protocol |
|---|---|---|
| Acts for me | "Dan said this, his agent typed it" | grantor = human, grantee = agent |
| Acts as itself | "dan+poster said this" | grantor == grantee == agent |
| Acts as me | indistinguishable from the human | grantor == grantee == human ⚠ |

The third is dangerous and occasionally necessary. It must be possible,
never accidental, and its cost must be legible: nothing afterwards can
separate the agent's actions from the human's, and revoking it means revoking
themselves.

Secondary, only when there IS a separate agent: **which agent identity** — a
new sub-address (`dan+poster@…`), one the account already has (reuse beats
minting one per app), or its own top-level address (no provider supports this
yet; show as unavailable, do not hide).

Also present, sometimes: **which of the human's identities** is delegating
(they may have several); and **what the agent may do** — a list of requested
permissions ("post to Bluesky") which today renders as a separate block.

## Hard constraints

- Static HTML + inline JS inside a Rust binary. Strict CSP: no external
  fonts/CSS/JS/images; every inline script is SHA-256-pinned in the server
  (`INLINE_SCRIPT_HASHES`), so script changes require a matching const update.
- The server contract is fixed unless we change it: `identity_mode` is
  `self` | `handle` | `standalone`, plus a `handle` string, plus the
  delegating `identity_email`. Warrants are signed CLIENT-SIDE here, so the
  page is not a dumb form — it holds keys and produces signatures.
- A request may PIN the grantor and/or grantee. Pinned fields must be shown
  as fixed and explained, and if the signed-in user cannot satisfy a pin the
  page must refuse with a reason, not substitute something.
- A "foreign" grantee (a service with its own identity, e.g. `poster@mingo`)
  is a real case: the actor is fixed by the request, only "who it acts for"
  remains. It also needs the service's holder id, which today fails AFTER
  approval with "a foreign grantee must supply its holder".
- Must work for a first-time user with no browserid account: the page also
  offers sign-in / register / add-an-email inline.

## What good looks like

1. A stranger approves the right thing in under 30 seconds without reading
   documentation.
2. They can say afterwards, correctly, whose name is on the agent's actions.
3. Nobody grants "act as me" by clicking through defaults.
4. The dangerous choice and the safe choice are not visually symmetrical.
5. Words a non-technical person uses. Not: grantor, grantee, holder, warrant,
   scope, config cert, provisioning.

## Evidence from the current design (all observed, this week)

- A user picked "with its own handle" and got a warrant where the agent was
  ALSO the attributed party — because the page could not express the
  distinction. Nothing on screen told them.
- Requests that pinned an identity failed silently: the page substituted the
  user's choice, and the requester learned 15 minutes later as "expired".
- The identity picker offers only root identities, so an account owned by a
  sub-identity can never delegate — invisible in the UI, fatal later.
- Defaults matter more than we thought: a pre-selected shape is what most
  people will approve.

## Open questions for design

- Should the shape be chosen, or INFERRED from what the agent asked for, with
  the human just confirming a sentence? (The requester can pin its intent.)
- Is "acts as itself" worth exposing to a normal user at all, or is it an
  advanced case? Note it is pseudonymous, not anonymous: the handle contains
  the owner's address.
- One dialog for both first authorization and later permission requests
  (`consent.html`), or two?
- How should the requested permissions ("post to Bluesky") sit relative to
  the identity choice — same card, progressive disclosure, or a second step?
- What does the confirmation look like on a phone, where the summary sentence
  is the only thing many people will read?
