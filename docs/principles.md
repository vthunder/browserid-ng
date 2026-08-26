# BrowserID principles

> **Working draft.** This is a baseline to iterate on, not a finished
> declaration. Workshop notes and open questions are at the bottom.
> Tracking: bean browserid-ng-0med.

## Why now

The web never got an identity layer. Into that gap came the platforms:
"Sign in with" a company, on that company's terms, under that company's
watch. The open alternative has been tried more than once — OpenID, Mozilla
Persona and its BrowserID protocol (our own lineage), and others — and every
attempt lost. They lost in part because, for humans, passwords were just
barely tolerable: an open protocol was optional, and optional wasn't enough.

Agents end that truce. You cannot hand an agent your password and call it
fine; borrowed credentials that merely annoyed humans become indefensible at
machine speed. The identity question is being forcibly reopened right now,
and the answer will harden into infrastructure that lasts decades. Layers
this deep get rebuilt about once a generation.

We get to make this choice again. Let's choose correctly this time. These
are the principles we're choosing by.

## Principles

### 1. Your identity is an email-shaped name.

For humans and agents alike. Email addresses are the only identifier with
all three qualities an open identity system needs: everyone already
understands them as identity; anyone can issue them by registering a domain;
and the name carries its own trust root — split on the `@` and you know who
vouches for it. Anything that isn't an email is plumbing, or gets tied to an
email before a person or agent has to deal with it.

### 2. No gatekeepers.

Anyone can join — as an identity provider, a site, or a broker — by
publishing a record and speaking the protocol. No applying, no registering,
no paying, no partnering. There is no list of blessed parties anywhere in
the design; a two-person domain and the largest mail provider on earth have
the same standing. The protocol can't dictate whom the market favors —
sites still pick which brokers they trust — but it will never hard-code the
choice.

### 3. Every identity answers to its owner — and no one else.

You own your personal identity, so where you sign in is between you and the
site: your identity provider vouches for your name, but never learns where
you use it and gets no veto. That's architecture, not policy — the issuer
sits outside the sign-in path, so watching or selectively blocking you is
structurally impossible. The worst it can do is refuse you outright: coarse,
visible, and escapable (see 2).

Organizations own managed identities — the same rule, different owner. The
issuing organization rightly sees and governs their use, and anyone dealing
with one can see what kind of identity it is. Either way, who an identity
answers to is disclosed, and no one else holds levers over it.

### 4. All authority is borrowed.

Agents are real actors with real identities, but everything an agent may do
is delegated: granted by a person or an organization in an explicit
signature, scoped to named places and actions, expiring, revocable at any
moment — and when in doubt, the answer is no. Revoking an agent never costs
the human their own access.

Borrowed authority can be passed on but never amplified — a delegate can
grant only a narrower slice of what it holds. And the protocol delivers
attribution and scope to the site; whether the site displays them, and how
much a human chooses to grant, remain their choices. We build the rails; we
can't force the trains.

### 5. One protocol for humans and machines.

No caste system, no separate agent lane, and no pretending the protocol can
tell which actors are human — any protocol that claims to is wrong or lying.
Walling agents out of "human-only" actions doesn't produce a web without
agents; it produces agents wearing their humans' faces. We make honesty
cheaper than masquerade: acting as itself, with borrowed authority, works
everywhere, so an agent never needs to impersonate anyone.

And consequences need an address: an agent with its own identity can be
blocked or rate-limited without touching the person behind it, and revoked
without that person rotating their own life.

### 6. Anything that acts between you and the world owes its loyalty to you.

The browser was named the "user agent" for a reason: software that stands
between a person and the network represents that person. We extend the same
duty to everything identity requires — the wallet, the broker, and the AI
agent itself are all the user's agent.

This is a duty, not a description. People worry — rightly — that an AI
agent may serve its vendor, or its objective, before its user. We cannot
make every agent loyal. What the identity layer can do is give the duty
teeth: an agent acts within a scope its human granted, under a name that
consequences can attach to, with access that ends the moment trust does.
Where loyalty can't be verified, boundaries can be enforced.

For the intermediaries we build — the wallet, the broker — the duty is
concrete: loyal in interest, neutral in fact. They represent you but never
lie for you: everything they assert is verifiable by the party receiving
it, which is what lets a broker take the user's side and still be trusted
ground for sites and issuers. They know as little as their job requires,
and they can be replaced.

### 7. No one has to choose between open and working.

Identity systems that need many kinds of parties to adopt before anyone
benefits are stillborn — chicken-and-egg is what killed the last generation.
So we ship the scaffolding that makes the system whole from day one: a
fallback issuer for domains that have none, a hosted verifier, a hosted
wallet. Any site can adopt today and reach everyone with an email address.

The scaffolding is essential and may well stay — browserid.me may remain
the common broker for a long time, and that's fine. What matters is not
that anyone replaces it, but that anyone can: your own issuer for your
domain, your own verifier for your site, a browser that speaks the protocol
natively for the user. Openness lives in the ability to leave, not the
obligation to.

---

## Workshop notes (not part of the manifesto)

**Bold-line status:**

- (2) "No gatekeepers." adopted (Dan's pick from the candidates). Rejected
  along the way: "Entry requires a domain, not a deal" (reads AI-punchy),
  "New IdPs/sites/brokers need no one's blessing" (brokers weakened the
  claim — a site still chooses which brokers to accept; now said honestly
  in the body).
- (3) reframed around ownership ("Every identity answers to its owner")
  so managed identities read as the same rule with a different owner, not
  an exception contradicting the headline. Earlier rejections: "Attestation
  is not dominion" (opaque), "Issuers vouch; they don't watch" (misses the
  veto half).
- (7) "No one has to choose between open and working." — Dan's suggested
  line, shifted from "should have to" into is/does form per the
  dreams-in-the-opening rule. Alternate headline candidate if this one ever
  wobbles: something built on "no chicken-and-egg."

**Framing memo — swapping the broker (keep in mind, not in the text):**
Replacing the broker is not unilateral for any single party. Either the RP
chooses a different broker (real cost: users won't have it set up and face
an unfamiliar implementation), or the user's browser natively implements
the navigator.id.* APIs (fine — the user's own choice), but if that
browser's broker issues fallback certificates the RP still has to trust
that fallback; no way around it. Our implementations hard-code browserid.me
as the default broker because principle 7 demands *some* default. This is
why (7) names the per-party swap paths (issuer↔domain, verifier↔site,
native browser↔user) instead of claiming "anyone can swap the broker"
flatly, and why (2) says "sites still pick which brokers they trust."

**Structural questions still open:**

- (1): do the three qualities of email (understood as identity; openly
  federated; trust root discoverable from the name) stay folded under one
  principle, or become principles of their own? Current lean: folded —
  they're the argument for a choice, not independent commitments.
- Does the diagnosis (borrowed passwords, no boundaries, no kill switch —
  the homepage problem statement) join the "Why now" story, or is that
  audience already converted?
- Contrast-pairs coda (human authority over agent autonomy; legible over
  unlinkable; open federation over curated trust; revocation over rotation;
  working defaults over pure decentralization) — parked; decide after the
  main text settles.
- "Censorship resistance" as a word appears nowhere; the substance lives in
  3 (coarse/visible/escapable) and 2 (exit). Confirm we're happy leaving
  the term out.
- (6): the AI-agent paragraph now frames loyalty as a duty the identity
  layer enforces boundaries around ("where loyalty can't be verified,
  boundaries can be enforced") — confirm this is the right register, vs.
  stating it as pure aspiration.

**Deliberately excluded:**

- Operator commitments (free hosted service, etc.) — kept out per the test
  "would we demand this of someone else's deployment?" The one that passes
  ("no fee to federate") already lives in 2.
- Attenuation as its own principle — derivable from 4; chained warrants are
  roadmap.
- The "a web where…" aspirational preamble — the principles drive; the
  "Why now" story carries the stakes.
