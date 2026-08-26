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

For humans and for agents alike. Email addresses are the only identifier
with all three of the qualities an open identity system needs: everyone
already understands them as identity; they are openly federated — anyone can
become an issuer by registering a domain; and the name carries its own trust
root — split on the `@` and you know who vouches for it. Anything that is
not an email is plumbing, or gets tied to an email before a human or agent
has to deal with it.

### 2. No gatekeepers.

Anyone can join the system — as an identity provider, a site, or a broker —
by publishing a record and speaking the protocol: no applying, no
registering, no paying, no partnering. There is no list of blessed parties
anywhere in the design; a two-person domain and the largest mail provider on
earth have exactly the same standing. The openness is structural, not
promised: the protocol can't dictate whom the market favors — sites still
choose which brokers they'll accept — but it will never hard-code the choice
for them.

### 3. Every identity answers to its owner — and no one else.

You own your personal identity, so where you sign in is between you and the
site. Your identity provider vouches for your name; it does not learn where
you use it and it does not get a veto. This is architecture, not policy: for
a personal identity the issuer sits outside the sign-in path entirely, so
watching or selectively blocking your logins is structurally unavailable to
it — the worst it can do is refuse you service outright, which is coarse,
visible, and escapable (see 2).

Organizations own managed identities — the same rule with a different owner.
The organization that issues a managed identity legitimately sees and
governs its use, and everyone dealing with one can see that it is that kind
of identity. In both cases, who an identity answers to is disclosed, and no
one else holds levers over it.

### 4. All authority is borrowed.

Agents are real actors with real identities, but everything an agent may do
is delegated to it: granted by a person (or an organization) in an explicit
signature, scoped to named places and actions, expiring on a date, revocable
at any moment — and when in doubt, the answer is no. Revoking an agent never
costs the human their own access.

Borrowing composes but never amplifies: a delegate that granted more than
it holds would be lending authority it never borrowed, so delegation can
only narrow. And honesty about reach: the protocol delivers
attribution and scope to the relying party; whether an RP displays "agent A
acting for user U," and whether a human grants an agent everything, are
their choices. We build the rails; we can't force the trains.

### 5. One protocol for humans and machines.

No caste system, no separate agent lane, and no pretending the protocol can
tell which actors are human — any protocol that claims to is wrong or lying.
Walling agents out of "human-only" actions doesn't produce a web without
agents; it produces agents wearing their humans' faces. So we make honesty
cheaper than masquerade: an agent never needs to impersonate anyone, because
acting as itself, with borrowed authority, works everywhere.

And consequences need an address: because an agent has an identity of its
own, consequences can attach to it — a site can block or
rate-limit one agent without touching the person behind it, and a person can
revoke one agent without rotating their own life.

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
concrete: loyal in interest, neutral in fact. They represent you, but never
lie for you. Everything they assert to a counterparty is verifiable by that
counterparty, so sites and issuers trust the protocol rather than the
operator's character — that verifiability is what lets a broker be loyal to
users and still be trusted ground for everyone else. And the loyalty is
enforced by architecture, not promises: hold the minimum knowledge needed
(you can't betray what you can't see), and stay replaceable (honest because
your users can walk away).

### 7. No one has to choose between open and working.

A site adopting the protocol reaches 100% of people with an email address on
day one — no waiting for issuers to adopt, no chicken-and-egg. Identity
systems that need many kinds of parties to join before anyone benefits are
stillborn; we ship the scaffolding that makes the system whole from the
start: a fallback issuer for domains that have none, a hosted verifier, a
hosted wallet.

The scaffolding is essential, and it may well stay: browserid.me may remain
the common broker for a long time, and that's fine. What matters is not
that anyone replaces it, but that anyone can — every hosted piece can be
swapped for your own domain, your own verifier, your own broker. Openness
lives in the ability to leave, not the obligation to.

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
  dreams-in-the-opening rule.

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
