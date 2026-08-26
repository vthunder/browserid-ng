# BrowserID principles

> **Working draft.** This is a baseline to iterate on, not a finished
> declaration. Workshop notes and open questions are at the bottom.
> Tracking: bean browserid-ng-0med.

## Why now

The web never got an identity layer. Into that gap came the platforms:
"Sign in with" a company, on that company's terms, under that company's
watch. We tried to build the open alternative once — BrowserID, Mozilla
Persona — and lost. We lost in part because, for humans, passwords were just
barely tolerable: the open protocol was optional, and optional wasn't
enough.

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

### 2. New identity providers, sites, and brokers need no one's blessing.

Joining the system means publishing a record and speaking the protocol — not
applying, registering, paying, or partnering. There is no list of blessed
parties anywhere in the design: a two-person domain and the largest mail
provider on earth have exactly the same standing. Structural openness is the
guarantee; the protocol can't dictate whom the market favors, but it will
never hard-code a favorite.

### 3. Where you sign in is between you and the site.

Your identity provider vouches for your name; it does not learn where you
use it and it does not get a veto. This is architecture, not policy: for a
personal identity the issuer sits outside the sign-in path entirely, so
watching or selectively blocking your logins is structurally unavailable to
it — the worst it can do is refuse you service outright, which is coarse,
visible, and escapable (see 2).

Managed identities are the disclosed exception, by the same rule: they
belong to organizations, not users. The organization that issues a managed
identity legitimately sees and governs its use — and everyone dealing with
one can see that it is that kind of identity. What a party may see and stop
is exactly what its authority covers; nobody holds hidden levers.

### 4. All authority is borrowed.

Agents are real actors with real identities, but everything an agent may do
is delegated to it: granted by a person (or an organization) in an explicit
signature, scoped to named places and actions, expiring on a date, revocable
at any moment — and when in doubt, the answer is no. Revoking an agent never
costs the human their own access.

Below the fold: borrowing composes but never amplifies — a delegate that
granted more than it holds would be lending authority it never borrowed, so
delegation can only narrow. And honesty about reach: the protocol delivers
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

Below the fold: consequences need an address. Because an agent has an
identity of its own, consequences can attach to it — a site can block or
rate-limit one agent without touching the person behind it, and a person can
revoke one agent without rotating their own life.

### 6. Anything that acts between you and the world owes its loyalty to you.

The browser was named the "user agent" for a reason: software that stands
between a person and the network represents that person. We extend the same
duty to everything identity requires — the wallet, the broker, and the AI
agent itself are all the user's agent.

Loyal in interest, neutral in fact: your agent represents you, but it never
lies for you. Everything an intermediary asserts to a counterparty is
verifiable by that counterparty, so sites and issuers trust the protocol,
not the operator's character — that verifiability is what lets a broker be
loyal to users and still be trusted ground for everyone else. And the
loyalty is enforced by architecture, not promises: an intermediary holds the
minimum knowledge needed to do its job (it can't betray what it can't see),
and every intermediary is replaceable (it stays honest because you can walk
away).

### 7. Open must also mean working.

A site adopting the protocol targets 100% of people with an email address on
day one — no waiting for issuers to adopt, no chicken-and-egg. We ship the
scaffolding that makes this true: a fallback issuer for domains that have
none, a hosted verifier, a hosted wallet. An RP never has to choose between
"open" and "working."

Scaffolding, not a cathedral: every scaffold is designed to be replaced —
by your own domain, your own verifier, your own broker — and its success is
measured by its eventual irrelevance.

---

## Workshop notes (not part of the manifesto)

**Bold lines still being workshopped:**

- (2) current line is serviceable but flat. Rejected: "Entry requires a
  domain, not a deal" (reads AI-punchy). Other candidates: "Anyone can set
  up shop." / "No gatekeepers at the door."
- (3) candidates rejected so far: "Attestation is not dominion" (opaque),
  "Issuers vouch; they don't watch" (misses the veto half, punchy).
  Current line is closest to the plain statement of the principle.
- (7) alternatives: "Working everywhere is part of the protocol."

**Structural questions still open:**

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

**Deliberately excluded:**

- Operator commitments (free hosted service, etc.) — kept out per the test
  "would we demand this of someone else's deployment?" The one that passes
  ("no fee to federate") already lives in 2.
- Attenuation as its own principle — derivable from 4; chained warrants are
  roadmap.
- The "a web where…" aspirational preamble — the principles drive; the
  "Why now" story carries the stakes.
