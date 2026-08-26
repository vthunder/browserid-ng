# BrowserID principles

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

For humans and agents alike. An open identity system needs its identifiers
to have three qualities: everyone already understands them as identity;
anyone can issue them; and each name carries its own trust root, so whoever
vouches for it can be found from the name alone. Email addresses are the
only identifier that has all three — anyone can issue by registering a
domain, and the name declares its issuer at the `@`. Anything that isn't an
email is plumbing, or gets tied to an email before a person or agent has to
deal with it.

### 2. No gatekeepers.

Anyone can join — as an identity provider, a site, or a broker — by
publishing a record and speaking the protocol. No applying, no registering,
no paying, no partnering. There is no list of blessed parties in the design;
a two-person domain and the largest mail provider on earth have the same
standing. Defaults exist — our implementations point at browserid.me so the
system works out of the box (see 7) — but a default is not a gate: nothing
in the protocol requires it, and every default has an escape hatch.

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
benefits are stillborn. So we ship the scaffolding that makes the system
whole from day one: a fallback issuer for domains that have none, a hosted
verifier, a hosted wallet. Any site can adopt today and reach everyone with
an email address.

The scaffolding is essential and may well stay — browserid.me may remain
the common broker for a long time, and that's fine. What matters is not
that anyone replaces it, but that anyone can: your own issuer for your
domain, your own verifier for your site, a browser that speaks the protocol
natively for the user. Openness lives in the ability to leave, not the
obligation to.
