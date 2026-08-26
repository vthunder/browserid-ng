# Why browserid.me exists

> The web never got an open identity layer. Agents are forcing the question
> open again — and this time, the open answer has to be the one that works.

I led the BrowserID/Persona effort at Mozilla from its first days — first
building, then as product lead — until shortly after Persona launched. Plenty
of people contributed as much as I did, and more on the technical side; but I
was in the room for just about every protocol and product decision, so I know
what we got right and where it failed. What we got right, I'd still defend
today: email as identity, and shipping the scaffolding ourselves — it worked
with any email, in any browser, from day one, and the only people we had to
convince were websites. Why it died is a longer story: timing and priorities
inside Mozilla at least as much as anything in the market, a too-late bridge
to the big mail providers, and, yes, passwords that were just barely
tolerable — so an open protocol stayed optional. The project failed; the idea
never did.

A decade of other work later, agents changed the terms. You cannot hand an
agent your password and call it fine; credentials that merely annoyed humans
become indefensible at machine speed. The identity question is open again,
and the answer will harden into infrastructure that lasts decades.
browserid-ng is my second run at it: Persona's best idea, kept — and extended
to the thing 2011 never anticipated, agents acting on your behalf. It's an
independent project, not affiliated with Mozilla.

## What guides it

Everything here is built against a short set of written principles. Their
spirit, in one breath: your identity is an email-shaped name that answers to
you and no one else; anyone can join the system — as an issuer, a site, or a
broker — without asking permission; an agent is a real actor whose authority
is always borrowed — scoped, attributed, revocable; all of it has to be easy,
because ease is what makes the right way the common way; everything that
stands between you and the world, browser and wallet and broker and the AI
agent itself, owes its loyalty to you; and none of it may ask anyone to
choose between open and working. The full eight are short and worth reading:
[the principles](/principles).

## Try it

The whole stack is open source (MPL-2.0), free to use, and developed in
public by me, Dan Mills ([@vthunder](https://github.com/vthunder)) —
protocol, broker, SDKs, this site. But the fastest way to understand it is to
try it: in a couple of minutes your agent can have an identity of its own,
sign a public wall with it, and lose the permission the moment you revoke it.
Start with [the demos](/demos), or say hello via the
[contact page](/contact).

## More

- [Principles](/principles) · [Contact](/contact) · [Privacy](/privacy) · [llms.txt](/llms.txt)
- [GitHub](https://github.com/vthunder/browserid-ng) · [Spec](https://github.com/vthunder/browserid-ng/tree/main/docs/specs)
