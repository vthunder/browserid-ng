# About BrowserID

> An open identity protocol, run in the open. BrowserID (browserid-ng) is an
> open, DNS-rooted identity protocol: AI agents get their own cryptographic
> identity, delegated from a human, scoped to exactly what the human approved,
> and revocable at any time. Human passwordless sign-in included.

## Where it comes from

The protocol descends from **BrowserID**, the email-based sign-in protocol
behind Mozilla Persona (2011–2016). browserid-ng is an independent successor —
it keeps Persona's best idea, that your email address is your identity and its
domain is your issuer, and extends it to the thing 2011 never anticipated:
agents acting on your behalf. It is not affiliated with or endorsed by Mozilla.

Everything the original got right is still here: no passwords held by relying
parties, no central identity vendor at sign-in time, verification rooted in
the domain's own DNS. What's new is the authority model — warrants a human
signs for an agent, scoped to one site and a few actions, checked fail-closed
on every call, and revocable from one page.

## Who builds and runs it

BrowserID is built and operated by **Dan Mills**
([@vthunder](https://github.com/vthunder)). The code is open source under the
[Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/) and
developed in public at
[github.com/vthunder/browserid-ng](https://github.com/vthunder/browserid-ng) —
the protocol spec, the broker, the SDKs, and this website included. Questions
and bug reports are welcome on the [contact page](/contact).

## Pricing

**Everything is free.** The hosted broker, the wallet, the verifier, domain
onboarding, and all SDKs cost nothing to use — no API keys, no registration,
no rate-limit tiers, no billing. BrowserID is an open-source protocol offered
as an open service.

Will that change? Paid offerings may appear someday for advanced or at-scale
features, but the basics — sign-in, verification, the wallet, revocation — are
intended to stay free. And because the protocol is open and the whole stack is
self-hostable, you are never locked in: your domain's one DNS record can point
at a key you hold instead of ours, any time.

## The design in one paragraph

Your identity is your email address. Its domain publishes one DNSSEC-signed
record that makes the domain its own issuer (or delegates to a hosted one). A
human signs a *warrant* naming an agent, a site, and a scope; the agent
presents it alongside its own certificate; the relying party verifies the
whole chain in one call — against DNS, not against a vendor. Revoking the
warrant kills the agent's access on its next check, everywhere, without
touching the human's own credentials.

## More

- [Contact](/contact) · [Privacy](/privacy) · [llms.txt](/llms.txt)
- [GitHub](https://github.com/vthunder/browserid-ng) · [Spec](https://github.com/vthunder/browserid-ng/tree/main/docs/specs)
