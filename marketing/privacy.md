# BrowserID privacy

> An identity service should be able to explain itself. This page says, in
> plain language, what BrowserID stores and why. The design goal throughout is
> data minimization: we hold what the protocol needs to work, and nothing
> else. No ads, no data sales, no cross-site tracking — ever.

Last updated: 2026-08-26

## This website (www.browserid.me)

The marketing site you're reading holds no accounts and sets no cookies. It
runs a locked-down, self-hosted copy of PostHog for basic page analytics: page
views, page leaves, and clicks on a handful of named buttons. Autocapture,
session recording, and surveys are disabled; the analytics state lives in your
browser's localStorage, not cookies; and events are scrubbed of anything that
looks like an email address before sending. Events are sent through this
origin and processed by PostHog Inc. (US cloud) on our behalf — no other third
party receives anything.

## The identity service (browserid.me)

When you create an account, the broker stores what the protocol needs: your
email address, a password hash if you set one, the public keys of your devices
and agents, the names you give them, and the warrants (permission grants) you
sign — who may act, where, with what scopes, until when. Sessions use a cookie
on that origin only. Sign-in codes are emailed to you and expire in minutes.
The broker runs no analytics JavaScript; its own server-side event log covers
product funnels (e.g. "an account was created"), not browsing behavior.

**What we can't see:** private keys never leave your devices, and sign-ins at
other sites verify against your email domain's DNS — a relying party checking
a presentation does not tell us who signed in where unless it chooses to use
our hosted verifier for the check.

## What's public by design

Revocation status lists are published so relying parties can check them; they
contain opaque bit indexes, not names or emails. If you have your agent sign
the demo guestbook, the entry — its display name, its issuer domain, and its
message — is public; emails are not shown. Warrants are held by the sites you
granted them to; that's what a grant is.

## Deleting your data

You can revoke any grant, remove any agent, or cancel your whole account at
[browserid.me/account](https://browserid.me/account). Cancelling deletes the
account's stored emails, keys, and grants; already-issued short-lived
certificates simply expire, and revocation takes effect on the next
fail-closed check.

## Self-hosting means never having to trust us

Everything above describes the hosted service at browserid.me. The entire
stack is open source (MPL-2.0) — if this policy ever stops being one you like,
you can run your own broker under your own domain and this page stops applying
to you at all.

## Questions

Ask on [GitHub](https://github.com/vthunder/browserid-ng/issues) or email
**code@sandmill.org** — see the [contact page](/contact). Material changes to
this policy will be noted here with a new date.

## More

- [About](/about) · [Contact](/contact) · [llms.txt](/llms.txt)
- [GitHub](https://github.com/vthunder/browserid-ng) · [Spec](https://github.com/vthunder/browserid-ng/tree/main/docs/specs)
