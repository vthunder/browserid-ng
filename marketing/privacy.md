# Privacy policy

Last updated: 2026-08-26

## Who runs this

BrowserID is a free, open-source project operated by one person (see the
[contact page](/contact)). This policy covers the website
(www.browserid.me), the identity service (browserid.me), and the hosted
wallet and verifier. It is a hobby project, run with care but on a
best-effort basis: there are no SLAs, no compliance certifications, and no
legal department — please treat the service accordingly. The full source
code is [public](https://github.com/vthunder/browserid-ng), so every claim
on this page can be checked.

## What we collect

If you create an account, the identity service stores your email address, a
password hash if you set a password, the public keys of your devices and
agents, the names you give them, and the warrants (permission grants) you
sign — who may act, where, with what scopes, until when. Private keys are
generated and kept on your devices; we never see them.

Sign-in codes are sent to your email address and expire within minutes. A
session cookie keeps you signed in on browserid.me.

We collect basic product analytics: page views and a few named button clicks
on the website, and server-side events on the identity service (for example,
that an account was created). Identity-service events identify users only by
an opaque hash of the email address; raw email addresses, verification
codes, and IP addresses are never included in analytics events.

Like almost every web service, our servers keep standard request logs, which
include IP addresses. We use them for operations and abuse prevention,
including rate limiting.

If a site uses our hosted verifier, its verification requests tell us who
signed in there. A site that would rather we not see that can run its own
verifier.

## Who else receives data

Analytics events from both origins are processed by PostHog Inc. (US) on our
behalf. Sign-in code emails are delivered through our email provider, which
necessarily sees the recipient address. The service runs on servers rented
from commodity hosting providers. We do not run ads, do not sell data, and
do not track you across other sites.

## What is public

Revocation status lists are published so relying parties can check them;
they contain opaque bit positions, not names or emails. Guestbook entries —
display name, issuer domain, and message — are public, and they remain on
the wall after the account that signed them is deleted. Warrants you grant
are held by the sites you granted them to.

## Cookies and local storage

browserid.me sets one cookie, for your signed-in session. www.browserid.me
sets no cookies; it uses localStorage for your theme choice and the
analytics state.

## Retention and deletion

Sign-in codes expire within minutes. Access certificates are short-lived and
expire on their own. You can revoke any grant, remove any agent, or cancel
your account at [browserid.me/account](https://browserid.me/account);
cancelling deletes the stored account data — email addresses, password hash,
keys, names, and grants. Revocation takes effect on a relying party's next
status check. Guestbook entries are not stored with the account and are not
removed by cancelling it. Server logs are kept briefly and rotated.

## Changes and contact

Changes to this policy are posted here with a new date. Questions: the
[contact page](/contact). The whole stack is open source and self-hostable —
a service you run yourself is not covered by this policy.

## More

- [About](/about) · [Principles](/principles) · [Contact](/contact) · [llms.txt](/llms.txt)
- [GitHub](https://github.com/vthunder/browserid-ng) · [Spec](https://github.com/vthunder/browserid-ng/tree/main/docs/specs)
