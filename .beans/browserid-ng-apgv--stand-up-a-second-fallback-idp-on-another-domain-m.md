---
# browserid-ng-apgv
title: RP-chosen external SMTP fallback — browserid.me routes to it, no trust on browserid.me
status: completed
type: feature
priority: normal
created_at: 2026-07-11T16:08:54Z
updated_at: 2026-07-11T19:23:07Z
---

Demonstrate — and build the flow for — an RP that trusts **only** an external SMTP verifier (`other.fallback.com`), never browserid.me, while **browserid.me stays the broker**. Validates 8t8h with a real second issuer and proves browserid.me need not be a trusted identity authority for an RP to use it.

**This is NOT a second broker** (that's 0efn, user-chosen broker). Here browserid.me remains the broker — mediator + account (password) + roster + keystore — and merely **routes email verification to an RP-accepted external fallback** and stores the returned cert.

## Corrected model (supersedes the first draft of this bean)

Roles:
- **Broker = browserid.me**: mediator + account. Holds the **password**, the **roster** of emails, and the **keystore** (certs + keys, per email/issuer). The password unlocks the roster AND (practically) the keystore. Serves the dialog. Routes verification to an RP-accepted fallback; reuses stored certs while valid.
- **Fallback / SMTP verifier / issuer**: browserid.me's *own* SMTP, OR an external one (`other.fallback.com`). Proves control of an email (SMTP challenge), then issues a **short-lived cert** (`iss=<fallback domain>`) for a supplied pubkey. Publishes its `_browserid` DNSSEC key.
- **RP**: declares `acceptedFallbacks`; its verifier accepts a cert only if `iss` is in the set.

Key facts (corrections to earlier mistakes):
- **Re-verification is periodic, not once-forever.** browserid.me-as-fallback re-verifies ~every 30 days. An external fallback should issue **7–30 day certs** (revocation — egr7 — makes shortish certs cheap), giving the *same* per-device cadence. The password does NOT replace verification forever; it unlocks the roster + keystore and lets stored (still-valid) certs be used.
- **The broker keeps its password.** It protects the roster + keystore and is valuable regardless of which fallback issued the certs. (Earlier "mediator shouldn't have a password" was wrong.)
- One user, many fallbacks → **many certs in one keystore, one password**.

## Flow to build

1. RP declares `acceptedFallbacks: ["other.fallback.com"]` (excludes browserid.me).
2. User at that RP enters `a@b.com` (no primary). browserid.me's dialog sees browserid.me isn't accepted but `other.fallback.com` is → **routes verification to `other.fallback.com`**: generate a keypair (key stays at the browserid.me origin keystore), hand the pubkey + email to `other.fallback.com`, which SMTP-challenges `a@b.com`, and on proof returns a cert (`iss=other.fallback.com`, ~7–30 day). browserid.me stores it under `(a@b.com, other.fallback.com)` and logs into the RP. browserid.me itself sends no mail.
3. The user sets a **browserid.me password** (protects the account/roster/keystore) — regardless of which RP they used first.

## Corner cases (all in scope)

- **Add `b@c.com` at another RP** (accepts a different fallback): roster gains it; a second cert from that issuer joins the keystore.
- **New device**: password unlocks the roster (shows `a@b.com`, `b@c.com`), but the keystore is empty here → re-verify each email via its fallback (one SMTP roundtrip per email/fallback) to repopulate. Same as browserid.me's own 30-day re-verify cadence.
- **Forgot password**: reset via browserid.me's **own** SMTP (it emails the account itself — confirmed: `stage_reset` → `send_password_reset`; never leans on a fallback), set a new password. On a keyless device that then wants the external-fallback RP, also re-verify via `other.fallback.com` → up to **2 roundtrips** (reset + fallback). Accepted friction; the password still earns its keep by unlocking the roster + reusing valid certs elsewhere.
- **RP1 (trusts browserid.me) + RP2 (trusts other.fallback.com)**: user SMTP-verifies **twice** (once per fallback), ends with **two certs** in the store, **one password** unlocking the list and letting both stored certs be used while valid. Password set regardless of which RP is used first.

## Components to build

1. **External fallback service** (`other.fallback.com`): pubkey-in / cert-out after an SMTP challenge (a stripped broker: fallback+issuer role only, no mediator/account). Short-lived certs; `_browserid` DNSSEC key. (Related to the standalone-provision / login-support-doc idea in pn5n.)
2. **Mediator routing** in browserid.me's dialog: when the RP accepts an external fallback (not browserid.me), drive verification through it (cross-origin pubkey-in/cert-out; the RP-facing privkey stays in the browserid.me-origin keystore) and store the returned cert. NOTE: today the dialog can only *decline* browserid.me (8t8h) — routing to an external fallback is the new build here.
3. **Keystore**: hold certs from multiple issuers per email; reuse while valid; account/password/roster unchanged.

## Blocker (needs the user): DNS

DNSSEC-rooted, so `other.fallback.com` needs an A/CNAME → host and a **DNSSEC-signed `_browserid` TXT** with its pubkey. I can generate the exact record values; adding them is the user's (DNS provider). Standing up the public service is outward-facing — confirm before creating.

## Decisions

- **Domain** for the external fallback: a `sandmill.org` subdomain (already DNSSEC-signed — simplest) or another owned domain?
- **Email verification**: real SMTP (mail config on the fallback) or a console/mock verifier for the demo?

## Related

Builds on / validates 8t8h (RP-selected fallbacks). Distinct from 0efn (user-chosen *broker*). The external-fallback service reuses the pubkey-in/cert-out idea from pn5n.

## Progress (2026-07-11) — fallback issuer deployed

Milestone 1 (the external fallback issuer) is up. `browserid-broker` deployed as dokku app `fallback` at `fallback.sandmill.org` (host 198.199.110.160), keyed via `BROKER_KEY_SECRET` (env-loaded seed; pubkey `wFa8FDEzhPB1gANJ22jKk5JxYxvD3jrZRtYX44TCkuc`), own `/data` SQLite volume, Resend SMTP reused (from `fallback@id.sandmill.org`), agent-provisioning off. Serving `/.well-known/browserid` with the matching key (verified via Host header pre-DNS).

Waiting on the user's DNS (2 records on the DNSSEC-signed sandmill.org zone):
- `fallback.sandmill.org A 198.199.110.160`
- `_browserid.fallback.sandmill.org TXT "v=browserid1; public-key-algorithm=Ed25519; public-key=wFa8FDEzhPB1gANJ22jKk5JxYxvD3jrZRtYX44TCkuc; host=fallback.sandmill.org"`

Then: enable Let's Encrypt TLS; verify a fallback.sandmill.org-issued cert validates via its DNSSEC key with browserid.me nowhere in the chain.

Still to build (milestone 2): mediator routing — browserid.me's dialog driving verification *through* this fallback and storing the returned cert (today the dialog can only decline browserid.me, 8t8h). Plus the keystore/corner cases.

Code landed this session: `BROKER_KEY_SECRET` env support + `gen_broker_key` example (committed).

## Progress (2026-07-11) cont. — fallback live + /verify accepts external fallbacks

- DNS live: A + DNSSEC-validated `_browserid` TXT for fallback.sandmill.org. TLS enabled (Let's Encrypt); app serves HTTPS.
- **Design correction (vthunder):** the external fallback is an ISSUER only, NOT a verifier. The RP delegates verification to browserid.me's `/verify` (a verification *service*), passing its accepted fallbacks. So `/verify` (and `verify_assertion_with_dns`) now take `accepted_fallbacks`: a no-primary email's cert is authorized iff its issuer ∈ the set, and the issuer's key is resolved via ITS OWN DNSSEC record. Primaries always accepted; primary domains can't be fallback-overridden. Default (no list) = {this broker}. Deployed to browserid.me.
- Nice datapoint: browserid.me/verify with the *default* list correctly REJECTS a fallback.sandmill.org cert ("not an accepted fallback"); it accepts only when the RP lists it — proving browserid.me isn't a universal root.
- Tests: verifier_test accepted_external_fallback_is_authorized (rejected by default, accepted when listed); workspace 367 green.

Next: live proof — POST to browserid.me/verify with accepted_fallbacks=["fallback.sandmill.org"] and a fallback-issued cert → okay. Then milestone 2 (dialog routing + keystore + corner cases).

## Milestone 1 COMPLETE — proven live (2026-07-11)

Live against production:
- `/verify` default set → REJECTS a fallback.sandmill.org cert ("not an accepted fallback").
- `/verify` with `accepted_fallbacks:["fallback.sandmill.org"]` → OKAY, email demo-user@example.com, issuer fallback.sandmill.org.

So: independent fallback issuer (own DNSSEC key, TLS) + browserid.me as a stateless verification service enforcing the RP's accepted list + browserid.me not a trusted authority (rejects by default). An RP trusting only fallback.sandmill.org has browserid.me out of its trust chain.

Landed: `BROKER_KEY_SECRET` env, `gen_broker_key` + `fallback_verify_demo` examples, `/verify` `accepted_fallbacks`. Deployed browserid.me (c6a2b7d) + fallback app.

## Remaining — Milestone 2 (pure code, no infra)

Dialog routing: browserid.me's dialog drives verification THROUGH an RP-accepted external fallback (pubkey-in/cert-out; privkey stays in the browserid.me-origin keystore) and stores the returned cert. Multi-issuer keystore. Corner cases (new device, forgot password 2-roundtrips, RP1+RP2 two certs/one password). The external fallback needs a pubkey-in/SMTP-verify/cert-out endpoint (today it's a full broker; the dialog would drive its account/verify flow or a dedicated issuance endpoint).

## Milestone 2 part 1 DONE — fallback implements the primary-IdP interface (SMTP auth)

Per vthunder's design: the fallback IS a primary IdP, differing only in that it vouches for emails whose domain it doesn't own (SMTP-gated). Built into browser-broker (any deployment can be a fallback):

- `/auth` + `/auth.js` (interactive SMTP): `/auth/send` emails a one-time code, `/auth/verify` sets a **30-day signed email cookie** (broker-key-signed {email,exp}; no account/password).
- `/provision` + `/provision.js` (ported from mingo): dialog-driven `beginProvisioning → genKeyPair → POST /cert_key → registerCertificate`. The dialog holds the keypair; the fallback only sees the pubkey.
- `/cert_key` (primary-style, cookie-gated): issues a **24h** cert (iss=broker domain, principal=verified email). 401 without the cookie → dialog drops to `/auth`.
- `/whoami` probe. `/provision` exempt from frame-denial (framed cross-origin by the mediator).
- Design: 24h cert + 30d cookie ride browserid's silent refresh — fresh certs mint against the cookie until it expires, then the SMTP dance repeats. No long certs needed (vthunder).

Tested: fallback_idp_test (send→verify→cookie→cert, email-binding, 401 without cookie). Workspace 368 green. Deployed to fallback.sandmill.org (+ browserid.me, same code).

## Milestone 2 part 2 REMAINING — dialog routing (needs live + real inbox to test)

When an email has no primary AND the RP accepts an external fallback F (not this broker), the dialog must treat F as the primary IdP: fetch F's `.well-known` (auth/provision paths), run the primary provisioning flow pointed at F, store the cert, return the RP assertion. Intricate because it threads through the existing primary machinery (handlePrimaryIdP / redirectToPrimaryAuth / handleAuthReturn / retryProvisioningAfterAuth) which is primary-specific and does a `/wsapi/auth_with_assertion` browser-account step a fallback cert won't pass. Needs:
- route no-primary+accepted-external-fallback through a fallback-aware primary flow (skip/adapt the browser-account step; use F's URLs; re-fetch-addressInfo retry path must know it's fallback F, not re-derive from the email domain).
- keystore: cert keyed by (email, issuer); reuse gated by acceptedFallbacks (partly done in 8t8h).
- Corner cases (new device, forgot password 2-roundtrips, RP1+RP2 two certs/one password), silent-refresh via comm-iframe.
Best done interactively with a real inbox to complete the SMTP dance and observe the popup/return flow.

## COMPLETE — full flow + edge cases proven live (2026-07-11)

Milestone 2 edge cases verified in a real browser (vthunder):
- A: re-visit fallback-demo → instant reuse of the fallback.sandmill.org cert (no re-SMTP).
- B: broker-demo (trusts browserid.me) with the same email → browserid.me's own flow → browserid.me cert (different issuer per RP).
- C: back to fallback-demo → still instantly reuses the fallback cert; both certs coexist (issuer-keyed keystore).

The whole apgv thesis is proven: an RP can trust ONLY an external SMTP fallback (fallback.sandmill.org) and log a user in, with browserid.me acting solely as mediator + stateless verification service — never vouching for the identity. The fallback implements the primary-IdP interface (SMTP /auth → 30d cookie; /provision + cookie-gated /cert_key → 24h cert). One email holds coexisting certs from different issuers, each reused at the RPs that accept it.

Shipped: BROKER_KEY_SECRET env, gen_broker_key + fallback_verify_demo examples, /verify accepted_fallbacks, the fallback-IdP surface (/auth,/provision,/whoami,/cert_key + pages), dialog external-fallback routing, issuer-keyed keystore, /fallback-demo + /broker-demo RPs. Deployed: browserid.me + fallback.sandmill.org (new dokku app, own DNSSEC _browserid key).

Not explicitly exercised (standard browserid machinery, would need a 24h wait or forced expiry): the silent re-provision of an expired 24h cert against the still-valid 30d cookie. Follow-ups if desired: browserid.me-account persistence of fallback identities (roster/cross-device), and the multi-fallback batch/UX polish.
