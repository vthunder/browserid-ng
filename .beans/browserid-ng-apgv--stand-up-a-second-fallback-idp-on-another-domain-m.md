---
# browserid-ng-apgv
title: RP-chosen external SMTP fallback — browserid.me routes to it, no trust on browserid.me
status: todo
type: feature
priority: normal
created_at: 2026-07-11T16:08:54Z
updated_at: 2026-07-11T16:08:54Z
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
