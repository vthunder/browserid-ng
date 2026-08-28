---
# browserid-ng-d0xb
title: 'Fallback-IdP as a standalone API: native wallets drive secondary-identity issuance without the dialog'
status: in-progress
type: feature
priority: normal
created_at: 2026-08-27T11:04:49Z
updated_at: 2026-08-28T19:35:49Z
blocked_by:
    - browserid-ng-bw9q
---

Third design thread from the menubar-wallet prototype (with gxi9 and bw9q): a native wallet holding a SECONDARY identity currently has no sanctioned API — the prototype drives the dialog's own wsapi calls (authenticate_user, stage/complete_signin_code, /device/issue) with a cookie session, which is undocumented, cookie-bound, and effectively reverse-engineered.

Define how the broker's fallback-IdP role is consumed standalone: what the issuance API is (email verification ceremony, authentication, device+config cert issuance), how it can be done safely from a native app (password/phishing surface, rate limits, no weakening of the mint-authorization chokepoint), and how it composes with the bw9q auth mechanism — per Dan, this is downstream of bw9q: the fallback IdP is probably a subset of the same well-specified API family, sharing the presentation→bearer-token auth once bootstrapped (the chicken-and-egg is only the FIRST issuance, which necessarily rests on the email-verification ceremony).

Same spec-quality bar as bw9q: implementable independently from the spec. See docs/plans/2026-08-28-native-wallet-design-handoff.md.

**Scope note from registry-api-v1 review (2026-08-28):** the registry spec's §5.5 defines the /.well-known/browserid-registry discovery document with a reserved `browser` object — this spec defines its keys: the browser-ceremony URLs a native wallet opens for what it cannot (or should not) do natively — account creation / email verification, password set/reset, account cancel/recovery. Walk the native-wallet account lifecycle end to end (create account, sign in, forgotten password, recovery) and decide per step: native API, browser handoff (discovered via meta), or out of scope. Primaries don't need this — they discover their IdP's ceremony surface via DNS/address_info; only the broker-as-fallback-IdP does.

**Per-scope re-review gate from registry-api-v1 (2026-08-28):** the token exchange accepts self-issued (broker-rooted secondary) presentations for the `registry` scope, justified because that scope excludes all root ops. When this spec adds scopes to the same token family (issuance, account ceremonies), each MUST re-justify self-issued acceptance individually — a self-issued presentation must never reach the mint-authorization chokepoint or password/email root ops just because it can reach the inbox. The password remains the root credential for secondaries; derived credentials must not mint root control.

## Work plan (started 2026-08-27)

- [x] Recon (2026-08-27): exact wire shapes of the current secondary-issuance surfaces (dialog cookie lane: authenticate_user / stage+complete_signin_code / browser_holder / device/issue; fallback-IdP lane: /auth/send / /auth/verify / /auth/device_cert), password lifecycle + recovery endpoints, existing rate limits, address_info
- [x] Walk the native-wallet account lifecycle (2026-08-27; per-step lane decisions drafted into the skeleton §5) end to end; per step decide native API / browser handoff (registry §5.5 `browser` keys) / out of scope
- [x] Spec skeleton (2026-08-27): docs/specs/fallback-idp-api-v1.md — auth model (composition with registry-api-v1 token family + the first-issuance email ceremony), endpoint inventory with legacy mapping, `browser` discovery keys, error taxonomy, invariants, open questions
- [ ] Dan reviews skeleton; resolve open questions (decision log in spec)
- [ ] Flesh out: wire examples, machine reasons, normative grammars
- [ ] Adversarial review pass (fresh-eyes agent), fix findings
- [ ] Per-scope self-issued re-review gate: justify (or refuse) self-issued presentations for EVERY new scope this spec adds

## Direction change (Dan, 2026-08-28): fallback-as-primary

Skeleton redrafted twice on review: (1) issuance bar corrected to password + durable verified flag (/device/issue parity, not the two-lane union). (2) Dan chose option (a) — no credential ever crosses a native API — plus 'treat the fallback as a primary': address_info advertises device_auth/access_mint for secondaries, the broker mounts a device-authorize page implementing the standard fragment/return contract (made normative), and the wallet keeps ONE bootstrap flow with a single skip-the-join branch. All native password/code endpoints (stage/complete/email send+verify/issue, email_proof) deleted from the spec. Headless secondary issuance deliberately not offered (agent lane covers scripted clients). New sibling bean uboq: time-expire SMTP verification (issuer policy §3.4). Open: holder continuity param (absorbs kmvm), max-age window, config-cert identity set, page mount.

## Review rulings round 2 (Dan, 2026-08-28)

- Spec cleaned of draft archaeology (meta-commentary lives here, not in the doc).
- address_info DROPPED from the native contract: native clients run core §3 discovery themselves and CHOOSE their fallback (client configuration = the escape hatch); the endpoint stays web-dialog-only. Support document already carries device_authorization (core discovery.rs:55) — the broker just has to advertise it for its own fallback role (+ access_mint).
- Holder: same as the primary lane — issuer-assigned fresh holder bound to the fragment keys, never derived from the ceremony page's browser session (the wallet must not show up as a web device). No client-supplied holder param; kmvm stays independent.
- Registration reframed as a first-class, client-configured relationship with the registry, distinct from issuance: token exchange (or session join) with the new certs; issuer==registry is the redundant case (issuance already recorded), and the lanes' self-issued rules make that composition safe by construction. Registry choice surfaced at wallet setup; default preserves current UX.
- Remaining open: verification max-age window; config-cert identity set; page mount (new route vs broker-as-own-tenant on the hosted-IdP machinery).

## Review rulings round 3 (Dan, 2026-08-28)

- Verification max-age: issuer policy, NOT in the spec; browserid.me implements 90 days (uboq).
- Old open Q3 (page mount) dropped from the spec — implementation detail, decide at build time.
- Spec gained a §1 model section: four parties (RP / wallet / IdP / registry), independently chosen, identical APIs regardless of operator. RP acceptance of fallbacks (core §8.1) is part of the model.
- Registration is ALWAYS wallet-driven, even when issuer == registry: token exchange + a new POST /api/v1/devices/register (idempotent upsert; to add to registry-api-v1 §5.3 during flesh-out — the token exchange records nothing today). Issuer-side recording demoted to an internal convenience nothing may rely on.
- New bean u6jq: the native wallet lane drops the RP's acceptedFallbacks (extension does not forward them to the localhost bridge).
- Remaining open: config-cert identity coverage (exact address vs local+*@domain sub-address wildcard).
