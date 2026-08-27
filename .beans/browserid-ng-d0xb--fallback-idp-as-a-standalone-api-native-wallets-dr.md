---
# browserid-ng-d0xb
title: 'Fallback-IdP as a standalone API: native wallets drive secondary-identity issuance without the dialog'
status: draft
type: feature
priority: normal
created_at: 2026-08-27T11:04:49Z
updated_at: 2026-08-27T15:42:11Z
blocked_by:
    - browserid-ng-bw9q
---

Third design thread from the menubar-wallet prototype (with gxi9 and bw9q): a native wallet holding a SECONDARY identity currently has no sanctioned API — the prototype drives the dialog's own wsapi calls (authenticate_user, stage/complete_signin_code, /device/issue) with a cookie session, which is undocumented, cookie-bound, and effectively reverse-engineered.

Define how the broker's fallback-IdP role is consumed standalone: what the issuance API is (email verification ceremony, authentication, device+config cert issuance), how it can be done safely from a native app (password/phishing surface, rate limits, no weakening of the mint-authorization chokepoint), and how it composes with the bw9q auth mechanism — per Dan, this is downstream of bw9q: the fallback IdP is probably a subset of the same well-specified API family, sharing the presentation→bearer-token auth once bootstrapped (the chicken-and-egg is only the FIRST issuance, which necessarily rests on the email-verification ceremony).

Same spec-quality bar as bw9q: implementable independently from the spec. See docs/plans/2026-08-28-native-wallet-design-handoff.md.

**Scope note from registry-api-v1 review (2026-08-28):** the registry spec's §5.5 defines the /.well-known/browserid-registry discovery document with a reserved `browser` object — this spec defines its keys: the browser-ceremony URLs a native wallet opens for what it cannot (or should not) do natively — account creation / email verification, password set/reset, account cancel/recovery. Walk the native-wallet account lifecycle end to end (create account, sign in, forgotten password, recovery) and decide per step: native API, browser handoff (discovered via meta), or out of scope. Primaries don't need this — they discover their IdP's ceremony surface via DNS/address_info; only the broker-as-fallback-IdP does.

**Per-scope re-review gate from registry-api-v1 (2026-08-28):** the token exchange accepts self-issued (broker-rooted secondary) presentations for the `registry` scope, justified because that scope excludes all root ops. When this spec adds scopes to the same token family (issuance, account ceremonies), each MUST re-justify self-issued acceptance individually — a self-issued presentation must never reach the mint-authorization chokepoint or password/email root ops just because it can reach the inbox. The password remains the root credential for secondaries; derived credentials must not mint root control.
