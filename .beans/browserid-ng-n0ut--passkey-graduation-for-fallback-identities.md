---
# browserid-ng-n0ut
title: Passkey graduation for fallback identities
status: draft
type: feature
priority: low
created_at: 2026-07-13T16:40:27Z
updated_at: 2026-07-13T16:40:27Z
---

Roadmap exploration (not committed). Came out of the FedCM discussion (see [[fedcm-idp-support-spike]]).

## Problem
A **fallback** identity (browserid.me vouches because the email domain has no `_browserid`) is intrinsically **operator-forgeable**: the operator controls the email-verification channel that IS the identity proof, so it can always mint a legitimate session for any fallback email. No amount of TEE/cookie hardening rises above that ceiling (see [[confidential-tee-backed-signing-transparency-log-f]]).

## Idea — raise the trust FLOOR, not just add accountability
Let a fallback user **graduate to a user-held key**: after the first successful email verification, enroll a **passkey (WebAuthn)** bound to the account. Thereafter require the passkey to mint assertions. This converts an operator-forgeable fallback into a **user-key-rooted identity the operator cannot forge** without the user's authenticator — the actual fix for the root problem, not a mitigation.

## Tradeoffs
- Cost is a WebAuthn ceremony (platform UI) — so it is NOT the silent lane. It slots naturally into FedCM's **Continuation API** popup (first-party browserid.me page runs the WebAuthn + keystore signing, then `IdentityProvider.resolve(token)`), or into the existing popup dialog.
- Recovery: losing the passkey must fall back to email re-verification (which reopens operator-forgeability for the recovery window) — acceptable and normal, but must be designed (multiple passkeys, recovery codes?).
- Progressive: keep email-only fallback for users who don't enroll; passkey is an opt-in/nudged upgrade.

## Why it's higher-value than the TEE for fallbacks
TEE = accountability on top of an unfixable root. Passkey-graduation = removes the root weakness for users who enroll. Complementary, but this is the one that actually makes a fallback unforgeable.

## Open questions
- Enrollment UX: auto-prompt after first verification, or nudge later? How much friction is acceptable for a "just sign in with your email" product?
- Does a graduated identity change how the assertion/cert is issued (does the passkey sign the assertion directly, or gate the keystore ephemeral key)?
- Interaction with agent delegation (agents act for a human — does a graduated human change warrant issuance?).
- Cross-device / multi-passkey story.
