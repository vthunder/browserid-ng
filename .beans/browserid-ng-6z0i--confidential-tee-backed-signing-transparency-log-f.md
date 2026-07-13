---
# browserid-ng-6z0i
title: Confidential (TEE-backed) signing + transparency log for server-side assertions
status: draft
type: feature
priority: low
created_at: 2026-07-13T16:40:06Z
updated_at: 2026-07-13T16:40:06Z
---

Roadmap exploration (not committed). Came out of the FedCM discussion (see [[fedcm-idp-support-spike]]), but is independent of FedCM.

## Idea
Hold the IdP/assertion signing key inside a TEE (SGX / SEV-SNP / TDX / AWS Nitro Enclave) so that:
1. **Keys are unstealable** — the signing key never exists in operator-readable memory; a server breach yields nothing.
2. **Signing is accountable** — the enclave enforces that every signature is appended to an external append-only **transparency log** (Certificate-Transparency-style) before release, and attests that policy. Flips the property from "operator can silently forge" to "operator can only forge *auditably* — every forgery leaves a public, tamper-evident trace."

## What it does NOT achieve (important, decided in discussion)
A TEE canNOT make a **fallback** identity unforgeable. The operator controls the identity-establishment channel (email verification travels through operator SMTP infra), which sits *below* the cookie/TEE layer — so the operator can always mint a fresh legitimate session and drive the enclave to sign. Liveness cannot be guaranteed from the `(cookie, rp)` inputs a FedCM `/fedcm/assertion` request carries: the browser sends no unforgeable presence proof; the cookie is a bearer token; DBSC stops third-party replay but not the issuer (re-enrolls via email); a per-request user key (WebAuthn) would work but requires client-side crypto = a popup, not the silent lane. So the honest framing is **accountability + key protection, not forgery prevention.**

## Strongest fit: confidential IdP *hosting* for primaries
Where a TEE most pays off is hosting **primary** IdPs: a domain delegates its DNSSEC-rooted signing key to a TEE-backed service. Root of trust is DNS (not operator email), the enclave holds the key without exfiltration, the domain pins the enclave's attested policy, and the transparency log makes any sign visible. Marketable story: "your hosting provider can't steal your key and can't sign for you without it showing in your log."

## Applies to
- The FedCM silent (server-signed) lane, if adopted — TEE + log makes the server-side minting auditable and the key unstealable.
- Hosted-primary signing (the strongest case).

## Open questions
- TEE platform choice (Nitro is easiest ops; SEV-SNP/TDX for confidential VMs; SGX deprecating).
- Transparency log design (own log vs piggyback on an existing CT-style log; inclusion proofs to RPs?).
- Attestation surface: how do RPs/domains verify the enclave measurement + policy.
- Interaction with the assertion format (does the log entry hash the cert~assertion?).

Complements [[passkey-graduation-fallback-identities]], which raises the trust *floor* rather than adding accountability on top.
