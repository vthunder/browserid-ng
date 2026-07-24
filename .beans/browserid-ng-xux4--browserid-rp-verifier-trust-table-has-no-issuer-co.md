---
# browserid-ng-xux4
title: browserid-rp Verifier trust table has no issuer conformance — any trusted key vouches for any identity
status: completed
type: bug
priority: high
created_at: 2026-07-24T13:24:35Z
updated_at: 2026-07-24T13:27:26Z
---

The RP library's Verifier.issuer_keys is a flat domain->key map consumed by the core verify closure. Nothing checks the issuer is AUTHORITATIVE for the identity's domain (spec §6.2/§8 conformance: a primary vouches only for its own domain; a fallback only for no-primary domains). Consequence: an RP that pins/fetches a primary IdP's key (e.g. sandmill.org) implicitly lets that key mint identities at ANY domain (alice@gmail.com). The hosted broker verifier does the conformance check (verifier.rs); browserid-rp never did. Found live wiring TRUSTED_IDPS into the bsky bridge (browserid-bsky).

Fix: distinguish trust_primary (authoritative for exactly its domain) from trust_issuer/fallback; after core verify, enforce per-identity conformance on BOTH ends of the grant: (grantor, config-cert issuer) and (grantee, access-cert issuer) — a primary never vouches off-domain, and a domain with a declared primary accepts no fallback.

## Summary of Changes

browserid-rp Verifier now distinguishes trust classes: trust_primary(domain,key) / trust_primary_from_well_known() mark an issuer authoritative for exactly its own domain; trust_issuer() keeps fallback semantics. After core verify, issuer conformance is enforced per identity on both ends of the grant — (grantor, config-cert issuer) and (grantee, access-cert issuer): a primary never vouches off-domain, and a domain with a declared primary accepts no fallback. Tests: primary_vouches_only_for_its_own_domain, declared_primary_domain_rejects_fallback_vouching. Found live via the bsky bridge (TRUSTED_IDPS wiring).
