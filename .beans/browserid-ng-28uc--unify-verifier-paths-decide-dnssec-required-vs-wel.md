---
# browserid-ng-28uc
title: Unify verifier paths / decide DNSSEC-required vs .well-known primary support
status: in-progress
type: task
priority: high
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-10T09:50:54Z
parent: browserid-ng-8u60
blocked_by:
    - browserid-ng-l7q1
---

/verify and auth_with_assertion call verify_assertion_with_dns, which ONLY recognizes DNS-based primaries. A Persona primary publishing .well-known/browserid with an authority delegation but no _browserid DNS record is rejected. The fuller verify_assertion (supports .well-known primaries + delegation via discovery::discover) is dead code, unreachable from any route.

DECISION NEEDED (owner unsure):
- [ ] Option A: make DNSSEC discovery REQUIRED — deprecate the .well-known primary + delegation path, delete dead verify_assertion, document that primaries must publish a DNSSEC-signed _browserid record. Depends on the DNSSEC-auth fix landing first.
- [ ] Option B: keep .well-known/delegation as supported — wire delegation into the DNS path so both work through /verify.
- [ ] Investigate whether any real scenario needs .well-known-only primaries before committing.

## Note: DNSSEC trust model after the l7q1 fix (2026-07-08)

The l7q1 fix made discovery use DNS-over-TLS to Google Public DNS (8.8.8.8:853, cert dns.google) and trust its AD flag. We do NOT validate DNSSEC locally - the RRSIG chain-to-root validation is outsourced to the authenticated resolver. Google is therefore in the TCB: a malicious/compelled resolver could assert AD=1 for a forged record, or strip AD to force broker fallback.

If the decision here is Option A (DNSSEC required), primaries hinge entirely on this trust, so we should revisit and consider removing Google from the TCB: upgrade to hickory 0.25+ and validate locally against the root trust anchor (0.25's Proof API distinguishes Secure/Insecure/Bogus/Indeterminate per record - hickory 0.24 cannot, which is why l7q1 went with DoT). DoT would then remain only as transport privacy.

## DECISION (2026-07-10): DNSSEC required — the sole trust path

Go all-in: an authenticated `_browserid` DNSSEC record (RFC 9102, DoT, AD flag, SERVFAIL→reject) is the REQUIRED and ONLY trust root for a primary IdP's identity key. Remove `.well-known/browserid` as a key-trust / discovery path — no dual path, no downgrade (accepting either = security of the weaker link).

Rationale: closes the downgrade; gives offline/on-chain-provable discovery (RFC 9102 artifacts, no live fetch); single owner-controlled trust root vs the entire WebPKI/CA surface; unifies the verifier (this bean's original goal). Long tail is unaffected — domains/users without DNSSEC go through the browserid.me broker, which itself publishes DNSSEC.

Open sub-items to resolve during implementation:
- **Endpoint discovery.** With well-known removed as trust, auth/provision endpoint URLs still need a source: convention (default /auth, /provision) or carried in the DNS record. (Endpoints don't need DNSSEC-grade trust since responses are key-verified — a forged endpoint can't mint a valid cert — but they need SOME discovery.) Decide.
- **Key-rotation tooling.** DNSSEC couples key rotation to DNS updates (we hit the browserid.me key↔DNS drift this session). Build rotation + proof-refresh tooling. Relates to egr7.
- Canonize in the spec (v9rz); resolves divergence 'C' (discovery.rs:3 stale well-known-only doc-comment).

## Refinement under discussion (2026-07-10)

The 'remove .well-known' wording above is too strong. Revised direction (pending confirmation):
- DNSSEC `_browserid` key stays the SOLE ROOT OF TRUST (no WebPKI-only key trust, no downgrade).
- `.well-known/browserid` is RETAINED for endpoint discovery (auth/provision URLs) — we do NOT force endpoints into DNS. Its trust is re-anchored: whatever it serves must chain to the DNSSEC key.
- Reconsidering HOST CERTIFICATES (reverse the silent email-only narrowing, divergence 'A'): keep them, but require a host cert to be SIGNED BY THE DNSSEC KEY (not self-signed + well-known-trusted like old browserid). Chain: DNSSEC key → host cert → user cert, all Ed25519, offline-verifiable via the RFC 9102 proof. Enables (a) DNS-admin ≠ host/IdP-operator separation, (b) operational key rotation WITHOUT a DNS change (new host cert vs DNS propagation — mitigates the key↔DNS drift footgun we hit), while keeping browserid-like well-known flows. Still single-rooted in DNSSEC → no downgrade.

## FINAL decision (2026-07-10) — supersedes the framing above

- ROOT OF TRUST: authenticated DNSSEC `_browserid` key (K_dns) — REQUIRED, sole root, offline-provable (RFC 9102, DoT, AD flag, SERVFAIL→reject). No WebPKI-only key trust; no dual-path downgrade.
- HOST CERT (OPTIONAL): { host key K_host } signed by K_dns, asserting K_host is authoritative for the domain. Reinstates old browserid's host principal (divergence 'A') but DNSSEC-signed instead of self-signed/well-known-trusted. Enables DNS-admin ≠ host/IdP-operator separation, and operational key rotation without a DNS change (rotate K_host via a new host cert; K_dns stays cold — mitigates the key↔DNS drift footgun). NO endpoints in the cert (keep them operationally movable).
- USER CERTS: email principal, signed by K_host (if a host cert is used) or directly by K_dns.
- .WELL-KNOWN: RETAINED for endpoint discovery (auth/provision URLs live here) and to deliver the optional host cert. NOT a trust root — anything it serves chains to K_dns. Endpoint integrity leans on HTTPS, which is fine: a forged endpoint can't mint valid creds (responses must chain to K_dns); worst case is a phishing/DoS UI surface.
- VERIFICATION (offline): user cert ← K_host ← host cert ← K_dns ← DNSSEC proof, OR user cert ← K_dns directly.

Resolves divergence 'A': reinstate host certs (DNSSEC-signed); do NOT keep the email-only narrowing.

Implementation scope: require DNSSEC + sole root; add OPTIONAL DNSSEC-signed host-cert verification; keep .well-known for endpoints; unify the verifier around the single DNSSEC-rooted chain. Canonize in v9rz. Follow-up: key-rotation tooling (egr7-adjacent).

## Phase 1 IMPLEMENTED (2026-07-10) — branch feat/dnssec-required (85021d2, off fix/discovery-cleanup, unmerged)
Unified the verifier to a single DNSSEC-rooted path. Removed the dead sync verify path (no production caller). Key resolved ONLY from the authenticated _browserid DNSSEC record (Secure+record; Bogus->reject; Insecure/NXDOMAIN->broker); .well-known fetched for ENDPOINTS only, key overridden with the DNSSEC one. Also closed the BROKER-fallback downgrade: broker key now DNSSEC-resolved too (a non-DNSSEC broker is a hard error). New Discoverer trait (RPITIT) makes the verifier unit-testable with a mock. Tests green: verifier_test 14/14 incl downgrade-closure + bogus-rejection; core/broker/rp suites pass.
Production impact (intentional): all active primaries publish DNSSEC (mingo.place ok, sandmill.org has record+RRSIG - CONFIRM AD=true before deploy; browserid.me ok). Broker now MUST have DNSSEC -> any dev/local non-DNSSEC broker (localhost) hard-errors on fallback.
Phase 2 hook (host certs): inserts at the final cert check in verify_signatures_with_doc - if user cert not signed by K_dns directly, verify a K_dns-signed host cert authorizing the signer, then verify user cert against the host key.
Remaining: Phase 2 (optional DNSSEC-signed host certs); C doc-comment fixed as part of Phase 1.
