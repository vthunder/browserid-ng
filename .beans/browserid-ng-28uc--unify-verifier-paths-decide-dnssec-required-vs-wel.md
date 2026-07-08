---
# browserid-ng-28uc
title: Unify verifier paths / decide DNSSEC-required vs .well-known primary support
status: todo
type: task
priority: high
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-08T18:24:31Z
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
