---
# browserid-ng-m95b
title: 'Hosted IdP without DNSSEC: fallback-signed tenants (managed by browserid.me)'
status: todo
type: feature
created_at: 2026-08-11T22:02:44Z
updated_at: 2026-08-11T22:02:44Z
---

Domains that want the hosted-IdP org features but cannot enable DNSSEC on their zone should still get the full /domains management surface. Flow: verify domain control WITHOUT DNSSEC (e.g. a plain TXT challenge — no _browserid trust-root record), then unlock the same tenant console — roster, admins, managed identities, policy, revoke-all, delete — ideally 100% feature parity. Under the hood the broker signs these tenants' certs as the FALLBACK (iss: browserid.me) instead of as the tenant domain, exactly like ordinary secondary identities; the org-side controls (roster gating, managed-identity policy, TTL bounds, revocation) apply at the broker's own issuance path. Users of such a domain see 'managed by browserid.me' instead of the domain being its own issuer. Verifier is untouched (certs are ordinary fallback certs). Notes: needs a tenant flag (dnssec_rooted vs fallback_signed); claim/issuance routing must consult the roster + policy for fallback-signed tenant domains even though the domain has no _browserid record; upgrade path when a tenant later enables DNSSEC should be seamless (same console, flip the signing root).
