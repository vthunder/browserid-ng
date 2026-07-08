---
# browserid-ng-l7q1
title: DNSSEC discovery isn't actually authenticated (AD-flag trust over plaintext UDP)
status: completed
type: bug
priority: critical
created_at: 2026-07-08T06:13:39Z
updated_at: 2026-07-08T18:12:01Z
parent: browserid-ng-8u60
---

dns_fetcher.rs sends a plaintext UDP query to 8.8.8.8 and trusts the AD flag. No local RRSIG validation, no authenticated transport. An on-path/UDP-spoofing attacker can set AD=1 and inject a forged _browserid.<domain> TXT record with their own public key -> becomes a DNSSEC-validated primary IdP for ANY domain and mints certs for any email there. Defeats the point of the DNSSEC feature.

Also: Bogus branch (dns_fetcher.rs:128-134) matches error strings like 'dnssec'/'rrsig', but real validation failures come back as SERVFAIL and get misclassified as Insecure -> silent broker fallback. 'Bogus -> reject' isn't real.

- [x] Locally-validating DNSSEC client (verify chain to trust anchor) OR authenticated DoT/DoH to a trusted resolver
- [x] Correctly detect SERVFAIL/bogus and hard-reject instead of fallback
- [x] Tests: forged-AD record rejected; bogus -> reject not fallback

## Summary of Changes

Switched discovery to DNS-over-TLS (RFC 7858) instead of plaintext UDP, and replaced error-string matching with response-code classification:

- `dns_fetcher.rs`: queries now go over TLS (rustls 0.21 + webpki-roots, matching hickory-proto 0.24 pins) to the trusted resolver (default 8.8.8.8:853, cert name dns.google). The AD flag is only trusted because the channel is now authenticated - an on-path attacker can no longer forge AD=1 or inject records.
- SERVFAIL from the validating resolver is now classified as Bogus (RFC 4035 s5.5) -> hard reject via `BrokerError::DnssecValidationFailed`, never silent broker fallback. Other rcodes (Refused etc.) -> Insecure. Transport failures (TLS/timeouts) -> Insecure (downgrade-to-broker only; cannot forge primary).
- Response classification extracted into pure `classify_response()` with unit tests: SERVFAIL->Bogus, AD+record->Secure, no-AD->Insecure, NXDOMAIN with/without AD, Refused->Insecure (not Bogus).
- Integration regression test `test_forged_ad_over_plaintext_is_not_secure`: a plaintext server forging AD=1 can no longer yield Secure (TLS handshake fails -> Insecure).
- API change: `DnsFetcher::with_resolver_addr(addr)` -> `with_resolver(addr, tls_name)`; default port 853.

Residual trust: the configured resolver (Google Public DNS) performs the DNSSEC validation. Local RRSIG validation was considered but hickory 0.24's `AsyncDnssecClient` cannot distinguish Insecure from Bogus (unsigned zones error as `RrsigsNotPresent`, no authenticated denial of existence), so authenticated-channel-to-validating-resolver is the correct fix at this dependency version.

Deploy note: broker hosts must allow outbound TCP 853.
