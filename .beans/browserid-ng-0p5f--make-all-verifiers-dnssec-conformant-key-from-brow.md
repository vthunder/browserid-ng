---
# browserid-ng-0p5f
title: Make all verifiers DNSSEC-conformant (key from _browserid record, support host=, never .well-known keys)
status: in-progress
type: feature
priority: high
created_at: 2026-08-09T15:05:49Z
updated_at: 2026-08-09T15:05:49Z
parent: browserid-ng-g5qt
---

Hosted tenants publish their key ONLY in the DNSSEC _browserid record (+ host= for endpoints) and serve no key at .well-known. Any verifier that reads the issuer key from .well-known over HTTP breaks on tenant presentations (and is a spec violation — DNSSEC is the sole root of trust; .well-known never carries a key).

## Confirmed failure (2026-08-09)
danmills@sandmill.org (now a hosted tenant: DNS has tenant key EzZwk1X_ + host=idp.browserid.me) signs into mingo.place. mingo's verifier (mingo-idp/src/verify.rs) resolves the key via browserid-core discover()+HttpFetcher → fetches sandmill.org/.well-known (still self-serves the OLD key 5T9Vg…) → verifies tenant-signed certs against the old key → "Signature verification failed."

## Plan (DNSSEC-only, one pass)
- [ ] Extract a shared `browserid-dnssec` crate: move broker dns_fetcher.rs; add a DnssecDiscoverer that resolves {key, host, endpoints} from _browserid (key ALWAYS from the DNSSEC record; .well-known fetched at host= for endpoints only).
- [ ] Rewire browserid-broker to consume it (behavior identical; fallback_fetcher uses the shared fetcher).
- [ ] browserid-rp: DNSSEC-only trust — resolve every issuer key from the _browserid record + host=; drop the .well-known-key path (closes audit kh0j/H2). Keep an explicit offline pin escape hatch only if needed.
- [ ] mingo mingo-idp/src/verify.rs: resolve the issuer key via DNSSEC (shared crate), not HttpFetcher .well-known. Bump mingo's browserid-ng git pins.
- [ ] Tests across broker + rp; build mingo.
- [ ] Deploy broker + mingo; verify sandmill.org → mingo login end to end.

## Deferred (separate bean)
On-chain / SBO verifier conformance — file after the above.
