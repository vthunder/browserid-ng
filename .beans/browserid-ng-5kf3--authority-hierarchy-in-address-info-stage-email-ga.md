---
# browserid-ng-5kf3
title: Authority hierarchy in address_info + stage_email gate
status: completed
type: feature
priority: normal
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T22:31:54Z
parent: browserid-ng-tsqk
---

Broker runs the claim-time hierarchy (_browserid → handle binding → MX → refuse).

- [x] address_info: runs the hierarchy for no-primary domains; response gains `proof` ("smtp"|"atproto"|"none") and `claim` (bridge claim URL) fields
- [x] stage_email refuses non-SMTP-authority domains — and so do stage_user and stage_reset (a mailed reset code on an atproto domain is an account-takeover primitive)
- [x] Step 2 is a RESOLVED binding: delegated to the bridge GET /idp/resolve (existing resolve.rs machinery, both methods, DNS wins, bidirectional check)
- [x] Step 1 unchanged: existing DNSSEC-validated primary discovery (fallback_fetcher) runs before the new steps
- [x] Cached: AuthorityChecker caches per-domain answers 600s (both positive and negative); bridge probe timeout-bounded at 10s; both probes fail open on transport errors
- [x] Pre-flight (run 2026-07-30): CLEAR — no prod domain resolves as a handle.

| domain | handle? | MX | _browserid | hierarchy lands on |
|---|---|---|---|---|
| bsky.browserid.me | no | no | yes | 1 (primary — existing D identities untouched) |
| mingo.place | no | yes | yes | 1 (primary) |
| sandmill.org | no | yes | yes | 1 (primary) |
| example.com | no | NULL MX (RFC 7505) | no | 4 (refuse — correct: mail there never delivered; verified identities unaffected) |
| gmail.com | no | yes | no | 3 (SMTP, unchanged) |

Zero identities change proof method. NOTE: this is a snapshot, not a guarantee — re-run immediately before shipping the gate. If a hit ever appears, the fix is a one-time backfill of the proof method onto pre-existing identities (a grandfather clause, NOT general pinning, so it does not contradict the no-pinning rule).

## Pre-flight re-run 2026-07-31 (before shipping the gate)

Still clear: no verified prod domain resolves as a handle (checked _atproto TXT + /.well-known/atproto-did for all five). Correction to the 07-30 table: example.com publishes a NULL MX (`0 .`), not a usable MX — under the gate it is Unprovable. Prod impact none (staging @example.com never delivered mail anyway; existing verified identities do not re-stage). Dev/e2e impact avoided by defaulting MX_GATE off when DISABLE_SMTP is set.

## Summary of Changes

- `browserid-broker/src/authority.rs` (new): `AuthorityChecker` runs hierarchy steps 2–4 for no-primary domains with injectable probes (`HandleProbe::{Bridge,Static,Disabled}`, `MxProbe::{Dns,Static,Off}`), 600s per-domain cache, localhost skip, fail-open-on-transport semantics.
- `dns_fetcher.rs`: new `lookup_mx` over the existing DoT channel; null MX (RFC 7505) reads as no-mail; resolver failure is an error (caller fails open), never a silent false.
- `routes/email.rs`: `address_info` reports `proof`/`claim`; shared `require_smtp_authority` gate applied in `stage_email`, `stage_user` (account.rs), `stage_reset` (reset.rs). New errors `DomainProvenByAtproto`/`DomainUnprovable` (403).
- `main.rs`: probes on by default; `ATPROTO_BRIDGE_URL=""` disables the atproto lane; MX gate defaults OFF when `DISABLE_SMTP` is set (dev/e2e), else on; `MX_GATE=0` overrides.
- Tests: unit tests in authority.rs + dns_fetcher.rs; integration `tests/authority_hierarchy_test.rs` (proof lanes in address_info, all three stage gates). Full broker+core suite green.
- Pre-flight re-run 2026-07-31 before shipping: clear (see section above; example.com null-MX correction).
