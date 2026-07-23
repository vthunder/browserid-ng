---
# browserid-ng-exj6
title: Verifier availability — JS/Python/Go verifier libs + hosted /verify
status: todo
type: feature
priority: normal
created_at: 2026-07-10T15:24:41Z
updated_at: 2026-07-23T11:02:42Z
---

GTM: Rust-only verification is a silent adoption ceiling. "Add agent auth" must be five minutes in any stack. Plan: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` (§7).

- Tiny verifier libraries beyond Rust — priority order by RP demand, likely JS/TS first, then Python, Go.
- Hosted `/verify` endpoint as the zero-dependency path.
- Every port bakes in the v3 fail-closed agent handling from day one: reject unrecognized cert `typ`, require warrant-in-chain for agent certs, enforce `aud`, surface scopes; status-list check with cache.
- Sequencing: after spec v0.4 stabilizes chain format (blocked conceptually by 5zdh; start scaffolding earlier if useful).

### Todo
- [~] JS/TS verifier (npm): hosted-verify wrapper shipped (sdk/js); in-process native crypto+DNSSEC port still pending
- [ ] Python verifier
- [ ] Go verifier
- [x] Hosted /verify hardening + docs
- [x] RP quickstart docs per language (JS/Python/Go/curl)

## Progress 2026-07-12

Shipped the zero-dependency hosted-verify path so RPs in any language can verify today:
- sdk/js @browserid/verify — thin fail-closed typed wrapper over hosted /verify (10 unit tests + live check).
- docs/verify-quickstart.md — /verify HTTP contract + JS/Python/Go/curl examples + safety rules (server-side audience pinning, fail-closed, explicit agent policy).
- docs/plans/2026-07-12-native-verifier-libraries-notes.md — algorithm distilled from verifier.rs for the in-process ports.

The hosted /verify endpoint was already complete (DNSSEC-rooted, accepted_fallbacks, agent attribution, status-list revocation, fail-closed) — verified live.

**Remaining (kept open):** native in-process verifiers for JS, Python, Go. These carry DNSSEC validation + Ed25519 and should follow spec v0.4 chain-format stability (5zdh) to avoid rework; the DNSSEC step is the hard part (see notes). Left for review rather than shipping unreviewed security-critical crypto autonomously.
