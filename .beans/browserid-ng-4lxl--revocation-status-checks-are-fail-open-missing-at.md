---
# browserid-ng-4lxl
title: Revocation status checks are fail-open / missing at broker, spec says fail-closed (B2)
status: completed
type: bug
priority: high
created_at: 2026-07-23T21:40:54Z
updated_at: 2026-07-23T22:49:57Z
---

Spec §6.4 (protocol.md:408-412) requires all three status checks (access cert, config cert, warrant) fail-closed, and claims (protocol.md:372-376) the broker checks its own credentials authoritatively at /verify. Reality: broker /verify-access checks NONE of the three refs (verifier.rs:135-137 'Revocation is therefore not yet enforced'; verify_access_with_dns never touches them), and browserid-rp defaults fail-open (StatusCache::new fail_closed:false lib.rs:483-492; Unknown passes unless opted in lib.rs:242-247).

Decide: flip reference defaults to fail-closed + implement broker checking (spec-compliant), or downgrade the spec MUST to a policy knob and mark broker enforcement planned. Recommendation: spec is right — revocation is the model's backbone; implement.

From docs/plans/2026-07-23-spec-code-divergence-audit.md (B2).

## Summary of Changes

Fail-closed revocation is now enforced end to end (spec §6.4):

- **browserid-rp**: StatusCache defaults to fail-closed (explicit .fail_open() opt-out); a Verifier with NO status cache now rejects any presentation carrying a status ref unless .without_status_checks() explicitly opts out; new async Verifier::refresh_status(uri) fetches a list, verifies it against the trusted-issuer table (list iss must be trusted), and caches it. New tests cover both defaults.
- **browserid-broker**: verify_access_with_dns takes a StatusCtx and checks all three status refs (access cert, config cert, warrant) fail-closed after the cryptographic join. Own-list refs are checked authoritatively against the local store; foreign refs are fetched (5s timeout), bound to their authority (list iss MUST be the URI's host, signature verified under that domain's DNSSEC-discovered key, sub must match the URI, freshness enforced), and cached in AppState.foreign_status_lists. Unreachable/stale/unverifiable → reject. All three call sites wired (POST /verify-access, /wsapi/auth_with_presentation, guestbook sign); the guestbook's inline own-list check is replaced by the centralized one.
- **browserid-core**: status.rs module docs corrected (fail-closed is required, fail-open is a non-conformant opt-out).
- Tests: 5 new broker tests (own revoked, own store error, unreachable foreign, foreign revoked/clear via live HTTP list server, non-authoritative signer) + 2 new rp tests. Full workspace suite green. E2e suite run before/after: identical failure sets (35 pre-existing local failures on clean main, unrelated), zero regressions.

Deployment note: federated primary IdPs that allocate status refs MUST now actually publish their status list — creds carrying refs to an unreachable list are rejected (that is the point).
