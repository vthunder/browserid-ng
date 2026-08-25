---
# browserid-ng-wre6
title: 'Security audit: browserid-ng (production, browserid.me)'
status: completed
type: epic
priority: high
created_at: 2026-07-28T23:40:19Z
updated_at: 2026-08-25T19:04:51Z
---

Full adversarial security audit of the browserid-ng identity protocol and hosted broker, treating browserid.me as live production. Six workstreams: (1) verification-core proofs, (2) credential issuance & minting, (3) account lifecycle & auth, (4) network-facing input & DoS, (5) client key custody (SDKs), (6) dependency & secrets hygiene. Each candidate finding is confirmed or refuted by an independent adversarial reviewer (no PoCs required). Deliverables: a written security-audit report (docs/) and one child bean per confirmed finding.

## Candidate leads (from initial recon, to verify/refute)
1. Cross-issuer safety is an unenforced caller precondition; module doc contradicts code (core/device.rs:599-615 vs :15-17)
2. No replay protection on RP path (assertion.rs, rp_auth.rs, mint jti TODO device.rs:278)
3. SSRF via unvalidated status-list URI fetch (verifier.rs:197)
4. 6-digit code brute force, no attempt-limit on wsapi path (account.rs:126, reset.rs:113, email.rs:266)
5. Mailbox-only path to warrant-signing certs (fallback_idp.rs:271-413)
6. FedCM token minting rests on one header check (fedcm.rs:186)
7. identity_matches glob + implicit +tag expansion (core/device.rs:50-76)
8. No session/cert invalidation after password change/reset (auth.rs:168, reset.rs:139)
9. Unbounded status-list cache DoS (verifier.rs:225)
10. No brute-force protection on authenticate_user (auth.rs:37)
Smaller: split('@') parser differential; status ttl no ceiling; malformed-signed DNS downgrade; guestbook escape() misses '; admin/test endpoint posture; CORS mirrors any Origin on /wsapi/*.

## Summary of audit (2026-07-29)

Report: docs/security-audit-2026-07-29.md. 12-agent adversarial workflow (6 workstream finders + 6 skeptics). All 30 candidate findings verified/refuted by reading code (no PoCs).

Result: crypto core is sound (Ed25519-only, no alg agility, fail-closed DNSSEC, parameterized SQL, clean secrets-in-git). Risk concentrated in the broker account-lifecycle + network HTTP surface.
- 1 Critical (C1 codes brute-force), 2 High (H1 SSRF, H2 no session invalidation), 9 Medium (M1-M9), 12 Low (L1-L12 batched).
- Verified NON-issues: FedCM mint gate sufficient, holder isolation holds, config +*@domain redundant, email header injection not reachable, shipped image safe-by-default.

Child beans filed per finding. Remediation order: C1 → H1 → H2 → M4+M3 → M8 → M2/M9 → M1/M5/M6/M7 → lows.

## Remediation pass complete (2026-07-29)
Full broker suite green (31 test binaries, 0 failures); workspace builds clean.

FIXED + tested: C1(0ypr), H1(c5n5), H2(axee), M3(nlj8), M5(dbmy), M8(l7oq) → completed. M4(qtl7) → memory/body DoS fixed, negative-caching a minor follow-up. Lows L2/L4/L7/L8/L12 done (batch v1ia).

DEFERRED for product decision (UX/behavior/infra): M1(7ww7 fallback cert password-gate), M2(6q3u SDK allowAgent semantics), M6(ytjn login rate-limit needs proxy IP), M7(dw35 enumeration vs UX signal), M9(ttn3 SBO signer consent prompts), L1/L5/L9/L11.

Report updated: docs/security-audit-2026-07-29.md (Remediation status section).

## Remediation complete except ttn3 sign-off (2026-08-25)

Every audit finding is now closed: C1/H1/H2/M3/M5/M8 + lows batch part 1 (2026-07-29), M7 two-phase (2026-08-20), M1 (2026-08-19), M2, M6, M9 structurally (ttn3, signing grants — open only for Dan's interactive testing + spec editing pass), M4 fully (qtl7 incl. negative caching, 2026-08-25), and v1ia's remaining lows L1/L3/L5/L6/L9/L10/L11/zeroize (2026-08-25). This bean can complete when ttn3 does.

## Keyless support-document sweep (2026-08-25, Dan-directed, zexp/0p5f lineage)

All five live origins now serve keyless /.well-known/browserid (broker + hosted-idp already did; sandmill PHP, mingo-idp, bsky bridge fixed + deployed + verified). browserid-core's SupportDocument::new() is keyless by construction; the DNSSEC resolver attaches keys via with_discovered_key(); the broker's localhost-only dev exception is now the single place any codebase puts a key on the wire. Consumer sweep found TWO real TLS-key-trusting verifiers, both in the bsky bridge (startup broker-key fetch — surfaced as a deploy panic — and fetch_well_known_key backing four /verify paths); both now resolve via the _browserid DNSSEC record over DoT. Broker discovery pipeline confirmed already DNS-overridden; rp, SDKs, and client JS clean.

## Summary of Changes — audit CLOSED (2026-08-25, Dan's sign-off)

All 24 findings remediated, deployed, and verified: C1 + H1 + H2 + M3/M5/M8 + five lows in the 2026-07-29 pass; M7 in two phases (2026-08-20); M1 mint chokepoint (2026-08-19); M2 allowAgent removal; M6 rate limiting; M4 fully incl. negative caching (2026-08-25); the lows batch L1/L3/L5/L6/L9/L10/L11 + zeroize (2026-08-25); and M9 structurally via signing grants — consent-minted revocable records, wallet-side per-sign revocation checks (authoritative, no TTL on the broker origin), daemon submit-gate status checks, end-to-end revoke/re-consent loop verified interactively by Dan. Follow-on hardening the M9 work surfaced (keyless support documents everywhere, DNSSEC-rooted status verification, replay-deterministic clocks) landed the same day. Bean ttn3 stays open only for post-audit signing-grants polish (spec editorial pass), not for any audit finding.
