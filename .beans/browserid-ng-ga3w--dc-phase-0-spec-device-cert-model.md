---
# browserid-ng-ga3w
title: DC Phase 0 — Spec (device-cert model)
status: todo
type: task
priority: high
created_at: 2026-07-18T19:40:58Z
updated_at: 2026-07-23T21:40:37Z
parent: browserid-ng-oup3
---

Rewrite protocol + agent-provisioning specs to match the built device-cert model: purpose x HOLDER axes (opaque broker-assigned holder + HolderMatcher, replacing subject:user|agent), warrants as (grantor, grantee, holder-matcher) -> audience [+scopes] (replacing identifier/subject), device-cert issuance API, access-request + access-cert mint API, revocation links, config certs, mandatory conformance, always-warrant RP presentation. The grantor/grantee (on-behalf delegation) split is a NEW capability needing a fresh spec section, not a rename. Fold in Q5/Q8. See docs/plans/2026-07-18-device-cert-model-migration-plan.md.

## Work list from the 2026-07-23 divergence audit

Full audit: docs/plans/2026-07-23-spec-code-divergence-audit.md (Groups A, D, E are spec-side; B1/B2/B3 code-side gaps have their own beans).

- [ ] Group A: replace every subject/identifier mention in both specs with holder/grantor/grantee (protocol.md §4, §4.1-4.3, §5, §6.1-6.2; api.md §1-§7 — line refs in audit doc)
- [ ] New section: grantor vs grantee delegated/on-behalf grants + attribution semantics (VerifiedAccess email/grantee/issuer/grantee_issuer)
- [ ] B1 spec side: rewrite config-cert issuer-binding sections (protocol.md §4.3, §6.2 step 2, §8, §9; api.md §3, §5.3, §8) around grantor-attribution as the security guard (cross-issuer allowed per yhcx)
- [ ] D1: §3.1 support-document fields (access-cert, device-cert, device-authorization, agent-device-authorization; drop mint/authority or mark planned)
- [ ] D2: /verify -> /verify-access, response shape {status,email,holder,scopes,issuer,reason}; decide whether response should surface grantee/grantee_issuer
- [ ] D3: token response holder field (rp_auth.rs)
- [ ] D4: document the 'login' scope sentinel semantics
- [ ] D5: consent request/poll wire shapes (plain JSON not JWS; cap 1-10; verification_uri_complete; warrant~config_cert pairs; error-shape divergences)
- [ ] D6: author the missing external-service consent section (the code's phantom "§6.6")
- [ ] D7: spec the holder-namespace / device management surfaces (or explicitly scope them out)
- [ ] E: add planned/in-sbo caveat to §6.3 offline RFC 9102 verification; align §6.4 claims with actual broker behavior (per B2 decision)
- [ ] Verify the not-fully-audited DNSSEC §3 MUSTs against dns_fetcher.rs/fallback_fetcher.rs
