---
# browserid-ng-4lxl
title: Revocation status checks are fail-open / missing at broker, spec says fail-closed (B2)
status: todo
type: bug
priority: high
created_at: 2026-07-23T21:40:54Z
updated_at: 2026-07-23T21:40:54Z
---

Spec §6.4 (protocol.md:408-412) requires all three status checks (access cert, config cert, warrant) fail-closed, and claims (protocol.md:372-376) the broker checks its own credentials authoritatively at /verify. Reality: broker /verify-access checks NONE of the three refs (verifier.rs:135-137 'Revocation is therefore not yet enforced'; verify_access_with_dns never touches them), and browserid-rp defaults fail-open (StatusCache::new fail_closed:false lib.rs:483-492; Unknown passes unless opted in lib.rs:242-247).

Decide: flip reference defaults to fail-closed + implement broker checking (spec-compliant), or downgrade the spec MUST to a policy knob and mark broker enforcement planned. Recommendation: spec is right — revocation is the model's backbone; implement.

From docs/plans/2026-07-23-spec-code-divergence-audit.md (B2).
