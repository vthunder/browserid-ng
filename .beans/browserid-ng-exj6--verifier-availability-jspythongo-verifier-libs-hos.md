---
# browserid-ng-exj6
title: Verifier availability — JS/Python/Go verifier libs + hosted /verify
status: todo
type: feature
created_at: 2026-07-10T15:24:41Z
updated_at: 2026-07-10T15:24:41Z
---

GTM: Rust-only verification is a silent adoption ceiling. "Add agent auth" must be five minutes in any stack. Plan: `docs/plans/2026-07-10-agent-identity-v3-and-gtm-plan.md` (§7).

- Tiny verifier libraries beyond Rust — priority order by RP demand, likely JS/TS first, then Python, Go.
- Hosted `/verify` endpoint as the zero-dependency path.
- Every port bakes in the v3 fail-closed agent handling from day one: reject unrecognized cert `typ`, require warrant-in-chain for agent certs, enforce `aud`, surface scopes; status-list check with cache.
- Sequencing: after spec v0.4 stabilizes chain format (blocked conceptually by 5zdh; start scaffolding earlier if useful).

### Todo
- [ ] JS/TS verifier (npm) with fail-closed agent defaults
- [ ] Python verifier
- [ ] Go verifier
- [ ] Hosted /verify hardening + docs
- [ ] RP quickstart docs per language
