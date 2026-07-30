---
# browserid-ng-5kf3
title: Authority hierarchy in address_info + stage_email gate
status: todo
type: feature
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T20:35:08Z
parent: browserid-ng-tsqk
---

Broker runs the claim-time hierarchy (_browserid → handle binding → MX → refuse).

- [ ] address_info: run the hierarchy; new state telling the dialog to take the atproto lane
- [ ] stage_email: refuse the SMTP loop when authority is atproto, or when the domain has no MX
- [ ] Step 2 must be a RESOLVED binding (both methods, DNS wins, bidirectional alsoKnownAs check) — not just an _atproto TXT
- [ ] Step 1 must be DNSSEC-VALIDATED (an unsigned _browserid record is ignored today)
- [ ] Cache the resolve-only check; don't put an uncached bridge call on every no-primary address_info
- [ ] Pre-flight: confirm no currently-verified prod email sits at a domain that also resolves as a handle
