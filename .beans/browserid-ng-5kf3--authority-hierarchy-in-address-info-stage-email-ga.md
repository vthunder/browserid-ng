---
# browserid-ng-5kf3
title: Authority hierarchy in address_info + stage_email gate
status: todo
type: feature
priority: normal
created_at: 2026-07-30T20:35:08Z
updated_at: 2026-07-30T21:04:01Z
parent: browserid-ng-tsqk
---

Broker runs the claim-time hierarchy (_browserid → handle binding → MX → refuse).

- [ ] address_info: run the hierarchy; new state telling the dialog to take the atproto lane
- [ ] stage_email: refuse the SMTP loop when authority is atproto, or when the domain has no MX
- [ ] Step 2 must be a RESOLVED binding (both methods, DNS wins, bidirectional alsoKnownAs check) — not just an _atproto TXT
- [ ] Step 1 must be DNSSEC-VALIDATED (an unsigned _browserid record is ignored today)
- [ ] Cache the resolve-only check; don't put an uncached bridge call on every no-primary address_info
- [x] Pre-flight (run 2026-07-30): CLEAR — no prod domain resolves as a handle.

| domain | handle? | MX | _browserid | hierarchy lands on |
|---|---|---|---|---|
| bsky.browserid.me | no | no | yes | 1 (primary — existing D identities untouched) |
| mingo.place | no | yes | yes | 1 (primary) |
| sandmill.org | no | yes | yes | 1 (primary) |
| example.com | no | yes | no | 3 (SMTP, unchanged) |
| gmail.com | no | yes | no | 3 (SMTP, unchanged) |

Zero identities change proof method. NOTE: this is a snapshot, not a guarantee — re-run immediately before shipping the gate. If a hit ever appears, the fix is a one-time backfill of the proof method onto pre-existing identities (a grandfather clause, NOT general pinning, so it does not contradict the no-pinning rule).
