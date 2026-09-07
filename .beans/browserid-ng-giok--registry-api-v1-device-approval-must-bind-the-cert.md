---
# browserid-ng-giok
title: 'registry-api-v1: device approval must bind the cert, not the pubkey (review A5)'
status: completed
type: task
priority: high
created_at: 2026-09-06T11:08:58Z
updated_at: 2026-09-06T21:56:25Z
parent: browserid-ng-0c49
---

From the 2026-09-06 adversarial review (security M5/L11, UX 8, completeness 9). Dan: "sounds bad, not sure I understand it — discuss separately."

THE ATTACK as drafted before r5 fixes: device requests were keyed on public keys and recorded "at the certs' tiers" on retry. Attacker files a request with an AUTH cert for key K (approver sees a harmless read-only device), gets approval, then retries with a CONFIG cert for the same K from the same IdP → recorded at write.

r5 draft (2026-09-06) already applies the fix provisionally: requests keyed on SHA-256 of each cert's bytes, retry must carry byte-identical certs, approval per identity, 1 h window, confirm_transfer refused while a request is pending. This bean is to REVIEW that fix with Dan and settle:
- [ ] Walk the attack with Dan; confirm cert-hash keying closes it
- [ ] Per-identity approval semantics for multi-identity requests
- [ ] Whether an approver at read tier should see the request at all (UX: looks broken when refused write_required)

## Summary of Changes

Discussed with Dan 2026-09-06. Ruling: approving a device means 'this is me, connect this device to my account'. The reviewer's cert-hash binding did not close the escalation anyway (an approved read-tier device records a config cert under its own session via the with-session row), so it was dropped: requests are keyed on the set of public keys; retry with the same keys. §5.6.4 states the meaning of approval.
