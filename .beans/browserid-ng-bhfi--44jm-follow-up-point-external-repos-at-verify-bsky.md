---
# browserid-ng-bhfi
title: '44jm follow-up: point external repos at /verify (bsky, mingo, sbo)'
status: todo
type: task
created_at: 2026-08-25T20:56:41Z
updated_at: 2026-08-25T20:56:41Z
---

The /verify cutover (bean 44jm) is done in browserid-ng; /verify-access remains a permanent alias so nothing is broken, but external consumers should move to the canonical route:

- [ ] browserid-bsky: pds-bridge verify_presentation POSTs {broker}/verify-access (routes.rs) + test mock route
- [ ] mingo: check for /verify-access / /verify-assertion uses
- [ ] sbo: check daemon/attribution verify calls

Read ~/src/browserid-bsky HANDOFF before touching that repo.
