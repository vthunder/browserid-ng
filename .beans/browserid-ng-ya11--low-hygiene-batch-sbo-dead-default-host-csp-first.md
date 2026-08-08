---
# browserid-ng-ya11
title: '[Low] Hygiene batch: sbo dead default host, CSP first-script guard, handle-claim scope, public-name byline, MX fail-open, dual broker-key.json, subaddress spec gap, RP §8.1 policy, alg header, sandmill bad default'
status: todo
type: task
priority: low
created_at: 2026-08-07T16:03:44Z
updated_at: 2026-08-07T16:03:44Z
parent: browserid-ng-8g49
---

Low/info items from docs/spec-code-audit-2026-08-07.md (Low/Info section): sbo id.sandmill.org dead default (flip to browserid.me before CLI rebuild); CSP self-check hashes only first inline script per file (routes/mod.rs:485); whole-handle claim transfers all labels (handle_claim.rs:126-157, by-design note); set_public_name arbitrary byline (email.rs:161-193); authority/MX gate fails open (routing downgrade); two different broker-key.json in tree; implicit +subaddress auth undocumented in spec §4.1 (device.rs:59-85); browserid-rp §8.1 pin-based policy differs from broker; JOSE alg header never validated (jws.rs:33-41); sandmill broker_url default localhost:3000 vs hardcoded browserid.me.
