---
# browserid-ng-kh0j
title: '[H2] RP library trusts Web-PKI .well-known keys (DNSSEC-sole-root downgrade)'
status: todo
type: bug
priority: high
created_at: 2026-08-07T16:03:17Z
updated_at: 2026-08-07T16:03:17Z
parent: browserid-ng-8g49
---

browserid-rp fetch_well_known_key (browserid-rp/src/lib.rs:532-562, via trust_issuer_from_well_known/trust_primary_from_well_known) takes the IdP key from .well-known JSON over plain HTTPS (accepts http:// too), zero DNSSEC — the exact downgrade spec §3 forbids ('no dual path'). Stale comments lib.rs:120-123,271-273 claim the removed issuer binding holds. Make RP resolve via DNSSEC/detached proof, or mark _from_well_known test-only/pinning-bootstrap and fix comments. See audit H2.
