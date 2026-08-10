---
# browserid-ng-zexp
title: Remove advisory public-key from the .well-known/browserid support document
status: completed
type: task
priority: normal
created_at: 2026-08-08T10:41:03Z
updated_at: 2026-08-10T05:59:55Z
parent: browserid-ng-8g49
---

Per spec §3/§3.1 (2026-08-08), the support document carries NO key — the IdP key comes solely from the _browserid DNSSEC record. The discovery struct (browserid-core/src/discovery.rs SupportDocument.public_key: Option<PublicKey>) and the broker's well_known route still emit an advisory public-key. Remove it from the served document (and from SupportDocument, or keep the field ignored for back-compat). Also check consumers (browserid-rp, sandmill, mingo-idp, bsky) that read it. This eliminates the need to describe the field as advisory/untrusted.

## Fixed 2026-08-10 (commit pushed): served /.well-known/browserid no longer advertises a key (public_key=None on the served doc; struct field retained for the DNSSEC resolver). Tests resolve the broker key via TestContext.broker_key. Full broker suite green.
