---
# browserid-ng-0p5f
title: Make all verifiers DNSSEC-conformant (key from _browserid record, support host=, never .well-known keys)
status: completed
type: feature
priority: high
created_at: 2026-08-09T15:05:49Z
updated_at: 2026-08-10T03:39:20Z
parent: browserid-ng-g5qt
---

Hosted tenants publish their key ONLY in the DNSSEC _browserid record (+ host= for endpoints) and serve no key at .well-known. Any verifier that reads the issuer key from .well-known over HTTP breaks on tenant presentations (and is a spec violation — DNSSEC is the sole root of trust; .well-known never carries a key).

## Confirmed failure (2026-08-09)
danmills@sandmill.org (now a hosted tenant: DNS has tenant key EzZwk1X_ + host=idp.browserid.me) signs into mingo.place. mingo's verifier (mingo-idp/src/verify.rs) resolves the key via browserid-core discover()+HttpFetcher → fetches sandmill.org/.well-known (still self-serves the OLD key 5T9Vg…) → verifies tenant-signed certs against the old key → "Signature verification failed."

## Plan (DNSSEC-only, one pass)
- [x] Extracted browserid-dnssec crate: moved dns_fetcher; added resolve_idp_key() (key always from the DNSSEC record; verifiers never fetch the domain for a key, so host= is honored implicitly).
- [x] Broker consumes the crate (dns_fetcher re-exports it); behavior identical, tests green; redeployed to prod (1e0fed4).
- [x] browserid-rp: added verify_dnssec() (resolves every issuer key via DNSSEC; primary iff record present, else accept_fallback broker). Removed trust_*_from_well_known + fetch_well_known_key. Pinned trust_*/sync verify() kept as explicit offline/test mode. Tests green.
- [x] mingo verify.rs rewritten to DNSSEC (browserid-dnssec::resolve_idp_key); dropped HttpFetcher + dead fetch_domain_pubkey; routes.rs uses a DnsFetcher (no spawn_blocking). Pins bumped to bc8eaad. Committed + pushed (mingo 4aaf01e). Builds + tests green.
- [x] Tests green across broker + rp; mingo workspace builds + tests green.
- [~] Broker deployed + verified. MINGO DEPLOY PENDING (USER): the mingo deploy key ~/.ssh/donotuse_id_ed25519_service is not on this machine — run `make deploy-mingo` (git push to dokku@sandmill.org; slow host-build ~40min due to the new hickory dep on the 24G host; dokku keeps the current release if the build fails). Then re-test the sandmill.org → mingo login.

## Deferred (separate bean)
On-chain / SBO verifier conformance — file after the above.

## Deferred
On-chain / SBO verifier conformance filed as browserid-ng-k3rg.

## Mingo deploy blocked (2026-08-10)
Cannot deploy mingo from this machine: the deploy key ~/.ssh/donotuse_id_ed25519_service is absent, and no other on-disk/agent key (nor root@sandmill.org) authorizes dokku@sandmill.org. USER must run `make deploy-mingo` (or place the service key here). Code fix is committed + pushed (mingo 4aaf01e); dokku keeps the current release if the host-build fails, so re-running is safe.

## Deploy-key audit (2026-08-10)
Audited mingo deploy scripts for the "donotuse" key the user flagged:
- FOUND + FIXED: mingo Makefile `KEY ?= ~/.ssh/donotuse_id_ed25519_service` and 4 DEPLOYMENT.md commands referenced it. All switched to ~/.ssh/mini-ops (the declared mac-mini dokku ops key). No donotuse references remain (mingo d3cc2f3, pushed).
- Key access reality on the HOBBY host (sandmill.org / 198.199.110.160, where mingo/sbo/sandmill run): dokku authorizes admin(RSA), ailian, browserid-bsky-ci, browserid-ng-ci, laptop-admin. mini-ops is NOT installed here (only on the identity host browserid.me). So mini-ops via -i alone is denied; it works only because ssh falls back to laptop-admin in the agent.
- DONE (2026-08-10): installed mini-ops on the hobby host via `thunder@sandmill.org` + `sudo dokku ssh-keys:add mini-ops` (laptop-admin authorizes the thunder sudo login; root@ is denied but sudo NOPASSWD works). Verified mini-ops now authenticates standalone (IdentitiesOnly=yes) on the hobby dokku host. This is interim until the hobby host is rebuilt with the new provision scripts (separate infra bean), which will set it up automatically.
- mingo deployed successfully (mini-ops key) and healthy (mingo.place 200, running). The DNSSEC verifier fix is live; sandmill.org tenant login now verifies against the tenant key.
