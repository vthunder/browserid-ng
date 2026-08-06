---
# browserid-ng-gzq7
title: Split identity-critical apps onto a dedicated host
status: in-progress
type: epic
priority: high
created_at: 2026-08-06T14:12:15Z
updated_at: 2026-08-06T14:20:09Z
---

Rebuild sandmill.org dokku host into two: an identity host (browserid.me broker, bsky-bridge, bsky-pds, browserid-wallet) and a hobby host (everything else), driven by a reproducible setup script with secrets in an encrypted git repo.

Context: a leaked SSH key (public repo) was authorized on both the dokku user and a NOPASSWD-sudo account. Revoked 2026-08-06; forensics found no unauthorized use (all 118 logins were the owner's IP or matching CI runs, none as the sudo-capable user, no persistence artifacts). Rebuild is for hygiene/architecture, not incident response.

## Stage 1 — cheap cleanup (in progress)
- [x] Snapshot config+state of apps to be deleted (~/backups/sandmill/2026-08-06-decommission/decommission-bundle.tgz, 3.2M, mode 600 — CONTAINS SECRETS, must go into the encrypted backup set)
- [x] Delete unused apps: wallet (SBO), foo, phonics, fallback — 20 apps -> 16; public port 3001 closed
- [x] Back up rolodexterity state (in the decommission bundle; app kept and healthy)
- [x] Delete orphaned bud-state dir — kept the <2MB memory/journal subset (1_core, 3_long_term, insights, projects, journal.jsonl), dropped 865M of re-clonable repos. Disk 69% -> 65%
- [x] SSRF-guarded /retro?url= instead of relocating it (sandmill dc39f72): the risk was lateral movement (docker network, 169.254.169.254 metadata), not key theft — SSRF returns fetched bodies and cannot read env vars. Guard requires http(s) + globally-routable resolved addresses and disables redirect-following. 18 tests; verified live.

## Stage 2 — backups + secrets
- [ ] Encrypted offsite backup of all persistent state (~28MB, includes irreplaceable PLC rotation key + broker key + IdP key)
- [ ] Secrets repo: sops+age encrypted, one file per app, apply script

## Stage 3 — identity host
- [ ] Scripted host build (dokku, ufw 22/80/443 only, per-repo CI deploy keys, no key on sudo accounts)
- [ ] Migrate id, bsky-bridge, bsky-pds, browserid-wallet (no protocol change needed)

## Stage 4 — hosted IdP (defers the sandmill.org IdP migration)
- [ ] Spec/code: support-document endpoints MAY be absolute URLs (browserid-broker/src/routes/email.rs builds https://{domain}{path}); keeps iss == domain so the verifier trust model is unchanged
- [ ] Generalize bsky-bridge's idp module into a multi-tenant hosted IdP
- [ ] sandmill.org becomes tenant #1; retire the Laravel IdP; key moves to identity host

## Stage 5 — hobby host rebuild from the same script
