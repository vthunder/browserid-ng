---
# browserid-ng-gzq7
title: Split identity-critical apps onto a dedicated host
status: in-progress
type: epic
priority: high
created_at: 2026-08-06T14:12:15Z
updated_at: 2026-08-06T15:17:20Z
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
- [x] Encrypted backups: ~/bin/sandmill-backup.sh, daily 03:20 via launchd org.sandmill.backup. PULL model (droplet holds no backup creds); age PUBLIC-key encryption so the job cannot decrypt what it writes; private key ~/backups/sandmill/age-identity.txt (0600) — MUST also go in the password manager or backups are unreadable. SQLite snapshotted via .backup (WAL-safe). Verified: 477 entries, all 9 dbs PRAGMA integrity_check=ok, broker-key.json + attest/checkpoint keys + PLC rotation key + IdP key all present. Retains 14. Dedicated restricted SSH key ~/.ssh/sandmill-backup (agent is unavailable under launchd).
- [ ] Secrets repo: sops+age encrypted, one file per app, apply script

## Stage 3 — identity host
- [ ] Scripted host build (dokku, ufw 22/80/443 only, per-repo CI deploy keys, no key on sudo accounts)
- [ ] Migrate id, bsky-bridge, bsky-pds, browserid-wallet (no protocol change needed)

## Stage 4 — hosted IdP (defers the sandmill.org IdP migration)
- [ ] Spec/code: support-document endpoints MAY be absolute URLs (browserid-broker/src/routes/email.rs builds https://{domain}{path}); keeps iss == domain so the verifier trust model is unchanged
- [ ] Generalize bsky-bridge's idp module into a multi-tenant hosted IdP
- [ ] sandmill.org becomes tenant #1; retire the Laravel IdP; key moves to identity host

## Stage 5 — hobby host rebuild from the same script

## Backup gotchas found by testing the SCHEDULED path (not just manual)
launchd runs with a minimal PATH (no Homebrew -> age missing) and NO ssh-agent; the admin RSA key exists only in the agent, not on disk. Both are now explicit in the script. A backup that only works when run by hand is not a backup.

Still open: backups live only on the mini. A second, genuinely offsite copy (B2/S3 via rclone) is worth adding — as is putting the age private key in the password manager.

## www CI (2026-08-06)
.github/workflows/deploy-www.yml added: builds marketing/ -> ghcr.io/vthunder/browserid-ng/www, releases via git:from-image, replacing the `git subtree push --prefix marketing` deploy. www was the last identity-host app without a reproducible image build.

NOT YET GREEN. Two runs failed on transient GHCR problems, neither structural — run 1 built and pushed the sha-tagged manifest fine, then hit a GitHub SECONDARY RATE LIMIT tagging :latest; run 2 timed out in docker/login-action reaching ghcr.io. The workflow config is validated (YAML parses; context=marketing, file=marketing/Dockerfile — the Dockerfile COPYs by relative path so the repo root will NOT work).

Blocking first successful deploy: the ghcr.io .../www package must be made PUBLIC (new GHCR packages default to private; the host holds no registry credentials). No REST endpoint for container package visibility — it is a click in GitHub package settings, same one-time step the broker/wallet/guestbook packages went through.

The guestbook escaping fix was shipped meanwhile via the old subtree push (www e0842ea) so it did not wait on GHCR; verified live.
