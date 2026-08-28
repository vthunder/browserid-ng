---
# browserid-ng-gzq7
title: Split identity-critical apps onto a dedicated host
status: todo
type: epic
priority: high
created_at: 2026-08-06T14:12:15Z
updated_at: 2026-08-26T23:10:06Z
---

Rebuild sandmill.org dokku host into two: an identity host (browserid.me broker, bsky-bridge, bsky-pds, browserid-wallet) and a hobby host (everything else), driven by a reproducible setup script with secrets in an encrypted git repo.

Context: a leaked SSH key (public repo) was authorized on both the dokku user and a NOPASSWD-sudo account. Revoked 2026-08-06; forensics found no unauthorized use (all 118 logins were the owner's IP or matching CI runs, none as the sudo-capable user, no persistence artifacts). Rebuild is for hygiene/architecture, not incident response.

## RESUME HERE — state as of 2026-08-07

**Where things stand:** the identity split is DONE and live. Everything below is
verified, not assumed.

| Host | IP | Runs |
|---|---|---|
| `id-host` (new) | 159.89.230.185 | browserid.me, www, guestbook-mcp, browserid-wallet, bsky-bridge, bsky-pds — all with valid TLS |
| `sandmill.org` (old) | 198.199.110.160 | sandmill, mingo, sbo-daemon, fedcm-rp, rolodexterity, sandmill-{bot,irc,proxy,relay}, virtual-ethernet-switch. The 6 migrated apps are STOPPED here but their data remains — this is the rollback path, do NOT destroy it yet. |

**Everything lives in `github.com/vthunder/sandmill-infra` (private).** Read its
README first: it declares the rule (the domain is the trust boundary), the app
definitions, the access model, and the scripts. Encrypted secrets are committed
there; they are useless without the age key.

**First command to run when resuming** — proves the host still matches what the
repo claims, and is faster than re-reading anything:

    cd ~/src/sandmill-infra && bin/audit-host.sh root@159.89.230.185

**Access:**
- `~/.ssh/laptop-admin` (laptop, passphrase) — root + dokku on both hosts. Reaches
  the mini only via agent forwarding, so it vanishes when the laptop sleeps.
- `~/.ssh/mini-ops` (mini) — dokku user only. Enough to deploy and manage apps,
  never root. Use this for unattended work.
- `~/.ssh/mini-backup` (mini) — forced command only; produces an encrypted backup
  and nothing else.
- `~/backups/sandmill/age-identity.txt` — decrypts every backup and every secret
  in the infra repo. Also in the password manager since 2026-08-07, so the mini
  is no longer a single point of failure. Never commit it; never put it on a
  host (hosts hold only the PUBLIC half, at /etc/backup-recipient.pub).
- DigitalOcean: `doctl` is authenticated; the account holds exactly one SSH key.

**Backups:** `~/bin/sandmill-backup.sh`, launchd `org.sandmill.backup`, 03:20
daily, both hosts, 14 kept each, encrypted host-side.

## Next, in order

1. **Hobby host rebuild** (stage 5) — IN PROGRESS, see "Stage 5" section below.
   Repo prep is DONE (host profiles, hobby confs, secrets seeded); remaining
   stages need laptop-admin (agent forwarding to the mini).
2. **Decommission the old droplet** once confident.
3. **`browserid-ng-v96n`** — move the guestbook out of the broker. Independent
   of the host work; a good standalone task.
4. **Stage 4: hosted IdP** so `sandmill.org`'s IdP can leave the hobby host. The
   blocker is one line in `browserid-broker/src/routes/email.rs` that builds
   endpoint URLs as `https://{domain}{path}`; allowing absolute URLs lets a
   hosted IdP serve the endpoints while `iss` stays the customer domain, so the
   verifier's trust model needs no change. Start from bsky-bridge's `idp` module,
   which is already a working IdP.

## Gotchas worth not rediscovering

- **DNS:** creating `pds.bsky.browserid.me` made `bsky.browserid.me` an *empty
  non-terminal*, so the `*.browserid.me` wildcard refused to answer for it
  (RFC 4592 — NOERROR/0 answers, not NXDOMAIN). It needed an explicit record.
  Wildcards also match exactly one label.
- **Debian ships a `backup` user** (uid 34, home `/var/backups`). Creating one
  by that name silently mutates a system account and sshd reads the wrong
  authorized_keys. We use `dokku-backup`.
- **macOS `/bin/bash` is 3.2**: expanding an empty array under `set -u` errors,
  and it cannot parse nested `$( ... $(...) ... )`.
- **bsky-pds needs ONE SAN cert** covering both its wildcard and non-wildcard
  vhost; dokku keeps a single cert bundle per app, so a wildcard-only cert
  breaks `pds.bsky.browserid.me`.
- **GHCR packages from a public repo are already public** — no manual step,
  contrary to comments that used to be in the deploy workflows.
- Let's Encrypt DNS-01 can fail once on a challenge-TXT propagation race; retry.

## Stage 1 — cheap cleanup (done)
- [x] Snapshot config+state of apps to be deleted (now ~/backups/sandmill/decommission-2026-08-06.tar.gz.age — age-encrypted, plaintext destroyed)
- [x] Delete unused apps: wallet (SBO), foo, phonics, fallback — 20 apps -> 16; public port 3001 closed
- [x] Back up rolodexterity state (in the decommission bundle; app kept and healthy)
- [x] Delete orphaned bud-state dir — kept the <2MB memory/journal subset (1_core, 3_long_term, insights, projects, journal.jsonl), dropped 865M of re-clonable repos. Disk 69% -> 65%
- [x] SSRF-guarded /retro?url= instead of relocating it (sandmill dc39f72): the risk was lateral movement (docker network, 169.254.169.254 metadata), not key theft — SSRF returns fetched bodies and cannot read env vars. Guard requires http(s) + globally-routable resolved addresses and disables redirect-following. 18 tests; verified live.

## Stage 2 — backups + secrets
- [x] Encrypted backups: ~/bin/sandmill-backup.sh, daily 03:20 via launchd org.sandmill.backup. PULL model (droplet holds no backup creds); age PUBLIC-key encryption so the job cannot decrypt what it writes; private key ~/backups/sandmill/age-identity.txt (0600) — MUST also go in the password manager or backups are unreadable. SQLite snapshotted via .backup (WAL-safe). Verified: 477 entries, all 9 dbs PRAGMA integrity_check=ok, broker-key.json + attest/checkpoint keys + PLC rotation key + IdP key all present. Retains 14. Dedicated restricted SSH key ~/.ssh/sandmill-backup (agent is unavailable under launchd).
- [x] Secrets repo: ~/src/sandmill-infra (local git, not pushed). age-encrypted one file per app (5 apps, 41 vars), seeded from the 2026-08-07 backup and verified against the host. Uses age rather than sops — same key already protects the backups.

## Stage 3 — identity host
- [x] Scripted host build: sandmill-infra/bin/{provision-host,apply-apps,restore-state,seed-secrets}.sh + apps/*.conf for all 6 identity apps. apply-apps.sh smoke-tested against the live host on www (domains, GHCR pull, deploy, healthy). Scripts honour SSH_KEY/SUDO so they work as root@newbox and thunder@currenthost.
- [x] Identity host BUILT and verified at 159.89.230.185 (droplet id-host, 2GB/1vCPU, nyc1). All 6 apps (id, www, guestbook-mcp, browserid-wallet, bsky-bridge, bsky-pds) created, configured, deployed from pinned images, state restored from the 2026-08-07 backup. Verified vs production: identical broker public key, identical guestbook entries (3), identical user count (13), all 4 dbs integrity_check=ok, every app 200 via Host: header. audit-host.sh: no drift.
- [x] DNS cutover done 2026-08-07. browserid.me zone now: * / *.at / @ / pds.bsky / bsky -> 159.89.230.185. All 5 HTTP-01 certs issued and validating; bsky-pds still needs DNS-01 for the *.at wildcard.

DNS gotcha worth remembering: `bsky` needed an EXPLICIT record even with a wildcard present. Creating pds.bsky.browserid.me makes bsky.browserid.me an EMPTY NON-TERMINAL — the name exists in the tree, so per RFC 4592 the wildcard refuses to synthesize for it (NOERROR/0 answers, not NXDOMAIN). Same would apply to at.browserid.me. A wildcard also only ever matches ONE label.

## Stage 4 — hosted IdP (defers the sandmill.org IdP migration)
- [x] Spec/code: hosted IdP serves the endpoints while iss stays the customer domain — achieved via the DNS host= pointer mechanism instead of absolute URLs (well_known_host in browserid-core/src/dns.rs; live at idp.browserid.me)
- [x] Multi-tenant hosted IdP — achieved via the broker growing tenancy (hosted_idp.rs, epic g5qt) rather than generalizing the bridge module
- [ ] sandmill.org becomes tenant #1; retire the Laravel IdP; key moves to identity host — PARTIAL: tenant #1 live (_browserid.sandmill.org → host=idp.browserid.me, key on identity host via 1431a3c), but the Laravel IdP is not retired (BrowserIdController.php still serves /.well-known/browserid, bypassed by conformant verifiers)

## Stage 5 — hobby host rebuild from the same script

### Decisions (2026-08-27, confirmed with owner)
- Migrate 7 apps: sandmill, mingo, sbo-daemon, rolodexterity, sandmill-bot,
  sandmill-irc, sandmill-proxy. RETIRE fedcm-rp, sandmill-relay,
  virtual-ethernet-switch (legacy WS ethernet path superseded by in-browser
  virtual-gateway; fedcm-rp sources live in browserid-ng). They stay on the
  old droplet until decommission = the rollback for this call.
- New droplet: **1GB/25GB sfo3** ($6) — deliberate experiment; hobby profile
  adds a 2G swapfile for the on-host herokuish build of sandmill
  (composer+webpack). If it OOMs, DO resize 1GB→2GB is reversible (CPU/RAM-only).
- Root access: laptop-admin via agent forwarding (no root key minted on mini).
- Git hosting (old host ~/git, 11 bare repos incl. sandmill's origin):
  sandmill → private GitHub repo as new origin; the rest archived as
  ~/backups/sandmill/salvage/git-repos-sandmill.org.tar.gz (done).

### Done 2026-08-27 (no root needed)
- [x] sandmill-infra restructured: hosts/{identity,hobby}.conf profiles
  (ufw ports, extra plugins, swap), apps/ → apps/identity/ + apps/hobby/,
  all scripts take PROFILE= (default identity). Commit 6abecaf, pushed.
- [x] Hobby confs written from LIVE old-host inventory (domains/ports/storage
  verified via dokku, not from docs). sandmill-irc maps tcp:6667; hobby ufw
  = 22/80/443/6667; http-auth plugin 0.10.0 (rolodexterity, user ailiangan).
- [x] Hobby secrets seeded from the 2026-08-26 backup (7 apps, committed).
  GOTCHA: seed-secrets MUST be profile-scoped — the hobby backup carries meta
  for the STOPPED identity rollback apps and an unscoped run overwrites fresh
  identity secrets with stale ones (happened; reverted via git).
- [x] audit-host.sh --hobby validated against the old host: reports exactly
  the known deltas and nothing else.
- [x] rolodexterity salvage (no source repo exists): image
  dokku/rolodexterity:latest → ~/backups/sandmill/salvage/rolodexterity-image.tar.gz
  (200M, gzip-verified) + rolodexterity.htpasswd. Deploy on new host:
  gunzip | docker load, retag rolodexterity:salvaged, git:from-image; restore
  htpasswd + `dokku http-auth:on`.
- [x] All 11 ~/git bare repos archived to the mini (see salvage dir).

### Hobby host BUILT and verified 2026-08-27 (droplet `hobby-host`, 143.198.71.94, 1GB/25GB sfo3)
- All 7 apps deployed and verified via Host: curls: sandmill 200 (+title),
  www 200, proxy 200, rolodexterity 401 (http-auth, ailian's htpasswd),
  mingo.place 200, irc 6667 open. sqlite integrity ok (sandmill, mingo,
  rolodexterity). State restored from the 2026-08-27T0320 backup.
  audit-host --hobby: NO DRIFT. Disk 40%; herokuish Laravel build succeeded
  fine on 1GB (2G swap present).
- **sbo-daemon and sandmill-bot are deliberately STOPPED on the new host**
  until cutover: sbo-daemon publishes checkpoints/attestations with the
  authority keys (two live instances = double publishing); bot would join
  IRC/Discord twice. At cutover: stop on old host FIRST, then ps:start both
  on new. sandmill-bot also needed `ps:scale sandmill-bot worker=1` (scale is
  not part of git push).
- Gotchas hit and fixed (all committed to sandmill-infra):
  - ~/.ssh/laptop-admin.pub on the mini was a STALE key and got authorized as
    dokku 'admin' — git push denied. keys/dokku/ is the truth; provision now
    defaults to it. The mini's copy was replaced.
  - `dokku git:from-image` (BuildKit) ignores locally-loaded images — worked
    around with a throwaway `registry:2` on localhost:5000 (push tag there,
    from-image localhost:5000/rolodexterity:salvaged, rm container). Also:
    dokku's post-deploy prune DELETES loaded-but-unreferenced images, so the
    load→release chain must run without another deploy in between.
  - http-auth:on fails on a fresh host: needs `whois` (mkpasswd), then still
    dies in a sudo privilege drop. Replicated the end state directly instead:
    property file /var/lib/dokku/config/http-auth/<app>/enabled=true +
    nginx.conf.d/http-auth.conf + htpasswd. And dokku's "Reloading nginx" did
    NOT apply it — needed a real `systemctl reload nginx` (curl went 200→401).
  - Plugin pinning: dokku-http-auth stopped tagging at 0.9.0, so a v<version>
    committish silently takes HEAD. PLUGINS specs are now
    name:version[:committish]; http-auth = 0.13.0 @ aa1c43a.
1. ~~build~~ DONE (above).
2. ~~deploy + restore + verify~~ DONE (above).
3. ~~Cutover~~ DONE 2026-08-27 ~20:40Z. Flipped four A records (sandmill.org
   `@` `*` `id`, mingo.place `@`) → 143.198.71.94. Order executed: stopped
   sbo-daemon+bot on OLD host → final backup (pulled by IP,
   sandmill-final-cutover-2026-08-27T202524) → delta restore → started both
   on new host → letsencrypt all 5 web apps → verified https 200s (401s =
   intended auth gates) → mini known_hosts refreshed → backup job ran clean
   against both hosts by hostname → mingo/sbo CI needs nothing (fresh
   ssh-keyscan per run; mingo-ci already authorized).
   - DNS learned: the zone had NO records for www/proxy/rolodexterity/da —
     the `*.sandmill.org` wildcard carries them. `id.sandmill.org` A record
     KEPT: `send.id` TXT+MX + `resend._domainkey.id` are the BROKER's
     login-email identity (id@id.sandmill.org via Resend, on SES infra —
     easily mistaken for SES leftovers; bean j5rn moves it to browserid.me).
     While `send.id` exists, `id` is an empty non-terminal the wildcard will
     NOT cover (RFC 4592 again).
   - sandmill-proxy cert initially unissuable: its custom nginx.conf.sigil
     gated the nginx.conf.d include (= ACME challenge location) on SSL_INUSE
     — chicken-and-egg on any fresh host. Fixed in sandmill-proxy 273e-ish
     commit ("include nginx.conf.d on port 80 before SSL exists").
   - TODO: raise Namecheap TTLs (sandmill.org @/*/id, mingo.place @) back to
     Automatic/1800 after a day or two of stability.
   Original checklist for reference: (sandmill.org zone incl.
   *.sandmill.org wildcard + explicit records, AND mingo.place); final
   backup → re-restore delta; flip A records; letsencrypt per app (was
   SKIP_TLS); refresh mini known_hosts for sandmill.org (backup job runs
   BatchMode and fails loudly on new host key); authorize mingo-ci key on new
   host (mingo/sbo-daemon CI DOKKU_HOST=sandmill.org stays right); consider
   config:unset sandmill ETHERNET_RELAY_URL ETHERNET_WS_URL (retired apps).
4. Decommission (after ~a week). ~~GitHub part DONE 2026-08-27~~: private
   repo github.com/vthunder/sandmill created, main pushed, origin repointed,
   AGENTS.md updated (old bare repo archived in salvage tarball with the 10
   others; promote any of those to GitHub individually if ever needed).
   Decommission SWEEP done 2026-08-28 (thorough; nothing left of value):
   - Archived encrypted to ~/backups/sandmill/salvage/
     old-host-home-stragglers.tar.gz.age (27M, decrypt-verified):
     ~/sandmill-backup (a PERSONAL-DATA CHEST mislabeled as backups — dot-ssh,
     sandmill.org.databases.sql, twitterbot-secrets.json, webflow-sites,
     contacts), sandmill.old, example-app, sandmill.tar.gz, bootstrap.sh,
     working-tree .claude/settings.local.json (vendor/node_modules excluded).
   - Confirmed nothing else: no orphan dokku storage dirs, no private
     SSH/GPG keys in any home, no custom systemd units, /usr/local only had
     the bud watcher + our backup-snapshot, nginx stock, 38 dangling docker
     volumes are detritus of apps already in the 2026-08-06 decommission
     bundle. ~/sandmill.git is an EMPTY bare repo (the real one was ~/git/
     sandmill.git, archived + on GitHub). Working-tree HEAD is in main.
   - Disabled (dated, reversible) the old host's leftover automations:
     thunder cron bsky-bridge-watchdog (would have restarted the STALE
     rollback bridge if prod ever blipped), root acme.sh renewal cron
     (dueling with id-host's), /etc/cron.d/bud-rebuild (dormant).
   - Sweep found TWO id-host gaps, both fixed: (1) NO letsencrypt auto-renew
     cron — certs would have silently expired ~2026-11-05; cron added on both
     hosts and folded into provision-host.sh. letsencrypt:enable does NOT
     imply renewal. (2) the bsky-bridge fd-exhaustion watchdog was never
     ported with the bridge; now at /usr/local/bin/bsky-bridge-watchdog.sh
     on the id-host, root crontab, */2min, test-run healthy.
   Old droplet POWERED OFF 2026-08-27 ~19:52Z as a smoke test (doctl
   droplet-action shutdown; power-on = instant rollback). The test earned
   its keep immediately — TWO breakages surfaced, both fixed + codified:
   - sandmill-irc unreachable: dokku's nginx template renders tcp maps as an
     upstream with NO listener. Old host had legacy DOKKU_DISABLE_PROXY=1
     (docker publishes the port) which seed-secrets rightly drops as
     dokku-managed. Fix: proxy:disable + docker-options deploy "-p 6667:6667"
     + ps:rebuild. Now declared in apps/hobby/sandmill-irc.conf.
   - sandmill-bot crash-looping since deploy: its IRC target
     `sandmill-irc.web` is a docker-network alias; the old host's shared
     network was NEVER captured by backup meta. Off-network, the name
     resolves via PUBLIC DNS to ICANN's .web gTLD collision sinkhole
     (127.0.53.53) — fails as "connection closed", not NXDOMAIN. Fix: dokku
     network sandmill-net with initial-network on both apps
     (attach-post-deploy silently does not fire for proxy-disabled apps on
     0.37.3). backup-snapshot now captures network/proxy/docker-options per
     app on both hosts.
   Verified after fixes: irc 6667 open externally, bot joined #sandmill,
   external 6667 + all https endpoints green with old droplet OFF.
   THIRD smoke-test find (owner noticed the Mac OS 8 VM's IRC client dead):
   **sandmill-relay was MIS-RETIRED** — it is NOT the legacy path. The
   current virtual-gateway sends HTTP via WebOne but relays raw-TCP port
   6667 as wss://relay.sandmill.org/relay?host=irc.sandmill.org&port=6667
   (JSVirtualGateway.ts port→relay map; index.js allowlists exactly that
   target). It actually broke at DNS CUTOVER (wildcard moved relay.* to a
   host with no app), masked until the VM was exercised. Restored same day:
   conf added back, git push deploy, TLS issued; verified WebSocket 101 →
   relay log "ESTABLISHED irc.sandmill.org:6667". Only fedcm-rp and
   virtual-ethernet-switch stay retired. Lesson recorded in infra README:
   "part of the old path" is not evidence — trace the callers.
   Remaining: doctl compute droplet delete sandmill.org once the owner is
   confident — this also destroys the identity rollback apps, closing
   "next" step 2. Then update this bean to completed.
   (TTLs already restored to Automatic by owner, 2026-08-27.)

## Backup gotchas found by testing the SCHEDULED path (not just manual)
launchd runs with a minimal PATH (no Homebrew -> age missing) and NO ssh-agent; the admin RSA key exists only in the agent, not on disk. Both are now explicit in the script. A backup that only works when run by hand is not a backup.

Still open: backups live only on the mini. A second, genuinely offsite copy (B2/S3 via rclone) is worth adding — as is putting the age private key in the password manager.

## www CI (2026-08-06)
.github/workflows/deploy-www.yml added: builds marketing/ -> ghcr.io/vthunder/browserid-ng/www, releases via git:from-image, replacing the `git subtree push --prefix marketing` deploy. www was the last identity-host app without a reproducible image build.

NOT YET GREEN — CAUSE CONFIRMED EXTERNAL: a GitHub Actions partial outage (critical incident, 2026-08-06 ~16:20Z, confirmed on githubstatus.com). Three runs failed with three different platform errors: (1) GHCR secondary rate limit tagging :latest, (2) docker/login-action timeout to ghcr.io, (3) "Failed to resolve action download info. Service Unavailable" — a Set-up-job failure before any workflow step runs, i.e. Actions could not fetch actions/checkout. Nothing to fix here; re-dispatch once the incident clears. Original notes below, neither structural — run 1 built and pushed the sha-tagged manifest fine, then hit a GitHub SECONDARY RATE LIMIT tagging :latest; run 2 timed out in docker/login-action reaching ghcr.io. The workflow config is validated (YAML parses; context=marketing, file=marketing/Dockerfile — the Dockerfile COPYs by relative path so the repo root will NOT work).

CORRECTION: package visibility was never a blocker. A package published by Actions from a PUBLIC repo inherits that visibility — ghcr.io/vthunder/browserid-ng/www was anonymously pullable minutes after its first push, as were all the others. The claim that it needs a manual step was wrong and had been copied into deploy-broker/wallet/guestbook headers too; all four corrected.

The guestbook escaping fix was shipped meanwhile via the old subtree push (www e0842ea) so it did not wait on GHCR; verified live.

## www CI green (2026-08-07)
Run 31143436642 succeeded end to end once the GitHub Actions incident cleared — build, push, and the git:from-image deploy. www now reports `Git source image: ghcr.io/vthunder/browserid-ng/www:cc8aa569`, so EVERY identity-host app is released from a pinned CI image and the host builds none of them. Site healthy; the guestbook escaping fix is live.

Remaining host-builder: `sandmill` (git push deploy). Each of its deploys leaves a ~1.3GB dangling image — three deploys on 2026-08-06 pushed the disk 65% -> 73%; pruning dangling images + build cache recovered it to 58% (9.8G free). Giving sandmill the same CI-image treatment would stop the leak.

## Stage 3 status (2026-08-07)
Everything is ready except the droplet itself. Remaining: create it, run provision-host.sh, apply-apps.sh, restore-state.sh, then explicit A records per hostname (the *.browserid.me wildcard will keep pointing at the OLD ip until overridden). The *.at.browserid.me wildcard cert needs DNS-01, not HTTP-01 — bsky-pds.conf is marked LETSENCRYPT=no for that reason.

NOT yet verified end to end: provision-host.sh and restore-state.sh have never run against a real target — the first true test is the new droplet. apply-apps.sh has.

## Cutover checklist (not yet started)
1. Lower TTLs to 60 at Namecheap a day ahead (currently ~1800).
2. Take a FINAL backup immediately before flipping — the restore used the 03:20 snapshot, so anything written to production since then is not on the new host.
3. Add EXPLICIT A records per hostname -> 159.89.230.185. The *.browserid.me wildcard still points at the old IP and will keep answering for anything without its own record.
4. Flip least-critical first (www, guestbook-mcp), browserid.me LAST — it is the accepted fallback for other domains, so its downtime is ecosystem-wide.
5. After each hostname resolves: run apply-apps WITHOUT SKIP_TLS to issue certs (TLS is deliberately unissued right now).
6. *.at.browserid.me needs DNS-01, not HTTP-01 (bsky-pds.conf is LETSENCRYPT=no) — reuse the deSEC alias runbook in browserid-bsky.
7. Point the backup job at the new host once it is authoritative.

## Remaining after cutover
- [x] bsky-pds SAN cert issued on id-host (acme.sh + deSEC alias DNS-01), covering *.at.browserid.me + pds.bsky.browserid.me. Renewal wired via persisted reloadcmd -> deploy-bsky-pds.sh; next renewal by 2026-10-07. Verified: PDS health 200, claude.at.browserid.me -> its DID over a valid cert, unknown handle 404s.
- [x] Backup job now covers BOTH hosts via the same forced-command path (~/bin/sandmill-backup.sh, launchd 03:20 daily, keeps 14 per host). Verified in a clean env with no agent: id-host 132K / sandmill 2.0M, both decrypt, id-host carries broker-key.json + the PDS PLC rotation key. The job rejects any artifact that is not age ciphertext, so a host-side error cannot be stored as a successful backup.
- [x] acme.sh DNS-01 issuance folded into provisioning (bin/issue-dns01-cert.sh, driven by TLS_DNS01_DOMAINS in apps/bsky-pds.conf; deSEC token in secrets/acme-desec.env.age). A rebuild now gets the PDS wildcard cert automatically; re-running is a verified no-op.
- [x] Migrated apps STOPPED on the old host 2026-08-07 (id, www, guestbook-mcp, browserid-wallet, bsky-bridge, bsky-pds). Data left in place — the old host is still the rollback path, so do NOT destroy it yet. Hobby apps unaffected and verified.
- [ ] Decommission the old host once confident (after the hobby rebuild).
- Hobby host rebuild from the same scripts (stage 5).

## 2026-08-08 post-migration gap found (via browserid-ng deploy)

A browserid-ng push deployed via CI while DOKKU_HOST still said sandmill.org: the release went to the OLD host's stopped rollback apps and RESTARTED id + browserid-wallet there (production browserid.me was untouched and stale). Fixed in-session:
- Deployed 12e2129 manually: ssh dokku@browserid.me git:from-image id/browserid-wallet <ghcr image:sha> (mini-ops key).
- Re-stopped id + browserid-wallet on sandmill.org (rollback state restored).
- Set the browserid-ng repo variable DOKKU_HOST=browserid.me.

REMAINING (needs laptop-admin/root): the id-host dokku user authorizes only laptop-admin + mini-ops — no CI deploy key. Until one is added (per-repo key per infra README: authorize on id-host dokku user + commit pubkey to keys/dokku/ + set browserid-ng secret DOKKU_SSH_KEY), every browserid-ng CI deploy fails loudly at the ssh step and needs the manual git:from-image fallback. Same will apply to deploy-www / deploy-guestbook / bsky-bridge CI if they target the id-host.

**Audit note 2026-08-27:** identity host migration done (all identity apps on id-host with sandmill-infra confs; per-repo CI deploy keys landed via o7ip/4e2c061; hosted IdP shipped via g5qt). Moved to todo because what remains is exactly: (1) Stage 5 hobby-host rebuild — not started, sandmill.org still on the original droplet; (2) decommission the old host (blocked on stage 5); (3) retire the sandmill Laravel IdP.
