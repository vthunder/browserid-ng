---
# browserid-ng-o7ip
title: Authorize a browserid-ng CI deploy key on the id-host
status: completed
type: task
priority: high
created_at: 2026-08-08T16:55:14Z
updated_at: 2026-08-11T17:43:24Z
parent: browserid-ng-gzq7
---

Since the host split, browserid-ng CI cannot release to production: the id-host (browserid.me, 159.89.230.185) dokku user authorizes only laptop-admin + mini-ops, and the repo's DOKKU_SSH_KEY secret is the OLD host's deploy key. DOKKU_HOST was fixed to browserid.me on 2026-08-08, so every CI deploy now fails loudly at the ssh step. Interim: manual `ssh dokku@browserid.me git:from-image id ghcr.io/vthunder/browserid-ng/broker:<full-sha>` (wallet: app browserid-wallet, image .../wallet:<sha>) with the mini-ops key.

Needs the laptop (laptop-admin key = root on the id-host). Per sandmill-infra README: per-repo key, dokku-only, never on a sudo-capable account.

- [ ] Mint a fresh keypair for browserid-ng CI (do NOT reuse the old host's key)
- [ ] Authorize the pubkey on the id-host dokku user (root via laptop-admin; e.g. dokku ssh-keys:add browserid-ng-ci)
- [ ] Commit the pubkey to sandmill-infra keys/dokku/ (layout IS the authorization model; bin/audit-host.sh must pass afterward)
- [ ] Update the browserid-ng repo secret DOKKU_SSH_KEY with the new private key
- [ ] Re-run a deploy workflow (or push) and verify the change actually lands on browserid.me — CI 'success' alone is not proof
- [ ] Check whether deploy-www / deploy-guestbook (and browserid-bsky CI, if it deploys to the id-host) need the same key or their own per-repo keys

## Summary of Changes
Root cause: the DOKKU_SSH_KEY secrets held keys authorized on the HOBBY host
(sandmill.org), never the id-host. Fixed with per-repo CI deploy keys
(browserid-ng-ci / browserid-bsky-ci / mingo-ci): dokku-user-only, declared in
sandmill-infra keys/dokku (commit 4e2c061), authorized on both hosts, private
halves only in each repo's GitHub secret. bsky DOKKU_HOST var corrected to
browserid.me. All deploy workflows now tolerate the from-image
No-changes-detected no-op. Validated: mingo CI deployed end-to-end from image
(git source image ghcr.io/vthunder/mingo:1cd4b6e); browserid-ng release step
authenticated on rerun.
