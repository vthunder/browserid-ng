---
# browserid-ng-129z
title: 'Cleanup: merge holder branch; delete sandmill legacy auth views'
status: completed
type: task
priority: normal
created_at: 2026-07-21T21:02:32Z
updated_at: 2026-07-23T11:21:33Z
parent: browserid-ng-oup3
---

1) Merge browserid-ng holder-authorization-model -> main (prod deploys from the branch today). 2) sandmill: delete the dead classic /browserid/auth + auth-complete blade views (auth-complete loads the deleted authentication_api.js; nothing routes there since /account primary sign-in went through the dialog).

## Progress (2026-07-23)
- [x] Merge browserid-ng holder-authorization-model -> main: clean fast-forward (main was at merge-base, 51 commits ahead). main now == branch tip a51db66. NOT yet pushed to origin.
- [x] sandmill: deleted dead classic auth. Removed auth.blade.php + auth-complete.blade.php (auth-complete loaded broker authentication_api.js which no longer exists; auth.blade rendered by nothing). Removed the /browserid/auth route + auth() controller method + the 'authentication' entry in the .well-known discovery doc. Verified: broker has zero classic-authentication refs; php -l clean; no residual refs. Staged on sandmill master, uncommitted.

## Open deploy decisions (need Dan)
- Push browserid-ng main -> origin (ff, code already live from branch).
- sandmill commit + deploy: repo is on 'master' but dokku deploys from 'main' (per the known mis-deploy trap). Needs the right branch handling before it goes live on the primary IdP.

## Summary of Changes (2026-07-23)
Both tasks done and verified live.
1. browserid-ng holder-authorization-model -> main: clean fast-forward to a51db66, pushed origin.
2. sandmill classic-auth removal: deleted auth.blade + auth-complete.blade + /browserid/auth route + auth() method + .well-known 'authentication' entry. Renamed repo default master->main (origin HEAD repointed, origin master deleted; dokku deploy-branch set to main). Deployed to dokku main. VERIFIED live: sandmill.org/.well-known/browserid no longer lists 'authentication'; /browserid/auth returns 404.
Leftover (cosmetic): dokku bare-repo master branch/HEAD not deletable via the restricted dokku@ forced-command; harmless since app deploy-branch=main governs.
