---
# browserid-ng-1bqx
title: 'Deterministic package publishing: publish-status script + CI drift gate + auto-publish on version bump'
status: completed
type: task
priority: normal
created_at: 2026-08-26T06:51:28Z
updated_at: 2026-08-26T07:41:23Z
---

Yesterday's failure mode (2026-08-26): package content changed (/verify default) without version bumps, so 'for i in *; do npm publish; done' silently no-op'd on gate + mcp-auth (registry already had those versions with OLD code), and nobody could tell what actually needed publishing without hand-diffing npm. Fix by making publish state derivable and enforced:

## 1. scripts/publish-status.mjs (source of truth)
For every publishable package (sdk/* with package.json, sdk/python-mcp-auth via pyproject):
- registry version (npm view / PyPI JSON) vs local version
- when versions are EQUAL: content-drift check — npm pack the local dir, download the registry tarball, extract both, diff file trees (robust against tar metadata; npm pack itself is deterministic)
- output one table: OK / NEEDS PUBLISH (local ahead) / NEEDS BUMP (drift at same version) / AHEAD-UNPUBLISHED
- exit nonzero if anything is NEEDS BUMP
- make publish-status target

## 2. CI drift gate
Run publish-status in the existing sdk-tests workflow on every push to main. NEEDS BUMP fails the job — a PR that changes shipped package content must carry its version bump. (NEEDS PUBLISH alone doesn't fail; it's resolved by the publisher below.)

## 3. Auto-publish from CI
New workflow on push to main: for each package where local version > registry, npm publish --provenance --access public via npm trusted publishing (OIDC — no NPM_TOKEN secret), and uv publish via PyPI trusted publishing for the python package. Publishing then == merging a version bump; no local npm auth, no loops, no ordering mistakes.

## Notes
- [x] script + make target (scripts/publish-status.mjs, make publish-status)
- [x] wire into sdk-tests.yml (gate on drift)
- [x] publish.yml workflow + npm/PyPI trusted publishing configured and PROVEN (CI published @browserid-ng/wallet 0.4.6 via OIDC, no token; pypi job green)
- [x] document the flow in sdk/README (bump-in-PR convention)
- Depends on bean 2nay only cosmetically (dir names in the table); no ordering constraint.
- wallet-service file:-dep migration stays bean bf47; once auto-publish exists it gets easier.

## npm scope inventory note (2026-08-26)

The @browserid-ng scope has 10 packages, not 9: the 9 in this repo's sdk/ plus **@browserid-ng/bsky** (0.2.0), which is built from ~/src/browserid-bsky/agent-cli — a different repo. The publish-status oracle here intentionally covers only this repo's sdk/. If a vthunder/browserid-ng trusted publisher was added to @browserid-ng/bsky, it should be repointed at the browserid-bsky repo (which needs its own small publish workflow) or removed until one exists.

- [x] browserid-bsky repo: own scripts/publish-status.mjs + publish.yml + make publish-status landed (d40d1ff); trusted publisher repointed at browserid-bsky by Dan; first run green

## Summary of Changes

Built 2026-08-26 and proven end-to-end. scripts/publish-status.mjs (make publish-status) derives publish state — version vs registry plus a tarball content diff at equal versions; statuses OK / NEEDS PUBLISH / NEEDS BUMP / BEHIND. Wired as a drift gate into sdk-tests.yml (fails on NEEDS BUMP) and as the publisher in publish.yml (npm OIDC trusted publishing with --provenance; PyPI via pypa/gh-action-pypi-publish, environment pypi). First runs caught real facts: @browserid-ng/wallet README drift at 0.4.5 (bumped to 0.4.6, then auto-published by CI — the trusted-publishing proof), and wallet 0.4.6 missed by the manual publish loop. Same tooling replicated into browserid-bsky for @browserid-ng/bsky (npm-only). All 10 scope packages verified OK. Releasing is now: bump version, merge.
