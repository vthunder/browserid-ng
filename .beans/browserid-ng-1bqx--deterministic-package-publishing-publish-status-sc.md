---
# browserid-ng-1bqx
title: 'Deterministic package publishing: publish-status script + CI drift gate + auto-publish on version bump'
status: in-progress
type: task
priority: normal
created_at: 2026-08-26T06:51:28Z
updated_at: 2026-08-26T07:22:59Z
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
- [x] publish.yml workflow written; [ ] Dan: configure npm/PyPI trusted publishing (instructions delivered 2026-08-26)
- [ ] document the flow in sdk/README (bump-in-PR convention)
- Depends on bean 2nay only cosmetically (dir names in the table); no ordering constraint.
- wallet-service file:-dep migration stays bean bf47; once auto-publish exists it gets easier.

## npm scope inventory note (2026-08-26)

The @browserid-ng scope has 10 packages, not 9: the 9 in this repo's sdk/ plus **@browserid-ng/bsky** (0.2.0), which is built from ~/src/browserid-bsky/agent-cli — a different repo. The publish-status oracle here intentionally covers only this repo's sdk/. If a vthunder/browserid-ng trusted publisher was added to @browserid-ng/bsky, it should be repointed at the browserid-bsky repo (which needs its own small publish workflow) or removed until one exists.

- [ ] browserid-bsky repo: add its own publish workflow + trusted publisher for @browserid-ng/bsky (or remove the misconfigured one)
