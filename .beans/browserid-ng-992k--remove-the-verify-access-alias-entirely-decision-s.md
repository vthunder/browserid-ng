---
# browserid-ng-992k
title: 'Remove the /verify-access alias entirely (decision superseded: no permanent alias)'
status: completed
type: task
priority: normal
created_at: 2026-08-26T08:28:47Z
updated_at: 2026-08-26T08:45:54Z
---

Dan, 2026-08-26: now that every repo and all current package versions call /verify, remove the /verify-access alias — supersedes the 2026-08-25 'permanent alias' decision on 44jm. Old package versions that default to /verify-access get registry deprecation notices.

- [x] broker: remove the alias route; /verify-access → structured JSON 404
- [x] tests: alias test → 404 assertion (test_verify_access_is_retired); loops/openapi assertions updated; all 63 suites green
- [x] openapi.json (broker + marketing copies): remove the /verify-access path
- [x] docs: quickstart + spec + design note + broker-demo.html (missed by the original sweep — still POSTed the alias) + include.js/route comments
- [x] deploy + verify prod: /verify answers, /verify-access is the structured JSON 404, openapi live without the alias
- [x] npm deprecate all old versions that default to /verify-access (Dan ran the commands; verified across all 9 packages, ranges reach older versions, current versions clean)
- [x] PyPI: browserid-mcp-auth 0.1.0 yanked (verified; 0.1.1 unaffected)

## Summary of Changes

Completed 2026-08-26. The /verify-access alias is fully retired: broker route removed (structured JSON 404, pinned by test_verify_access_is_retired), openapi.json (both origins) no longer documents it (asserted by test), docs (quickstart/spec/design) cleaned, and broker-demo.html — missed by the original 44jm sweep, still POSTing the alias — fixed. Deployed and verified on prod: /verify answers, /verify-access 404s with the docs pointer. Registry cleanup verified: all old npm versions defaulting to the removed endpoint carry deprecation notices (verify<0.3.1, express/fastify/hono/nextauth<0.2.1, gate<0.10.3, mcp-auth<0.5.3, wallet<0.4.7, bsky<0.2.1; current versions clean) and PyPI browserid-mcp-auth 0.1.0 is yanked. Supersedes the 2026-08-25 permanent-alias decision on 44jm (noted there).
