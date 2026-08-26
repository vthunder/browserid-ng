---
# browserid-ng-992k
title: 'Remove the /verify-access alias entirely (decision superseded: no permanent alias)'
status: in-progress
type: task
priority: normal
created_at: 2026-08-26T08:28:47Z
updated_at: 2026-08-26T08:40:50Z
---

Dan, 2026-08-26: now that every repo and all current package versions call /verify, remove the /verify-access alias — supersedes the 2026-08-25 'permanent alias' decision on 44jm. Old package versions that default to /verify-access get registry deprecation notices.

- [x] broker: remove the alias route; /verify-access → structured JSON 404
- [x] tests: alias test → 404 assertion (test_verify_access_is_retired); loops/openapi assertions updated; all 63 suites green
- [x] openapi.json (broker + marketing copies): remove the /verify-access path
- [x] docs: quickstart + spec + design note + broker-demo.html (missed by the original sweep — still POSTed the alias) + include.js/route comments
- [x] deploy + verify prod: /verify answers, /verify-access is the structured JSON 404, openapi live without the alias
- [ ] npm deprecate all old versions that default to /verify-access (BLOCKED on Dan's OTP — 2FA; commands delivered 2026-08-26)
- [ ] PyPI: yank browserid-mcp-auth 0.1.0 (needs Dan's PyPI auth)
