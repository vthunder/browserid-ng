---
# browserid-ng-992k
title: 'Remove the /verify-access alias entirely (decision superseded: no permanent alias)'
status: in-progress
type: task
created_at: 2026-08-26T08:28:47Z
updated_at: 2026-08-26T08:28:47Z
---

Dan, 2026-08-26: now that every repo and all current package versions call /verify, remove the /verify-access alias — supersedes the 2026-08-25 'permanent alias' decision on 44jm. Old package versions that default to /verify-access get registry deprecation notices.

- [ ] broker: remove the alias route; /verify-access → structured JSON 404
- [ ] tests: alias test → 404 assertion; drop /verify-access from path loops + openapi assertions
- [ ] openapi.json (broker + marketing copies): remove the /verify-access path
- [ ] docs: quickstart + spec + any remaining live mentions
- [ ] deploy + verify prod (/verify 200-shape, /verify-access 404)
- [ ] npm deprecate all old versions that default to /verify-access
- [ ] PyPI: yank browserid-mcp-auth 0.1.0 (needs Dan's PyPI auth)
