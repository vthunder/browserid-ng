---
# browserid-ng-2nay
title: Rename sdk dirs to match published package names (sdk/js → sdk/verify, sdk/python-mcp-auth → sdk/browserid-mcp-auth)
status: todo
type: task
created_at: 2026-08-26T06:50:45Z
updated_at: 2026-08-26T06:50:45Z
---

Directory names and package names are hard to correlate (bit us on 2026-08-25/26: publish state was misjudged partly because sdk/js publishes as @browserid-ng/verify). Two mismatches:

- [ ] sdk/js → sdk/verify (@browserid-ng/verify)
- [ ] sdk/python-mcp-auth → sdk/browserid-mcp-auth (PyPI: browserid-mcp-auth)

Known reference sites to update (grep 'sdk/js|sdk/python-mcp-auth' at commit time):
- [ ] wallet-service/package.json (file:../sdk/js dep) + its package-lock
- [ ] .github/workflows/deploy-wallet.yml + deploy-python-mcp-demo.yml
- [ ] python-mcp-demo/Dockerfile (+ README)
- [ ] README.md (6 refs), examples/mcp-agent-auth/README.md, docs/verify-quickstart.md (../sdk/js link)
- [ ] any other file: deps in examples/, guestbook-mcp/, github-mcp/, mcp-demo/
- Leave dated docs/plans/* as historical record

Use git mv so history follows. Run sdk tests + affected deploy workflows after.
