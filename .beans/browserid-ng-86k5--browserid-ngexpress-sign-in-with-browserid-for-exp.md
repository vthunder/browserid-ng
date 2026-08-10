---
# browserid-ng-86k5
title: '@browserid-ng/express: Sign in with BrowserID for Express (Passport + middleware)'
status: completed
type: feature
created_at: 2026-08-10T06:09:48Z
updated_at: 2026-08-10T06:09:48Z
---

Built 2026-08-10 (commit 270ce85), sibling of the NextAuth adapter (bla3). sdk/express: a Passport-compatible Strategy (no passport dep) + browseridLogin() middleware + verifyBrowserID() + browseridSessionValid(), verifying at hosted /verify-access via @browserid-ng/verify (fail-closed, audience-pinned, humans-only). 7 unit tests + index.d.ts + README + sdk-tests CI. Library. Deferred: Remix/SvelteKit adapters off the same core; npm publish.
