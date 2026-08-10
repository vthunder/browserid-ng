---
# browserid-ng-p1wm
title: 'RP adapters: @browserid-ng/hono + @browserid-ng/fastify (edge + Node)'
status: completed
type: feature
created_at: 2026-08-10T07:33:28Z
updated_at: 2026-08-10T07:33:28Z
---

Built 2026-08-10 (commit d982c74), siblings of NextAuth (bla3) + Express (86k5). @browserid-ng/hono (Workers/Bun/Deno/Node middleware, 6 tests) + @browserid-ng/fastify (preHandler hook, 5 tests). Both: verifyBrowserID core + browseridLogin + browseridSessionValid over @browserid-ng/verify, audience-pinned, fail-closed, humans-only. NextAuth+Express+Hono+Fastify now cover the dominant JS server frameworks. Deferred: Remix/SvelteKit (loader/hooks-based, thinner value); npm publish.
