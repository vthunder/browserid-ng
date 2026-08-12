---
# browserid-ng-vaf3
title: 'M5: SaaS framing — same middleware, bigger knobs (no new code)'
status: todo
type: task
priority: normal
created_at: 2026-08-12T12:21:46Z
updated_at: 2026-08-12T12:21:55Z
parent: browserid-ng-81s6
---

Write the up-market story: mcp-auth is the same product a small SaaS drops in to expose its own data to agents without building an OAuth AS + refresh-token vault. Design-partner profile = the OAuth-less long tail (B2B tools/internal platforms without public OAuth), NOT mature SaaS with good OAuth. The org-governance angle (managed identities: employer controls where identities work, caps grant lifetimes, org-wide revoke) is what pulls mature SaaS later. Parent epic browserid-ng-81s6.
