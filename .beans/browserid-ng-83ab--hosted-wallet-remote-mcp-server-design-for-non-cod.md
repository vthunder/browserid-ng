---
# browserid-ng-83ab
title: 'Hosted wallet: remote MCP server design for non-code agents'
status: completed
type: feature
priority: normal
created_at: 2026-07-29T08:28:34Z
updated_at: 2026-07-29T08:31:29Z
---

Design doc for a hosted wallet service exposed as a remote (streamable-HTTP) MCP server so agents that cannot execute code (claude.ai web, mobile) can hold a browserid agent identity.

Key decisions from discussion (2026-07-29):
- Hosted wallet = just another agent device; holds only authentication-purpose material (agent device key, device cert, warrants). Config cert stays client-side; warrants still signed at the consent page — wallet compromise cannot mint new grants.
- Tenant binding via OAuth per MCP connector spec; wallet service is itself a browserid RP (dogfood login).
- Per-tenant Ed25519 keys, KMS envelope-encrypted, sign-only internal interface. No user-password unlock (password would transit model context; headless ops; off-brand).
- Audit log of every mint/assertion — improvement over local wallet.
- Positioned as explicit tier vs local wallet; separate service/keys from broker to preserve 'no single party can fabricate an authorization'.

- [x] Write design doc (tenancy model, OAuth flow, key custody/KMS shape) in docs/plans/

## Summary of Changes

Wrote docs/plans/2026-07-29-hosted-wallet-remote-mcp-design.md: hosted wallet at wallet.browserid.me as an MCP streamable-HTTP server (OAuth 2.1 RS with embedded minimal AS; browserid sign-in as the authorize step; PKCE S256, RFC 9728/8414/8707/9207, CIMD + DCR + pre-registered clients). Tenancy: wallet account = browserid identity, one default agent identity, keyed for named agents later. Custody: per-tenant Ed25519 seeds envelope-encrypted, KEK outside DB (env secret now, KeyWrapper seam for KMS), sign-only interface; password-unlock explicitly rejected. Audit log, threat-model delta table, tier repositioning of the 'never holds the key' claim, MVP cut (new wallet-service/ Node dir reusing sdk/agent), open questions (connector distribution, rate limits, transport variant, elicitation). OAuth section reconciled against MCP 2026-07-28 spec RC + claude.ai custom-connector docs. Implementation not started — follow-up beans when the MVP is picked up.
