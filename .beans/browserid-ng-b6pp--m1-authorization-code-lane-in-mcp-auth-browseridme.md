---
# browserid-ng-b6pp
title: 'M1: authorization-code lane in mcp-auth + browserid.me approval-return endpoint'
status: todo
type: feature
priority: high
created_at: 2026-08-12T12:21:46Z
updated_at: 2026-08-12T13:10:26Z
parent: browserid-ng-81s6
---

THE critical path. mcp-auth today advertises only grant_types_supported:[jwt-bearer], no authorization_endpoint, no DCR — a generic host (claude.ai) can't do the paste-URL-approve-done flow. Add: discovery fields (authorization_endpoint, authorization_code grant, S256 PKCE); Dynamic Client Registration (RFC 7591, POST /register); GET /authorize (PKCE, redirects browser to a browserid.me warrant-approval page carrying audience=resource + scopes + return_url); POST /token authorization_code grant (verify PKCE, redeem code for the approved warrant, mint the same fail-closed bearer as Lane A). On browserid.me: a browser warrant-approval-with-return_url endpoint reusing the existing consent UI + keystore signing. Grantee model: start (A) gateway-as-agent (gateway provisions one identity; warrants name it grantee, connecting human grantor), design toward (C) warrant-to-holder-key. Prove headless via curl: discover→register→authorize→code→token→gated tools/call. Parent epic browserid-ng-81s6.

DECISION 2026-08-12: grantee model is A now, B eventually, SKIP C. C lets the connecting human self-revoke their own sub-agents but leaves the OWNER blind (opaque holders); B gives owner-meaningful named sub-identities (friend+claude@…) reusing the managed-agent path hardened today. Keep the warrant status ref per-warrant (per grantor) so A→B is additive.
