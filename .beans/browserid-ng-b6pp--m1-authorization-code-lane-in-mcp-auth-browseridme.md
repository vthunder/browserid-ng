---
# browserid-ng-b6pp
title: 'M1: authorization-code lane in mcp-auth + browserid.me approval-return endpoint'
status: todo
type: feature
priority: high
created_at: 2026-08-12T12:21:46Z
updated_at: 2026-08-12T13:32:24Z
parent: browserid-ng-81s6
---

THE critical path. mcp-auth today advertises only grant_types_supported:[jwt-bearer], no authorization_endpoint, no DCR — a generic host (claude.ai) can't do the paste-URL-approve-done flow. Add: discovery fields (authorization_endpoint, authorization_code grant, S256 PKCE); Dynamic Client Registration (RFC 7591, POST /register); GET /authorize (PKCE, redirects browser to a browserid.me warrant-approval page carrying audience=resource + scopes + return_url); POST /token authorization_code grant (verify PKCE, redeem code for the approved warrant, mint the same fail-closed bearer as Lane A). On browserid.me: a browser warrant-approval-with-return_url endpoint reusing the existing consent UI + keystore signing. Grantee model: start (A) gateway-as-agent (gateway provisions one identity; warrants name it grantee, connecting human grantor), design toward (C) warrant-to-holder-key. Prove headless via curl: discover→register→authorize→code→token→gated tools/call. Parent epic browserid-ng-81s6.

DECISION 2026-08-12: grantee model is A now, B eventually, SKIP C. C lets the connecting human self-revoke their own sub-agents but leaves the OWNER blind (opaque holders); B gives owner-meaningful named sub-identities (friend+claude@…) reusing the managed-agent path hardened today. Keep the warrant status ref per-warrant (per grantor) so A→B is additive.

## M1 mechanism (verified 2026-08-12 against consent.rs)
Lane B = wrap the EXISTING §6.6 external warrant-request + RFC-8628 poll in an OAuth shell. The gateway authenticates to POST /warrant/request with its own agent device cert, gets /consent/<code>, human approves in-browser (picks which identity delegates), gateway picks up warrant~config_cert via POST /warrant/poll. The ONE new broker piece: an origin-validated optional return_url on /consent so the browser redirects back to the gateway after approval (bridges OAuth-redirect ↔ browserid device-flow; the gateway still polls for the warrant as source of truth). /authorize orchestration + the gateway's DeviceAgent identity live in mcp-auth's new auth-code lane (mcp-auth gains an optional warrant-requesting client role; today it only verifies).

Build spec written: docs/plans/2026-08-12-M1-authcode-build-spec.md (module design: mcp-auth optional auth-code lane embedding a DeviceAgent; discovery/DCR/authorize/return/token signatures; broker return_url with origin validation; test plan; exit criteria).
