---
# browserid-ng-t1jp
title: Requester can't express the intended relation — 'as itself' is unrequestable
status: completed
type: feature
priority: normal
created_at: 2026-07-25T23:12:41Z
updated_at: 2026-07-26T18:48:54Z
---

From the bsky.browserid.me friend test (2026-07-25). Grantor/grantee pins on RequestBody can fix IDENTITIES, but not the RELATION between them:

- grantee omitted/empty = as-you demanded (renders A5, the become-you danger card)
- grantee '*' = the approver chooses — on-behalf by default, standalone only via the human finding the A2 escape hatch
- there is NO way to request 'the agent should act as itself' (grantor == grantee == a to-be-minted identity), because the grantor pin can't reference an identity that doesn't exist until approval. There is also no way to require on-behalf ('I need the human as the authority — fail early if they won't').

Dan hit this live: the bsky agent-cli wanted 'act for me, or as itself' and could only get there by omitting grantee, which reads as demanding his bare identity.

Proposal sketch: a relation field on the request — e.g. relation: 'onbehalf' | 'standalone' | 'self' | 'any' (default 'any' = today's grantee semantics decide) — that the approval page uses to pick/lock the default card, refusing early when unsatisfiable, same pin-honouring rules as A3/A4. Alternatively a grantor sentinel meaning 'same as the minted grantee'. Relates to the design board's side quest #3 (grantor/grantee pins on consent requests) and #2 (attribution expectation enum on grants); complements k0s9 which made the cards honest about what a request DOES express.

## Live use case (2026-07-25, bsky friend test)

The bsky bridge's /browserid/provision 409s on-behalf creation whenever the grantor's email already owns an account — so a returning human MUST take the as-itself path, and today the agent can't open the approval on it; the human has to find the A1 escape hatch every time. The @browserid-ng/bsky CLI wants to request relation=standalone (or ask the human first and pin the chosen relation). Raising interest: Dan asked for this directly.

## Resolution shape (2026-07-26, aligned with Dan)

Superseded sketch: no separate 'relation' field. Fold everything into ONE grantor field, present on BOTH request bodies (RequestBody on /agent-provision/request and WarrantRequestBody on /warrant/request):

- absent (or '*') → approver chooses via dropdown; default = on-behalf of their matching identity (surface B may seed from the established relation)
- '<email>' → PINNED to that account; rendered as text, approve/deny only; approver who doesn't own it → refuse with reason (A4 semantics, now on both surfaces)
- 'self' → PINNED to the agent itself (grantor == grantee). Sentinel needed because a bundled request's agent address doesn't exist until I2; on surface B naming the agent's own email is equivalent.
- No 'prefer' dimension — pins for requirements, dropdown for choice. Additive later if a real case appears.
- The dropdown NEVER offers 'as me' — as-you stays an identity-flow demand (empty grantee); as-you + grantor pin = contradictory → invalid screen (grantor pin equal to the same bare root remains OK, as today's A5-locked case).

This dissolves the original hard case: in Flow P the grantee always exists, so grantor==grantee is just a value.

Scope of THIS bean (protocol only; UI lands with the v2 flows bean):
- [x] registrar: WarrantRequestBody gains grantor (absent | email | 'self') — stored on the pending request, exposed via /wsapi/warrant_requests, honored at respond (pin → only that grantor accepted; validation reuses the k0s9 RespondBody.grantor gate)
- [x] registrar: RequestBody grantor accepts 'self' sentinel; contradiction checks (as-you demand vs grantor pin) fail the request up front with a machine reason
- [x] SDKs (sdk/agent device.mjs requestWarrants + browserid-agent request_provision): pass-through grantor param + doc the sentinel semantics (rust SDK has no warrant-only call; request_provision gained a grantor arg)
- [x] registrar unit tests pinning the decision table (norm/pin-enforcement/contradiction/mode-composition; sqlite migration v19 adds warrant_requests.grantor)

## Summary of Changes

Implemented as the aligned single-field shape. `grantor` on BOTH request bodies: absent/'*' = approver's choice (dropdown on the P card); a concrete email = pinned, approve/deny only, refused (never substituted) when unsatisfiable; 'self' = pinned to the agent itself. On /warrant/request the pin normalizes immediately ('self' → the agent identity, which exists there), an unsatisfiable pin fails the REQUEST with a machine reason instead of expiring, and respond() refuses a substituted grantor. On /agent-provision/request 'self' survives as a sentinel (the grantee doesn't exist until approval), forces the standalone warrant shape at complete regardless of identity_mode, is contradictory with an as-you demand (refused up front) and with a foreign grantee (refused at approval). Registrar unit tests pin the normalization/enforcement/composition tables; broker integration test agent_flows_v2_test.rs exercises the pin over HTTP. Storage: warrant_requests.grantor (broker sqlite migration v19, default '*'). SDKs pass grantor through (js requestProvision/requestWarrants; rust request_provision) with the sentinel documented. Spec §6.2 updated.
