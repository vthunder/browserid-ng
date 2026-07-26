---
# browserid-ng-eywc
title: 'Agent flows v2: identity/permission split (Flow I / Flow P)'
status: completed
type: feature
priority: normal
created_at: 2026-07-26T17:38:07Z
updated_at: 2026-07-26T18:48:54Z
blocked_by:
    - browserid-ng-t1jp
---

Implement the design board 'Agent flows v2.dc.html' (claude.ai/design project 83819192): unbundle identity creation from permission granting. Flow I (account.html, /agent-provision/*) creates an agent identity and ends in a certificate — the fingerprint check becomes its own step (I1), name+address its own step (I2, both fields user-confirmed), and the word 'permission' first appears on the done screen (I3) only to say there are none yet. Flow P (consent.html, /warrant/request) grants permission to a KNOWN agent — no fingerprint, card opens with the user-chosen name, on-behalf is a dropdown (agent itself | any owned identity) unless the request pins grantor (then text, approve/deny only). As-you stays an identity-flow demand (I4); 'act as me' is never offered in the P dropdown.

Aligned decisions (2026-07-26):
- Bundled requests stay ONE call: /agent-provision/request with grants renders serially — I screens mint the identity, then the same code continues into P screens; I3 variant says permissions are next, button 'View permission request'. Poll delivers credential + grants together at the end. Requires two-stage completion in the registrar (identity stage mints the cert, grants stage records warrants; abandoning at P leaves an honest identity-without-permissions).
- Identity-only (grants: []) and warrant-only (/warrant/request) remain first-class.
- grantor relation field per bean t1jp (blocker).
- display_name lives server-side on the agent identity record: seeded from the requester's suggestion, confirmed at I2, editable from the account page; exposed with created_at + known flag on /wsapi/warrant_requests so P cards open with the trustworthy who.
- Unknown-agent guardrail only, no rathole: known = agents list ∪ device-cert registry; unknown renders deny-only P4; denied poll gains reason 'unknown_agent'.
- Agent message: request bodies gain optional message (shown as 'Agent message (unverified)', 'None given' when absent); label remains the name suggestion on provision requests.
- TTL copy says fifteen minutes (stores already use 15).

Todos:
- [x] registrar: two-stage complete (identity stage → cert minted, status IdentityIssued; grants stage → warrants; deny-at-P delivers credential with empty grants + grants_denied reason; poll slow-down now applies only while deciding, resolved delivers immediately like the consent flow)
- [x] registrar: display_name (complete body + host.set_agent_display_name), broker emails.display_name + warrant_requests.message via migration v20 (v19 = grantor, t1jp)
- [x] registrar: /wsapi/warrant_requests enriched with display_name, agent_created_at, known, grantor, message (host.known_agent = owned email ∪ device-cert registry); /warrant/poll denied reason unknown_agent
- [x] broker: account.html Flow I screens (I0 gate, I1 fingerprint step, I2 name+address, I3/I3b done, I4 as-you, I5 stopped) + serial P continuation (perm view: who/message/chips/on-behalf dropdown honoring pins) + identity_issued resume; A2 standalone escape hatch removed (relation lives in Flow P); foreign/pinmismatch/invalid kept
- [x] broker: consent.html Flow P cards (P1 common, P2 no-message, P4 unknown deny-only, P5 nothing waiting; B2/B3 kept as branches) with grantor dropdown/pin rendering, dropdown default from established relation
- [x] broker: INLINE_SCRIPT_HASHES for both pages (guard test green). Agent-name rename surface split to a follow-up bean
- [x] SDKs: message param (js + rust), grantor pass-through, grants_denied + denial reasons surfaced in polls; type decls + docs
- [x] tests: registrar units + broker integration agent_flows_v2_test.rs (pin/unknown_agent/two-stage/decline), broker CSP guard, e2e paired-provisioning spec updated to I1→I2→I3
- [x] docs/specs/agent-provisioning-and-grant-api.md: §6.2 grantor+message, §6.3 known-agent gate + display name, §6.4 denied reason, new §6.5 two-stage approval

## Summary of Changes

Implemented 'Agent flows v2.dc.html' end to end; all todos above completed. Highlights beyond the todo list:
- Two-stage complete under one code (stage: identity | grants; absent = legacy single-shot kept for SDK-driven approvals), Status::IdentityIssued in the in-process store, info exposes stage/agent_email/holder/status_uri so a reloaded page resumes at the permission screen, poll slow-down only applies while deciding.
- account.html: check/name/done/perm views replace main/standalone; A2's escape hatch removed (relation is the P screen's dropdown now); as-you (I4) is permission-free with the offer-an-address default; I3 branches (grant-less done / 'View permission request' / grants-declined) all honest about what exists.
- consent.html: P cards open with display_name + created date from /wsapi/warrant_requests (known flag; deny-only P4 for strangers, poll reason unknown_agent), message quoted under an unverified label, on-behalf dropdown defaults to the established relation.
- Verified: full cargo workspace green (incl. new agent_flows_v2_test.rs, 3 tests); JS SDK 18/18; CSP guard green; Playwright live runs — deny path (I1 stop → 'Nothing was created') and the full bundled serial flow (I1→I2 seeded name→I3 Meet→P message/chips/dropdown→Allow→single pickup with credential+warrant) both pass; the identity-only approve spec still ends at the pre-existing legacy-SDK credential drift (bean tnwb, unrelated).
- Deferred: agent-name rename surface → bean oenx.
