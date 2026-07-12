---
# browserid-ng-74u1
title: Standardize agent identity provisioning (device-grant pairing flow)
status: todo
type: feature
priority: high
created_at: 2026-07-12T11:42:42Z
updated_at: 2026-07-12T14:58:58Z
---

Today the initial agent-credential handoff has no protocol: the user goes to browserid.me/agents, downloads a credential JSON (containing the provisioning PRIVATE key), and the wallet polls ~/Downloads to pick it up. Standardize it as a device-authorization-style pairing flow, mirroring the warrant consent flow (request -> verification_uri -> poll -> pickup).

## Recommended design (agent-generates-key; zero secret handoff)
1. Agent generates a provisioning keypair locally. POST {broker}/agent-provision/request { provisioning_pubkey, requested_handles? } -> { code, verification_uri, interval, expires_in }.
2. Agent surfaces verification_uri to the human (like a consent URL).
3. Human opens it (authenticated session), picks the delegating identity, reviews/edits handles, decides reissue vs new; their identity key signs the delegation (P_cert) over the AGENT-supplied provisioning public key; handles reserved (session-authenticated). Delegation stored against code.
4. Agent polls {broker}/agent-provision/poll { code } -> { delegation (U_cert~P_cert), broker, idp, names, patterns } when done; assembles the credential locally with its held private key.

Key property: the provisioning private key is born in the agent and NEVER transits browserid.me or a file. Browser + broker only ever see public keys + signed certs. Strictly better than the download flow (no private key in a file to move around) and true to no-keys-in-the-middle.

## Notes / decisions
- Reservation moves to a session-authenticated step at the verification page (preserves create-time handle locking without a provisioning-key-signed request). Fold the reissue/add/reuse UX (see analysis in-session) here.
- Reuse consent-flow machinery (code + verification_uri + poll + expiry/interval).
- The download-JSON path stays as an ADVANCED escape hatch, hidden from the normal flow.
- Alternative (rejected): browser generates the provisioning key and encrypts it to an agent-supplied ephemeral pubkey for relay. Works but reintroduces a key that leaves the browser; agent-generates is cleaner.

## Surfaces to build
- Broker: /agent-provision/request + /agent-provision/poll endpoints; store pending provisions keyed by code; session-authenticated reserve.
- A /agent-provision/<code> page (or fold into /agents): review + sign delegation over the supplied pubkey.
- @browserid/agent: bootstrap()/provisionInteractive() -> { verificationUri, ready: Promise<Agent> }.
- wallet MCP server: a provision tool (deletes the Downloads-discovery hack).
- Docs.

Design doc first (docs/plans), then implement. Relates to 0phq (agent domain).

## Decision: keep both modes (paired default; portable download advanced)

The real axis is deployment shape, not agent capability (any browserid-ng agent can sign → can keygen; 'can't generate a keypair' is a phantom for real agents):
- PAIRED provisioning (agent-initiated, key stays local): the default/prominent path for a present, interactive agent. Zero secret transit.
- PORTABLE credential (web-first download): keep it — needed for provision-here-deploy-there, headless/air-gapped, thin/non-SDK consumers, and batch pre-provisioning. It inherently contains the provisioning private key, so label it clearly as a secret + offer easy revoke.

Unification: both are the SAME signing page, differing only in where the provisioning PUBLIC key comes from — agent-supplied (paired, via the code) or browser-generated (portable, for download). So keeping both is cheap: the pairing flow is the 'an agent is present' branch of the existing /agents signing UI. Nudge toward paired in tooling (SDK bootstrap(), wallet provision tool); keep download as the explicit/advanced escape hatch.

## Design doc

docs/plans/2026-07-12-paired-agent-provisioning-design.md — full flow, endpoints (/agent-provision/request + /poll mirroring warrant consent), shared signing page, session-authenticated reservation, data model, security analysis (no secret transit; poll result not a secret; device-grant phishing mitigations), SDK bootstrap() + wallet provision tool, compat, open questions, sequencing.

## Q1-Q4 resolved (2026-07-12)
- Q1: return all entry points (verification_uri + user_code + verification_uri_complete + fingerprint); agent shows whichever fits — desktop one-click URL (kept), headless types code at /link. Code is for cross-device/headless, not primarily anti-phishing.
- Q2: reservation is a standalone primitive with two auth modes (session-auth for browser/verify + reservation-only flow; provisioning-key-auth for the agent). NOT folded into registration — preserves agent-suggested + agent-driven reservation and the reservation-only flow.
- Q3: the verify page is a MODE of /account (reuse add-email/activate/create-agent), and MUST support new-user setup in-flow (add+verify+activate+delegate) — the common brand-new-user path, not an edge case.
- Q4: idp from delegating identity's issuer; inherits 0phq later, no v1 action.
Design doc updated accordingly.

## Build progress (2026-07-12) — happy path deployed

DONE + deployed to browserid.me:
- Backend (browserid-registrar/src/agent_provision.rs): POST /agent-provision/{request,poll,info,resolve,complete}. In-process pending store (ephemeral, 15-min TTL). Binding: complete verifies the delegation certifies the agent-supplied pubkey; metadata (idp/names/patterns) derived from the signed certs. Fingerprint byte-identical to the SDK (65-B6-06 KAT). Unit-tested. SMOKE-TESTED LIVE (request→pending→info→resolve).
- SDK Agent.bootstrap() (sdk/agent): generate provisioning key locally, request, return {verificationUri, verificationUriComplete, userCode, fingerprint, ready}; ready polls, assembles credential from the picked-up delegation, mints. Tested 7/7 incl. a full mock pair→mint. Credential.toJSON() for local persistence.
- account.html: /account?provision=<code> renders the approval panel — pick identity, sign P_cert over the agent's pubkey (Keystore.sign), register, complete. Deployed + serves live.
- wallet MCP:  tool (bootstrap + persist on approval); NEED_CREDENTIAL now points at it; AGENT_INSTRUCTIONS Step 1 updated. No downloaded file.

REMAINING (follow-ups, not blocking the happy path):
- Full human-approval loop verified only piecewise (endpoints + page serve live); end-to-end with a real session+identity not yet automated (manual test / Playwright e2e TODO).
- Q3 new-user inline setup NOT built: the approval panel requires an already-activated identity ('activate one first'); brand-new-user add-email/activate-in-flow is the main gap vs the design.
- Typed user_code entry UI (/link page) not built (resolve endpoint ready; one-click path works).
- Reservation currently claimed at mint (seconds after approve), not at approval — acceptable for v1; hardening in the reservation bean.
- No e2e test of the browser approval yet.

## Q1 + Q2 done (2026-07-12)

Q1 (race closed): RegistrarHost::reserve_agent_names — session-authed reservation mirroring ensure_agent_identity (collision scan, quota, parented to delegator). /agent-provision/complete verifies session owns the delegating identity, then reserves handles BEFORE storing the delegation, so approved handles are locked to the account and the agent's mint can't be refused. NamesTaken -> 409, surfaced before storing. Registrar+broker integration tests green.

Q2 (new-user inline): approval panel is now a banner over the account app; lists ALL account identities and activates the chosen one on approve (ensureActive: key+cert). Brand-new users add an email in the app below; the picker auto-refreshes. Resume-after-sign-in already worked (sign-in reload preserves ?provision).

Still remaining: end-to-end Playwright test of the browser approval loop; the typed user_code /link UI; primary cross-domain delegating identities (owns_verified_email assumes the delegator is a verified email on the browserid.me account — fine for secondary/browserid.me identities, edge case for external primaries).

## E2E test added (2026-07-12)
Playwright paired-provisioning.spec.ts drives the full loop end-to-end: Node SDK Agent.bootstrap (agent side) + real browser approval at /account?provision= (human side) -> agent picks up + mints; plus the deny path. Enabled AGENT_PROVISIONING=1 on the e2e web server. Full suite 92 passed. The 'no e2e of the browser approval loop' gap is closed. Remaining follow-ups: typed user_code /link UI; external-primary cross-domain delegation.
