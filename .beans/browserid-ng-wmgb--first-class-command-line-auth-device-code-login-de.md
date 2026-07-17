---
# browserid-ng-wmgb
title: 'First-class command-line auth: device-code login + dedicated /account section'
status: draft
type: feature
priority: normal
created_at: 2026-07-17T10:32:46Z
updated_at: 2026-07-17T12:15:23Z
---

Stronger support for authenticating command-line programs against browserid (mingo's CLI is the first consumer), with CLI credentials managed in their OWN /account surface — separate from "Agents" and "External services". Design captured 2026-07-17 (dan + investigation) as a concrete basis for discussion.

## The two shapes considered

1. **Delegated CLI identity + scoped warrant** — the CLI gets its own identity, the user authorizes it like a regular warrant; shown in a separate /account section.
2. **Plain cert for the parent email itself**, minted outside the browser — simplest attribution (no "acts as"), but full user authority on the CLI host.

## Key finding: option 1 is ~90% already built; option 2 has no front door

Everything option 1 needs exists today:
- **Device-code flow (RFC 8628):** `/agent-provision/request` -> `/poll`, human-typeable `user_code`, `verification_uri_complete=/account?provision=<code>`, interval/expiry (bean browserid-ng-74u1).
- **Delegated credential** (`AgentCredential` JSON: agent Ed25519 seed + `U_cert~P_cert` delegation + broker/idp), minted by the browser signing over the CLI's pubkey with the non-extractable identity key.
- **Per-audience scoped warrants + consent flow** (`WarrantClaims`: `aud`=exactly one RP like `sbo://…`, opaque `scopes` strings, per-grant `status` revocation index, ~90d validity).
- **"acts as" attribution:** `agent.parent` + scopes surfaced through the verifier and token endpoint — **mingo already consumes this** (mingo-poster's `as:`).
- **Status-list revocation** (`/.well-known/browserid-status`): separate indices for identities, warrant grants, and agent keys — real per-device/per-grant revocation, not expiry-only (bean browserid-ng-egr7).
- **Reference CLI:** `browserid-agent/examples/agent_cli.rs` (`provision`/`grant`/`assert`/`token`/`revoke`) (bean browserid-ng-dolc).

Option 2 has **no headless path to a plain parent cert**: `/wsapi/cert_key` is browser-cookie-gated, and the only non-browser cert path (`/provision/mint`) always produces an *agent* cert with attribution. So option 2 is net-NEW work AND a worse security posture (full parent authority on the CLI host, coarse revocation).

## Recommendation: option 1, productized

Build the device-code CLI login + credential storage + a dedicated "Command-line access" /account section ON TOP OF the existing agent-identity/warrant primitives. The feature is UX + surfacing, not new auth. Reserve any parent-cert path for a narrow, explicitly-labeled "full access" mode — and even then use short-lived-cert + device-bound refresh, never a long-lived parent cert.

## The actual (new) work

1. **CLI login command** — `mingo login` (and/or a generic `browserid login`) wrapping device-code provision + the per-audience warrant consent (audience `sbo://…`), storing the credential in the OS keyring with silent refresh. Plumbing exists; this is a clean command + storage + refresh.
2. **"Command-line access" /account section** — a peer `<h2>` between "Agents" and "External services" in browserid-broker/static/account.html, reusing the generic "Authorize an agent" device-provision card and the warrant list + per-grant **Revoke** UI. Human framing: "mingo CLI on dan-laptop — authorized Jul 17 — can post as you — Revoke."
3. **Framing/labeling** so a CLI credential (technically an agent identity + warrant under the hood) reads as command-line access, not a bot "agent."

## Open decisions (what to discuss)

- **Naming/framing:** "command-line access" vs "agent" — pure UI, but decide the vocabulary so it's not confusing that a CLI is technically an agent.
- **Scope vocabulary:** warrants scope by audience + OPAQUE scope strings (no structured path/action scoping in the warrant itself; the RP interprets scopes). sbo already interprets `action:post`/`as:`, so "this CLI may only post" is expressible — define + document the scope set mingo/sbo enforce. If we ever want BROKER-enforced structured scoping (paths/actions), that's a real addition to `WarrantClaims` (relates to browserid-ng-5zdh capability constraints).
- **Per-audience = per-RP consent:** a warrant binds exactly one audience, so a CLI hitting N browserid RPs needs N consents. Fine for mingo (one audience `sbo://…`); worth knowing before imagining one credential spanning everything.
- **Attribution target:** with `as:`, CLI writes attribute to the PARENT (posts show as the user); the signing principal is the agent identity. Confirm that's the desired on-chain identity (yes for a forum).
- **Credential storage/refresh:** OS keyring vs token file; refresh via re-provision vs a long-lived agent key + short-lived warrant.
- **Wrap vs reimplement:** should `mingo login` wrap the existing `browserid-agent` SDK/CLI (browserid-ng-dolc) or reimplement the flow in mingo? Leaning wrap.

## Alternatives considered + why not (default)

- **Option 2 — long-lived parent cert in the CLI:** no headless front door exists (net-new), and it puts full user authority on the CLI host with only coarse (expiry/identity-status) revocation. Rejected as the default.
- **Short-lived parent cert + device-bound refresh token:** option 2's zero-app-burden attribution with bounded blast radius + per-device revocation (OAuth access/refresh mapped onto certs). The sane form of option 2 IF zero-app-support attribution for OTHER RPs becomes a hard requirement. Not needed for mingo (already understands `as:`).
- **Derived/subordinate identity (mingo-cm8z) for the CLI:** a distinct real principal (no "acts as"), separately revocable — but the RP must map derived->parent for posts to show as the user (app awareness), and there's no headless plain-cert path for it today either. A third point between 1 and 2; not worth it given mingo has `as:`.

## Relationship to existing beans

- Builds on: browserid-ng-74u1 (device-grant pairing), browserid-ng-gsnm (agent identity v3: warrants/revocation/registrar), browserid-ng-tdxf (delegation-chain provisioning), browserid-ng-egr7 (revocation), browserid-ng-5zdh (capability constraints).
- Reference tool: browserid-ng-dolc (agent_cli as a reference).
- NET-NEW here is the CLI-auth PRODUCT layer (login command + storage + the dedicated /account section + framing); the underlying auth mechanism already exists.

## The one genuine capability gap (only if wanted)

Warrant scoping is coarse today (audience + opaque strings). Broker-ENFORCED structured scoping (paths/actions) would be a real addition to `WarrantClaims`. Not required for mingo (sbo enforces scopes RP-side), but worth noting if CLI credentials should be broker-constrained rather than RP-constrained.

## Application to mingo (2026-07-17)

Three consumer classes, and the daemon needs NO changes for the first two — mingo's sbo daemon already validates agent-cert + warrant + `as:` (that's what mingo-poster does server-side today):

1. **Regular users posting from a CLI** — `mingo login` yields a delegated agent credential (agent identity + warrant, audience `sbo://<mingo repo>`, scope `action:post`); the CLI signs with the agent key + presents the warrant, and the daemon attributes the write to the PARENT (the user) via `as:`. So CLI posts show as the user. This is exactly mingo-poster's path (mingo-3f3i mobile) but client-side. Zero daemon work.
2. **Bots / automation** — the community bot (mingo-zmrw, "on-chain-governed, warrant-authorized LLM poster") is literally this primitive; the sbo attestor + service agents already went agent-native (mingo-ua8w). CLI-auth and these share the warrant/agent infra.
3. **Admin / operator CLI** — does NOT use the browserid CLI-auth flow (see below): the sys identity is key-rooted, so there's no email "parent" to sign a browserid warrant. The analogous hardening is an sbo-LEVEL warrant signed by the sys key (see next section), not a browserid one.

## Can mingo's sys identity be an EMAIL? (sbo support + why mingo doesn't)

- **sbo supports it.** An email-rooted admin is just an identity reference (`{name:"sys@mingo.place"}` or a bare name canonicalizing to it); sbo authorizes email-rooted identities via browserid+DNSSEC attribution. Nothing in sbo prevents `roles.admin` from being an email.
- **mingo already HAS an email sys identity for NAMING** — genesis is Mode B domain-certified, so `sys@mingo.place` exists (`/sys/names/sys`). But the admin POLICY ROLE is deliberately keyed by the sys PUBKEY, not the email.
- **Why key-rooted admin (mingo-d7bi):** matching admin by the email would make on-chain admin authority depend on the IdP's willingness to mint a `sys@mingo.place` cert — anyone the IdP issues that handle to (or anyone who controls the IdP) becomes chain admin. That was an ACTUAL live privesc (mingo-d7bi: "IdP-issued sys@mingo.place ⇒ on-chain admin"), fixed by keying admin to the genesis pubkey so admin depends ONLY on holding the sys key, IdP-independent. So: don't switch sys to email-matched admin.

## The admin-CLI hardening angle (the real tangent)

The session has been holding the raw sys key on the operator's laptop (~/secure-backup/mingo-sys.key). The browserid CLI-auth model can't harden that directly (no email parent for a key-rooted admin). The right analog: the sys key issues an **sbo-level warrant** (auth_warrant, the same mechanism sbo already validates) delegating SCOPED, revocable admin authority to an ephemeral agent key — key-rooted throughout, IdP-independent, so the raw sys key can stay offline/HSM and day-to-day admin ops run under a narrow, revocable delegation. Parallel to CLI-auth (both are "scoped revocable delegation for a CLI"), but at the sbo layer for the key-rooted root, vs the browserid layer for email users. Worth its own bean if we pursue it.

## MVP BUILT (2026-07-17)

`mingo login` / `mingo whoami` / `mingo post` shipped in mingo-app/src/login.rs (commit a1defcf, mingo repo), wrapping the browserid-agent SDK — browserid-ng needed NO changes. Device flow (/agent-provision) + per-audience warrant with as:<user>. Credential stored ~/.mingo/credential.json (0600; OS-keyring deferred).

Key grounding: warrant audience is `sbo+raw://avail:turing:506/` (bare chain:appId) — the daemon REJECTS sbo:// (audience_identifies_db parses SboRawUri; DNS is not an on-chain trust root). Matches MINGO_SBO_DB_AUDIENCE + the poster tests. The as: path also requires a path: scope guardrail.

Proven without a browser: `assembled_envelope_matches_daemon_as_path_shape` builds a real agent cert + user-signed warrant, assembles the wire, re-parses, and asserts agent-key signer + valid sig + Owner=delegator + Auth-Cert agent(parent=user) + Auth-Warrant(agent, sbo+raw://…, as:<user>) — byte-compatible with validate.rs resolve_agent_effective.

NOT exercisable headlessly: the two interactive browser approvals (device consent + warrant consent) — those require the human signed in as the identity. So a real live login/post needs the user. Admin-scope is a `--scope admin` stub (adds action:delete); real operator-admin hardening is the sbo-warrant path (separate).

Status: MVP done; live e2e pending the user running `mingo login`.
