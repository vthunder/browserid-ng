---
# browserid-ng-1sb3
title: 'Registry API: does it need an account concept (cookie analogue)? Analysis + decision'
status: todo
type: task
priority: normal
created_at: 2026-08-29T20:49:11Z
updated_at: 2026-08-29T23:16:06Z
parent: browserid-ng-9yyk
blocking:
    - browserid-ng-71vt
---

Dan's framing (2026-08-29): the broker has a real ACCOUNT concept — one account spans multiple emails and resources — and the cookie authenticates to the account. The /api/v1 proposals authenticate self-authenticating resources (a token minted from one device pair), which is fine for the resources as standalone things, but we lose the account concept. Accounts matter for UX: after authenticating as ONE email, the broker exposes the account's OTHER emails so the dialog's chooser shows them all — even ones this browser/wallet has no certs for yet. Analyze the broker API and decide whether to add an account concept, e.g. via a cookie analogue.

## Precise statement of what the token lane has and lacks
The current token is MORE account-like than it first appears: the exchange resolves the presented identity to its owning account and the token then acts account-wide (GET /api/v1/devices lists ALL the account's devices; warrants, holders, inbox likewise — ApiUser.user_id). What differs from the cookie:
1. SELECTION: which account you become falls out of which pair you minted from — not from an interactive login. Multi-account browsers/wallets get the ambiguity that stalled the 71vt account/consent-page migration.
2. ACCOUNT-SURFACE READS: no token-lane analogue of list_emails — registry-api-v1 §6 excludes account/email surfaces — so a native wallet cannot render the dialog's chooser (all account emails incl. cert-less ones). This is the UX loss Dan names.
3. ROOT OPS: password/email lifecycle stay cookie-only BY DESIGN (§3.1 per-scope self-issued gate: derived credentials must never reach root ops). Any account concept must not reopen this.

## Options to analyze
(a) WIDEN THE TOKEN SURFACE, keep the model: add account-level reads to the token lane — e.g. GET /api/v1/account/identities → emails + proof classes + agent identities (the chooser's input). The token is already account-resolved, so this is surface, not a new auth model. Needs the per-scope self-issued re-review (read-only, no root op — likely justifiable, possibly under a distinct account.read scope so it can be refused independently). Solves the wallet-chooser UX; does NOT solve selection ambiguity.
(b) COOKIE ANALOGUE: an account-level session for the token lane — a longer-lived credential minted only by an interactive login at the broker's sign-in surface, presented by wallets alongside/instead of pair-derived tokens. Solves selection AND could gate future stronger scopes behind a real login; but reintroduces a second long-lived bearer credential (the thing 'no refresh tokens' deliberately avoided), needs its own binding story (what stops it moving between devices?), and blurs the clean 'resources authenticate themselves' model.
(c) HYBRID (likely landing zone): keep pair-derived tokens as the only API credential; fix selection page-side for broker-hosted pages (cookie stays their source of account truth, or session-owns-pair pin per 71vt); add (a)'s account reads for wallet UX.

## Deliverable
A short written recommendation against these options (+ any better shape), the per-scope self-issued justification for whatever reads are added, and the resulting registry-api-v1 spec patch. Blocks the remaining 71vt route-retirement decisions.

## Ruling (Dan, 2026-08-30): the §3.1 'no linking in the token lane' statement is challenged and falls

Dan missed that sentence at drafting time and rejects it as a standing position: now that the cookie APIs are classified broker-page-internal (outside the official spec surface), 'linking/merging/transfer only via cookie APIs' means the official browserid specs don't allow them AT ALL — they'd be registry-implementation-internal actions. Wrong: these flows were worked out in the cookie era and are still required; with cookie APIs retiring from the spec surface, they must exist in the token lane.

**Role split that scopes the work:** identity MEMBERSHIP (which identities an account owns: attach/detach/transfer/merge) is registry business → registry-api-v1. CREDENTIALS + verification (passwords, codes, bridge proofs, recovery) are IdP business → stay behind the issuer's sign-in page, preserving the root-op gate.

**Token-lane operation inventory (working direction):**
1. attach — anchor token (account membership) + new pair's issuer-verified certs (control of the new email) + approvals-inbox consent request (human gesture; also defeats the stolen-config-key durability escalation — a thief cannot approve their own attach without a second compromised device).
2. detach — remove identity from account; needs a not-the-last-identity rule + revoke-then-delete semantics for the identity's certs/warrants.
3. transfer — attach generalized: target owned by account B ⇒ the consent request raises in B's inbox ('release x@y?'), optionally an A-side confirm; both legs are existing proof machinery.
4. merge — bulk transfer; defer to v2 unless needed sooner.
Each op re-justifies self-issued acceptance individually; inbox consent is the general strong answer (bar = human approval on a trusted device, not credential provenance).

**Next:** draft a registry-api-v1 'Account membership' section (ops, consent-request shapes, §7.1 reasons) for Dan's review before code. Spec §3.1 sentence annotated as under review meanwhile.

**Draft ready for review (2026-08-30):** docs/specs/registry-api-v1-account-membership-draft.md — flows first (attach / transfer-as-release / detach), the one rule (tokens raise, only client-signed browserid-membership-v1 records complete), endpoint + record shapes, threat analysis (stolen-config-key durability → ≥2-device key-independence rule for attach; thief-detach bounded + recoverable; transfer-phish framing; no-existence-leak on foreign-owned attach), §7.1 additions, and 6 numbered decision points for Dan.
