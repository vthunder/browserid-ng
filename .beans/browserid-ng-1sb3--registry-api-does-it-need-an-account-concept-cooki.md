---
# browserid-ng-1sb3
title: 'Registry API: does it need an account concept (cookie analogue)? Analysis + decision'
status: todo
type: task
priority: normal
created_at: 2026-08-29T20:49:11Z
updated_at: 2026-09-09T16:12:07Z
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

**Ruling #2 (Dan, 2026-08-30): no release consent — transfer-on-proof adopted.** Fresh issuer attestation = proof of CURRENT ownership; the previous owner is notified (inbox notice + out-of-band SHOULD, revocations land immediately) and cannot block: 'they don't own that email anymore — the best we can do is make that visible.' Draft r2 written: Flow B folded into attach (§1.1 transfer effects at completion, atomic), release kind + record action deleted, hg2j cert revocation + empty-account deletion adopted, last_identity now detach-only, decision log records rulings 1-3; open points renumbered Q1-Q6 (attach approval independence, detach bar, TTL, merge deferral, agent-children-on-transfer edge, cookie-parity routing).

## Parity table (existing implementation vs §5.6) — for Dan's review, 2026-08-30

| # | Existing implementation decision | Where (code) | §5.6 | Delta |
|---|---|---|---|---|
| P1 | Transfer-on-fresh-proof: the identity's voucher adjudicates; the losing account is never asked | oidc.rs attach_verified, primary.rs, handle_claim.rs | ADOPTED (rule 2; Dan ruled — release consent deleted) | none |
| P2 | Inbox control can't take a password-backed account's E3 address; its channel is the reset ceremony (kgb9 unverify + H2 eviction) | signin_code.rs, oidc.rs cold-claim arm | inherited automatically — the fence lives at ISSUANCE (certs for an E3 address only mint under an owning session) | none |
| P3 | Change of holder revokes the former account's certs for that address, precisely scoped (hg2j) | every transfer arm | ADOPTED §5.6.2; also kills the loser's bound tokens fail-closed (= H2 for free) | none (was an r1 gap, fixed) |
| P4 | An emptied former account is deleted, not protected | primary.rs | ADOPTED §5.6.2; last_identity guards only detach | none (was an r1 gap, fixed) |
| P5 | Enumeration hygiene: owner-only state disclosure (M7/dw35), target-bound attempt-burned codes (C1), branch-indistinguishable responses | email.rs, code_guard.rs | ADOPTED: attach responds identically for owned/unowned targets; codes unguessable + TTL'd + rate-limited | none |
| P6 | Blast radius: one identity's certs/warrants, never a sibling's | hg2j scoping | preserved by P3 | none |
| P7 | No second-factor on adding an email (session + mailbox code; a session thief can attach today) | email.rs stage/complete | OPEN Q1: proposed ≥2-device different-key rule is STRICTER than shipped | new strictness, Dan to decide |
| Q5 | transfer_email moves ONE row; derived agent children stay behind, operational by the loser | store transfer_email + callers | OPEN — shipped behavior is arguably a bug (filed a93p, high); recommend revoke-and-drop children on transfer-out | shipped gap either way |

**Also resolved by Dan 2026-08-30:** Q4 merge deferred indefinitely (one-at-a-time transfer re-proves at the issuer anyway; bulk gains little). Q6: the account page UI invokes the WALLET, which talks to the registry — recorded in registry-api-v1 §10.8. **Merged:** the draft is now registry-api-v1 §5.6 (+ §5.1 kinds, §7.1 reasons, §10.8); the standalone draft file is deleted.

## Final rulings (Dan, 2026-08-30) — all questions closed

- Q1 = option A (self-approval): the anchor device signs its own membership record. Dan challenged the 'big risk'; honest answer recorded: the marginal risk over today is registry-scoped persistence (post-revocation account management, visible + detachable), EXCEPT for one escalation that exists in the shipped model too — a planted E3 address doubles as a PASSWORD-RESET channel (complete_signin_code on an owned address resets the owning account), turning registry/session access into root recovery. Mitigation is not a second device but severing membership from recovery eligibility: §5.6.2 deployment note added (shared-table registries MUST NOT let registry-attached addresses become reset channels without the issuer's own ceremony).
- Q2/Q3 dissolved: with self-approval there is NO inbox round-trip at all — attach and detach are SYNCHRONOUS calls carrying the record inline (record: iat/exp ≤300s + jti replay guard replaces pending codes/TTL/status polling). Matches Dan's 'no extra question' requirement and cookie parity exactly.
- Q5 = revoke-and-drop: on transfer AND detach, the loser's derived agent children of the departed parent are revoked and dropped, never transferred (winner provisions its own agents). Shipped leave-behind behavior confirmed a bug (a93p).
- Q4 merge deferred indefinitely; Q6 account-page-UI-invokes-wallet — both recorded earlier.

§5.6 rewritten synchronous in registry-api-v1.md; inbox keeps only the actionless transfer notice; §7.1 pared to record_mismatch/expired/replayed + last_identity. SPEC SETTLED — remaining work is implementation (registrar endpoints + wallet/dialog consumers + a93p fix), to sequence with 71vt/1sb3 build planning.

**Severity correction (Dan, 2026-08-30):** the planted-address reset is account-shell control + recoverable DoS, NOT takeover (kgb9 unverifies E3 siblings; primaries/bridges need proofs the attacker lacks; owner resets back via their own mailbox and cuts off the attacker's address). §5.6.2 deployment note softened from MUST to SHOULD-fence accordingly; mitigation exploration filed as bean dksx (recovery-eligibility delay for new addresses, reset-origin visibility to all addresses, the kgb9 agent-row gap — Agent rows stay verified so a post-reset attacker can mint the account's agent identities — and reset-war dampening; existing-address compromise means new-address fencing alone is insufficient).

## registry-api-v1 decision log (moved out of the spec 2026-09-05; the spec §10 points here)


Resolved 2026-08-28:

0. **Consent is API-complete** — approval was always a client-side
   signing ceremony; the browser page held the same keys, so the API
   adds no capability. Human-in-the-loop is the user agent's job
   (principle 8).
1. **Naming**: collections-as-GET + body-parameter POST verbs; no
   ids/emails in URL paths; small fixed `htu` set.
2. `success: true` dropped (§4).
3. `warrants/forget` stays; guard-rails deferred (bean `d51o`).
4. Proof alg pinned `EdDSA`; agility/PQ deferred (bean `hd63`).
5. *(superseded by 10, then 11)* Exchange warrant must carry the
   `registry` scope.
6. Inbox long-poll as OPTIONAL `wait`; SSE/webpush deferred.
7. **Secondary identities accepted** (unlike the cookie lane): this
   API's authority is a strict subset excluding root ops. Any future
   surface reachable with the same cert re-justifies self-issued
   acceptance (re-review logged on `d0xb`).

Resolved 2026-08-30:

8. **Account membership lives on this API** (§5.6), replacing "no
   linking in the token lane". Transfer is on-proof: fresh issuer
   attestation is current ownership; the previous holder is notified,
   never asked. Merge deferred (identities move one at a time). Derived
   agents are revoked and dropped with the departing parent (fixes bean
   a93p). Attach is synchronous and self-approved; a second-device rule
   was declined (residual risk: recoverable DoS — bean dksx).

Resolved 2026-09-01/02:

9. **Membership is cert-authenticated and self-authenticating**,
   superseding decision 8's membership record and the separate
   `devices/register`. Certs travel with possession proofs; `bh` makes
   the call its own consent artifact; one `attach` whether an identity
   is new or already owned. Two-tier authority: auth-cert possession
   records; membership changes and creation need a config-cert routing
   proof — else a stolen auth cert could plant a foreign identity and
   escalate to account-wide control. Joining certs must be fresh
   (`iat` ≤ 300s): config certs are RP-visible, so unexpired bytes
   alone must not move an identity. The exchange no longer auto-creates
   accounts (kills the parallel-account trap). Auth-only devices are
   supported policy (§5.6.6). Terminology per core §4.1: "device cert"
   is the umbrella, auth/config its flavors; no identity outranks
   another. Follow-up: the core §7.5 agent lanes should adopt the same
   possession bar (bean 0c49).

Resolved 2026-09-02:

10. *(amended by 11)* **Cert auth everywhere; the token exchange is deleted.** The
    exchanged warrant was self-issued by the very config key the token
    bound to, so its scope proved nothing beyond key possession; the
    token cached little (status was re-checked per call anyway) and
    cost a second auth mode plus a bootstrap exception. Now every call
    carries `Authorization: Cert` + `Proof`; the §5.6 two-tier rule
    became the whole authorization model (config cert = full, auth cert
    = recording tier). Only `attach` carries the cert; other calls
    name a recorded key by `kid`, so every actor is on the device list
    — the legibility hook for the open IdP-power question (bean
    `0c49`). Bean `ig9p` (cookie lane adopts the scope bar) loses its
    anchor; the cookie lane's delegated-authority concern is now stated
    directly in §3.4.

Resolved 2026-09-05:

11. **Per-identity authority; the session returns as a set; entry is
    guarded.** Decision 10 left any issuer of any roster identity with
    account-wide power (mint a config cert, read and revoke every other
    identity's warrants). Fix: the account is a roster, not a boundary.
    A session (§3.2) is minted from a *set* of proofs and carries each
    proven identity at its tier; every operation has a subject identity
    (§3.3). Unlike the deleted exchange, this token proves what one
    proof cannot — the union of several possessions — and stays
    sender-constrained (a member-key `Proof` per call keeps `bh` and
    defeats bearer theft). Holder mutations need write on every
    identity on the holder. Review then found the older hole: flow B
    (record a fresh cert for an owned identity, no session) let a new
    owner of an address, or its issuer, walk into the previous holder's
    account — the cookie lane always had the same shape, and the
    old "wipe on transfer" intent never covered it. Ownership epochs
    on certs were rejected (useless against a lazy or dishonest issuer
    or a taken-over mailbox). Ruling: entry is guarded (§5.6.7) — a
    registry-defined check delivered as one token, page or native; an
    unguarded fresh config cert is a change of ownership (the wallet
    must offer the guard and make "start fresh" explicit); an unguarded
    auth cert is recorded unblessed and reaches only per-audience
    warrant lookup (rate-limited), which keeps the shared-computer
    flow while a stranger must guess sites one by one. Guard kinds
    registered: `password` and `identity` (the page cannot obtain
    proofs from the wallet's keys, so the native kind stays). Blessing is per key and transitive
    through sessions, so the roster needs no separate gate. Detach
    stays destructive (a split would have let a new holder inherit);
    a non-owner may detach only through the guard. Guard reset and
    recovery policy is the registry's (reference broker: dksx; must
    not run through the address being attached). Bare `attach` keeps
    the shared-computer flow. The cookie lane keeps account-wide
    authority until bean `zpbh`. `attach` answers with a session.

Deferred elsewhere: agent-lane reparenting (`9mfw`);
browser-ceremony discovery keys (fallback-IdP spec, `d0xb`).


Resolved 2026-09-07:

12. **Explicit account, one identity at the door, account data.**
    Supersedes the per-identity partition of decision 11 (its guard
    and hold parts stand). Review of r5 showed every membership rule
    was inferring the account and that the per-identity partition
    was doing little once the guard existed. Now: an account has an
    opaque id, not a secret, given only to members (session/attach
    responses; named in `session` and optionally in `attach`); no
    oracle, first use unchanged. A bare `attach` concerns one identity
    (`mixed_accounts` deleted; `additional_identities` moved to the
    guard endpoint). Data belongs to the account: tiers lookup / read
    / write on the session; the subject rule, `not_in_session`,
    per-identity tiers, the holder authority rule, and the
    dead-issuer detach exception are gone. What keeps an issuer that
    can mint certs for an address out of the account is the guard at
    the door; a takeover lands it in an empty account; a co-member
    sees everything ("shared address = shared account"). Restore is an
    ordinary join: name the account, pass its guard or use a session;
    no revoked key is ever used as proof (the `recorded` proof kind
    and a 'secret id' variant were both considered and rejected). A
    holder with no other device and no other guard kind cannot
    restore — the same limit as a lost only device. Design note:
    docs/specs/registry-explicit-account-note.md (rev 2c).

2026-09-09: docs/specs/registry-explicit-account-note.md retired (deleted). Its three moves live in registry-api-v1 §4.1/§4.5/§5.2; its tier table was superseded by the login model and then by 'a session is the whole check' (§4.3, commit 6e0b88e). The rationale it carried: the answer to issuer power is the login gate, not per-identity partitioning.
