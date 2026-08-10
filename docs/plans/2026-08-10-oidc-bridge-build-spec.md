# OIDC bridge — build spec

**Date:** 2026-08-10
**Companion design:** `docs/plans/2026-08-02-oidc-bridge-design.md` (the *why*).
This is the *how* — the concrete, autonomously-buildable slice.

**One line:** claim `foo@gmail.com` by signing in with Google instead of a
mailed code — an in-broker OIDC proof method that upgrades the mailbox
ceremony for domains with a known OIDC issuer, reusing the atproto lane's
claim-hop verbatim.

## Placement (settled by the design doc)

OIDC is **not a new hierarchy step** — it upgrades the *ceremony* that proves
a mailbox for a no-primary, MX-having domain. The authority is still
mailbox-rooted (`proof` behaves exactly like `smtp` for every scope
decision: **one address, never the domain**). SMTP stays as an equal-strength
fallback ceremony for the same domain, so an OIDC outage degrades to today's
emailed-code flow. No pinning — the ceremony is chosen per claim.

## Reuse vs. build (from the code map)

**Reuse as-is:**
- The session-attach match table + cold-reclaim sub-match in
  `routes/handle_claim.rs:143–204` (signed-in-own / transfer / add / cold-
  known-sub-match / cold-new), swapping the match to
  `proof == Oidc && proof_subject == "<iss>#<sub>"`.
- `set_email_proof` / `Email.proof_subject`, `verify_email`,
  `create_user_no_password` / `transfer_email` / `add_email_with_type`.
- The dialog navigate-out/resume claim-hop machinery
  (`static/dialog.js` `CLAIM_RESUME_*`, `Keystore.putPending`) — add a
  parallel `proof === 'oidc'` lane tag.
- `address_info`'s `proof`/`claim` surfacing (`routes/email.rs:657–667`).
- `used_attestation_jtis`-style in-memory replay guard shape (for
  `state`/`nonce`), `reqwest::Client`.

**Build new:**
1. `ProofMethod::Oidc` (`store/models.rs:55–78`) + the `"oidc"` string arms.
2. `browserid-broker/src/oidc/` — the auth-code client: `/oidc/claim`
   (start: PKCE S256 + `nonce` + `state` + `login_hint=<claimed email>`),
   and `/oidc/callback` (verify the ID token, attach to session directly).
3. Provider→issuer config table (Google first), env-based client
   credentials (same custody as SMTP creds).
4. **JWKS fetch/cache + RS256 ID-token verification** — the real new code.
   `jsonwebtoken` v9 is in-tree but unused for verification (everything else
   is hand-rolled EdDSA JWS); Google ID tokens are RS256, so this is the
   first genuine `jsonwebtoken::decode` with `Algorithm::RS256`. Build a JWK
   URI (`https://www.googleapis.com/oauth2/v3/certs`) fetch + short cache,
   `DecodingKey::from_rsa_components`, validate `iss`/`aud`/`exp`/`nonce`
   and **require `email_verified == true`**.
5. Gmail address normalization (dots + `+tag` collapse) before the
   exact-email-equality check.

## The claim flow (per the design doc, attestation layer deleted)

1. Dialog: user types `foo@gmail.com` → `address_info` returns
   `proof: "oidc"`, `claim: "https://<broker>/oidc/claim?..."`.
2. Dialog's `proof === 'oidc'` branch parks pending state and navigates
   (popup or redirect) to `/oidc/claim`, which builds the Google
   authorization URL (PKCE + nonce + state + `login_hint`) and 302s to
   Google. State stored server-side keyed by `state` (single-use, TTL).
3. Google → `/oidc/callback?code&state`. The broker exchanges the code
   (server-side, with the client secret), verifies the ID token (JWKS/RS256,
   `nonce` match, `email_verified`, `aud`==our client, `iss`==Google), and
   **normalizes + requires the token's `email` to exactly equal the claimed
   address** (per-mailbox scope — no domain-wide grant).
4. Attach directly on the broker: run the same match table as
   `complete_handle_claim` (minus the attestation block), calling
   `set_email_proof(email, Oidc, Some("<iss>#<sub>"))`, then create a
   session + set cookie (cold) or attach to the existing session.
5. Redirect back to `/dialog/dialog.html?resume=oidc_claim`; the dialog
   resumes — since the callback already attached, "redeem" collapses to a
   `/wsapi/session_context` status check, then continues to cert issuance.

## Security checklist (from the design doc §gotchas)

- `email_verified == true` is **mandatory** (unverified Google emails are
  worthless as proof).
- Exact-email equality after Gmail dot/`+` normalization; never trust the
  `hd` (hosted-domain) claim to widen scope.
- `sub` is the stable identity; on a cold re-claim, match
  `proof_subject == "<iss>#<sub>"`, not the email string, so a reassigned
  address doesn't silently adopt the old account.
- `state` single-use + TTL (CSRF); `nonce` single-use + bound into the ID
  token (replay). Client secret in broker env only.
- The SMTP escape hatch stays available: `require_smtp_authority`
  (`email.rs:261–285`) must still accept an OIDC domain so "email me a code
  instead" works when Google is down.

## Decisions to confirm (build-blocking)

1. **Providers for v1** — Google only (covers Gmail + Workspace), or Google
   + Microsoft (Outlook/O365) together? Recommend **Google only** first.
2. **Workspace/custom-domain detection** — how does the broker know
   `acme.com` (a Google Workspace domain) uses Google OIDC? Options: (a)
   static allowlist of consumer domains only (gmail.com, googlemail.com) for
   v1, Workspace deferred; (b) detect Google Workspace via MX
   (`aspmx.l.google.com`) and offer Google for those too. Recommend **(a)
   static consumer-domain allowlist for v1** — Workspace detection is a fast
   follow but adds a domain-verification wrinkle (a domain's MX pointing at
   Google doesn't prove the *user* controls the mailbox any more than SMTP
   does, but the `hd` claim + `email_verified` cover it).
3. **Provider config location** — env vars on the broker
   (`OIDC_GOOGLE_CLIENT_ID/SECRET`), added to `sandmill-infra/secrets/
   id.env.age`. Confirm the in-broker custody (vs. the back-pocket bridge
   shape that keeps secrets off the broker). Recommend **in-broker** per the
   design doc.

## Deferred (follow-ups)
Microsoft/Apple providers; Google Workspace domain detection; the
bridge-shape secret isolation; any UI beyond the dialog lane.
