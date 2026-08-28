---
# browserid-ng-d0xb
title: 'Fallback-IdP as a standalone API: native wallets drive secondary-identity issuance without the dialog'
status: completed
type: feature
priority: normal
created_at: 2026-08-27T11:04:49Z
updated_at: 2026-08-28T22:30:46Z
parent: browserid-ng-9yyk
blocking:
    - browserid-ng-rjge
blocked_by:
    - browserid-ng-bw9q
---

Third design thread from the menubar-wallet prototype (with gxi9 and bw9q): a native wallet holding a SECONDARY identity currently has no sanctioned API — the prototype drives the dialog's own wsapi calls (authenticate_user, stage/complete_signin_code, /device/issue) with a cookie session, which is undocumented, cookie-bound, and effectively reverse-engineered.

Define how the broker's fallback-IdP role is consumed standalone: what the issuance API is (email verification ceremony, authentication, device+config cert issuance), how it can be done safely from a native app (password/phishing surface, rate limits, no weakening of the mint-authorization chokepoint), and how it composes with the bw9q auth mechanism — per Dan, this is downstream of bw9q: the fallback IdP is probably a subset of the same well-specified API family, sharing the presentation→bearer-token auth once bootstrapped (the chicken-and-egg is only the FIRST issuance, which necessarily rests on the email-verification ceremony).

Same spec-quality bar as bw9q: implementable independently from the spec. See docs/plans/2026-08-28-native-wallet-design-handoff.md.

**Scope note from registry-api-v1 review (2026-08-28):** the registry spec's §5.5 defines the /.well-known/browserid-registry discovery document with a reserved `browser` object — this spec defines its keys: the browser-ceremony URLs a native wallet opens for what it cannot (or should not) do natively — account creation / email verification, password set/reset, account cancel/recovery. Walk the native-wallet account lifecycle end to end (create account, sign in, forgotten password, recovery) and decide per step: native API, browser handoff (discovered via meta), or out of scope. Primaries don't need this — they discover their IdP's ceremony surface via DNS/address_info; only the broker-as-fallback-IdP does.

**Per-scope re-review gate from registry-api-v1 (2026-08-28):** the token exchange accepts self-issued (broker-rooted secondary) presentations for the `registry` scope, justified because that scope excludes all root ops. When this spec adds scopes to the same token family (issuance, account ceremonies), each MUST re-justify self-issued acceptance individually — a self-issued presentation must never reach the mint-authorization chokepoint or password/email root ops just because it can reach the inbox. The password remains the root credential for secondaries; derived credentials must not mint root control.

## Work plan (started 2026-08-27)

- [x] Recon (2026-08-27): exact wire shapes of the current secondary-issuance surfaces (dialog cookie lane: authenticate_user / stage+complete_signin_code / browser_holder / device/issue; fallback-IdP lane: /auth/send / /auth/verify / /auth/device_cert), password lifecycle + recovery endpoints, existing rate limits, address_info
- [x] Walk the native-wallet account lifecycle (2026-08-27; per-step lane decisions drafted into the skeleton §5) end to end; per step decide native API / browser handoff (registry §5.5 `browser` keys) / out of scope
- [x] Spec skeleton (2026-08-27): docs/specs/fallback-idp-api-v1.md — auth model (composition with registry-api-v1 token family + the first-issuance email ceremony), endpoint inventory with legacy mapping, `browser` discovery keys, error taxonomy, invariants, open questions
- [x] Dan reviews skeleton; resolve open questions (decision log in spec)
- [x] Flesh out: wire examples, machine reasons, normative grammars
- [x] Adversarial review pass (fresh-eyes agent), fix findings
- [x] Per-scope self-issued re-review gate: no new scope was added — devices/register sits under the existing registry scope, whose §3.1 self-issued justification bounds it (§5 ops only; registration records verified material and mints nothing)

## Direction change (Dan, 2026-08-28): fallback-as-primary

Skeleton redrafted twice on review: (1) issuance bar corrected to password + durable verified flag (/device/issue parity, not the two-lane union). (2) Dan chose option (a) — no credential ever crosses a native API — plus 'treat the fallback as a primary': address_info advertises device_auth/access_mint for secondaries, the broker mounts a device-authorize page implementing the standard fragment/return contract (made normative), and the wallet keeps ONE bootstrap flow with a single skip-the-join branch. All native password/code endpoints (stage/complete/email send+verify/issue, email_proof) deleted from the spec. Headless secondary issuance deliberately not offered (agent lane covers scripted clients). New sibling bean uboq: time-expire SMTP verification (issuer policy §3.4). Open: holder continuity param (absorbs kmvm), max-age window, config-cert identity set, page mount.

## Review rulings round 2 (Dan, 2026-08-28)

- Spec cleaned of draft archaeology (meta-commentary lives here, not in the doc).
- address_info DROPPED from the native contract: native clients run core §3 discovery themselves and CHOOSE their fallback (client configuration = the escape hatch); the endpoint stays web-dialog-only. Support document already carries device_authorization (core discovery.rs:55) — the broker just has to advertise it for its own fallback role (+ access_mint).
- Holder: same as the primary lane — issuer-assigned fresh holder bound to the fragment keys, never derived from the ceremony page's browser session (the wallet must not show up as a web device). No client-supplied holder param; kmvm stays independent.
- Registration reframed as a first-class, client-configured relationship with the registry, distinct from issuance: token exchange (or session join) with the new certs; issuer==registry is the redundant case (issuance already recorded), and the lanes' self-issued rules make that composition safe by construction. Registry choice surfaced at wallet setup; default preserves current UX.
- Remaining open: verification max-age window; config-cert identity set; page mount (new route vs broker-as-own-tenant on the hosted-IdP machinery).

## Review rulings round 3 (Dan, 2026-08-28)

- Verification max-age: issuer policy, NOT in the spec; browserid.me implements 90 days (uboq).
- Old open Q3 (page mount) dropped from the spec — implementation detail, decide at build time.
- Spec gained a §1 model section: four parties (RP / wallet / IdP / registry), independently chosen, identical APIs regardless of operator. RP acceptance of fallbacks (core §8.1) is part of the model.
- Registration is ALWAYS wallet-driven, even when issuer == registry: token exchange + a new POST /api/v1/devices/register (idempotent upsert; to add to registry-api-v1 §5.3 during flesh-out — the token exchange records nothing today). Issuer-side recording demoted to an internal convenience nothing may rely on.
- New bean u6jq: the native wallet lane drops the RP's acceptedFallbacks (extension does not forward them to the localhost bridge).
- Remaining open: config-cert identity coverage (exact address vs local+*@domain sub-address wildcard).

## Adversarial review round 1 (2026-08-28, fresh-eyes agent): 10 findings, all addressed
- HIGH 1: §2 named address_info fields (access_mint/device_auth) as support-doc keys — WRONG. Fixed to device-authorization/access-cert (core §3.1 / discovery.rs).
- HIGH 2: return_url delivery lane unvalidated → cert exfiltration. Real CURRENT vuln in the shared device-authorize page (postMessage lane checks return_origin, return_url lane doesn't). Spec MUST added; code bean 9it0 (high).
- HIGH 3: devices/register undefined + token-exchange presentation contains config_cert but NOT the authentication device_cert, so registration wasn't verification-covered. §4 now specifies the validation (DNSSEC issuer, account owns identity, shared holder, token-bound config cert); to add to registry-api-v1 §5.3.
- MED 4: §2 omitted DNSSEC-only trust root → client-side discovery downgrade. Added.
- MED 5/8/10: model stated as fact but reference wallet/fallback-doc/verified_at not yet converged. Marked target-state with bean refs (d0xb/2jfh/uboq).
- MED 6: wildcard widening rested on soft 'strongest session bar'. Now conditional: wildcard only at the password bar, exact-only otherwise (7ww7).
- MED 7: device_error enum the page doesn't emit. Now open set; unknown = generic refusal.
- LOW 9: registry-api-v1 §5.5 browser-key example was stale. Updated to 'account'.
Clean checks: registration wallet-driven, holder self-assign, self-issued token scoping all verified sound.

## Impact analysis (2026-08-28, fresh-eyes agent): no deeper protocol change needed

**Core spec** (bean rjge): support-doc schema already allows a fallback to advertise device-authorization/access-cert (§3.1 generic 'an IdP'); the work is rewording the many spots that weld the registry to 'the hosted broker' (§5/§6.3/§7.5/§1.3/§8) + the §3 AD-unset routing conflation. Mechanism-neutral. Plus qualify §3.1 device-cert REQUIRED once /auth/device_cert (2jfh) retires.

**registry-api-v1** (d0xb build): add POST /api/v1/devices/register to §5.3 (fallback §4 bar), its §7.1 machine reasons, and fix the §9 mapping row (record_device_cert records only the config cert; devices/register records the pair). §3.1 account-resolution + v1-warrant bootstrap already suit a just-issued identity — no change. agent-provisioning spec: no conflict (headless vs interactive lanes).

**Registry impl**: new handler in registrar/src/api.rs + route in lib.rs. Confirmed token_exchange (api.rs:243-355) never parses the authentication device_cert → registration must verify it. The registrar can't verify certs itself (PresentationVerifier trait has only verify_presentation/check_status_ref); needs a third capability, refactored from the broker-side record_device_cert pipeline (primary.rs:287-400: resolve_conformant_key, sig, fail-closed status, holder-move guard, insert). record_agent_device_cert records unverified; record_device_cert refuses non-authorization certs — devices/register is the verified union of both. Idempotent free (insert upserts on pubkey).

**Fallback impl**: broker's own support doc (well_known.rs:42-48) lacks device-authorization — add it + populate registry.browser.account. Ceremony page (static/idp/device-authorize.html + common/js) is structurally reusable but hardwired to the tenant /idp/* backend; fallback role needs the same page shape over the broker-session backend, issuing via the /device/issue core (already implements §3.2's authorize_mint bar + wildcard rule). Real new work: embedded-friendly sign-in/create UX (today /account is a full page).

**Web dialog**: NO required change — stays on the cookie lane, issuer-side recording + self-heal cover it (explicitly permitted by §4). Only shared-page 9it0 fix must not regress its postMessage lane.

**Native wallet**: bootstrap.js secondary lane (186-210) replaced by primaryHop (92-128) — deletes the app's only cookie code; both lanes end with token exchange + devices/register instead of joinBroker(). WATCH: holder healing/labeling rides the join + /device/issue move-resolution today; devices/register must carry the move-guard + UA-label hook or wallet devices lose healing.

**Three spec gaps to close while building:** (a) whose accepted-fallbacks set governs devices/register verification at an INDEPENDENT registry (record_device_cert uses accepted=[own domain]); (b) core §3.1 device-cert REQUIRED vs the two-key fallback contract post-2jfh; (c) holder healing needs a token-lane path.

## Sequencing (dependency-ordered)
1. NOW/independent: 9it0 (return_url, hardens live tenant lane); spec patches (registry §5.3 devices/register + §7.1 + §9; core wording rjge).
2. Parallel/independent: devices/register impl (registrar endpoint + verifier-trait extension + refactor primary.rs:287-400 into shared verified-recording core) — testable against existing-lane certs.
3. 2jfh consolidation (blocked by d0xb finalization): one issuance core; migrate dialog's /auth/device_cert; retire exact-only lane.
4. Fallback ceremony page + discovery advertisement — depends on 3 + embedded sign-in UX.
5. uboq verified_at expiry in authorize_mint — independent, land before advertising §3.2 conformance.
6. Wallet convergence (2m7y context) — needs 2 and 4 live.
7. u6jq acceptedFallbacks forwarding; ig9p cookie-lane registry-scope — separate tracks.

## Summary of Changes

Spec finalized (fallback-idp-api-v1: fallback-presents-as-primary, ceremony contract normative, wallet-driven registration, operator accepted-fallback policy for devices/register — Dan's call 2026-08-28). Built and deployed:
- POST /api/v1/devices/register (registry-api-v1 §5.3): verified-pair recording with the full §7.1 invalid_cert taxonomy, token binding, holder-move guard, idempotent upsert, UA labeling, and the i8a2 holder healing (browsers-prefix adoption + orphan move + completion) ported to registrar-store twins — the token lane no longer needs the cookie join for healing.
- Fallback ceremony page + discovery (see 2jfh) and verification freshness (see uboq).
- Wallet convergence: bootstrap.js is ONE ceremony flow for primary and fallback identities (fallback resolved via the broker's own support document), zero cookie code in the app, registration via token exchange + devices/register; test lane drives the real page in a hidden window with injected password; ceremony partition pins the wallet UA. Wallet e2e green end to end.
Spec gaps (a)/(b)/(c) from the impact analysis all closed (operator policy; core §3.1 fallback qualification; healing on devices/register). Remaining epic work is 71vt (dialog on /api/v1 + role split) and fl6r (low).
