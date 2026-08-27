# Native wallet: design handoff (2026-08-28)

Purpose: pick up the native-wallet design discussion in a fresh session and
produce a detailed build plan. This note carries the context; the beans carry
the work items. Read this, then `beans show 7v5l gxi9 bw9q d0xb lbla`.

## Where we are

The menubar-wallet prototype (bean **7oi3**, completed; code on branch
`proto/menubar-wallet` under `prototypes/menubar-wallet/`) proved the core
thesis end to end, human-confirmed with Dan's real primary identity: an
Electron menubar app holds device keys and replaces the browserid.me dialog;
an MV3 extension provides `navigator.id` on pages and routes login clicks to
the app over localhost; sign-in works on a real RP with **no popup and no
broker involvement in the login path** — IdP-issued device+config certs,
per-audience managed access mints at idp.browserid.me, self-signed login
warrants, `/verify` okay.

Protocol findings from the build (details in the prototype README and 7oi3's
summary): the verifier is wallet-agnostic by design ("they are all you" — no
holder-namespace or cert-type gate); the agent-provision lane can't bootstrap
a wallet because it never yields a config (Authorization) cert; managed
identities must name the audience in the access request; the device-authorize
page's `return_url` lane is the right native delivery channel (but
`return_origin` is a page precondition even then).

Housekeeping since: demo/dev pages no longer mount on the production broker
origin (commit `1826c64`: `/broker-demo`, `/dialog/test.html`,
`/dialog/sbo-smoke-test.html` are test-endpoint-gated; `/dialog` no longer
ServeDirs the whole static root). The wallet e2e serves its own RP page.

## The frame: "the broker" is four roles

1. **User-agent half** — dialog UI, keystore, holder cache, include.js
   mediation. The wallet replaces this. Proven by the prototype.
2. **Fallback IdP** — issuance for secondary (broker-vouched) identities.
3. **Registry** — holders/devices, warrant consent + registry, status lists,
   pending-approvals inbox. Today reachable only via cookie session.
4. **Hosted conveniences** — hosted /verify, hosted wallet UI, demos.

The design goal for the next phase: give roles 2 and 3 **well-defined APIs**
so the wallet is a first-class client — and so an independent broker could be
implemented from the spec alone, without reverse-engineering this one.
Openness principle at work: the ability to leave, per component.

## The three design threads (agreed with Dan)

### 1. Single-login bootstrap — `gxi9`

The prototype logs in twice (broker /account session, then IdP hop) because
it inherited the dialog's broker-first worldview. Correct order: wallet asks
*which email* → unauthenticated `address_info` → **one login at the issuer**
(IdP device-authorize hop for primaries; the broker /account login IS the
issuer login for secondaries) → wallet joins the broker silently via
`POST /wsapi/auth_with_presentation`.

**Confirmed against code: needs zero broker/IdP changes and weakens nothing**
— `/idp/device_cert` self-assigns a holder on cold login (hosted_idp.rs:386),
and `auth_with_presentation` demands a full valid presentation for the
broker's own audience (strictly stronger than a password). Holder healing
after the join rides the existing rrve/i8a2 machinery. This is wallet-only
work and can be built immediately.

### 2. Registry API — `bw9q`

Dan's direction: a carefully specified API with an **auth endpoint that
exchanges a presentation for a bearer token**; the bearer authorizes all
registry endpoints (approvals inbox, devices/holders, warrants, revocation).
Design questions to work in the fresh session:

- Token semantics: scope (which registry operations), lifetime, refresh,
  revocation (tie to holder status refs? a revoked device's tokens must die).
- Relationship to `auth_with_presentation` (mints a cookie session today —
  the token exchange is its API-shaped sibling; one endpoint content-
  negotiated, or a new `/api/v1/auth`?).
- Which of the existing cookie-authed `/wsapi/*` surface maps into the API,
  and what stays browser-only (CSRF-bound ceremonies like consent approval
  probably stay browser-side — approving is a human act).
- Spec artifact: where it lives (docs/api/?), what "independently
  implementable" requires (wire examples, error taxonomy, versioning).
- First consumer: the wallet's approvals inbox (kills the borrowed-cookie
  polling), then device listing/labeling (`lbla`).

### 3. Fallback-IdP standalone API — `d0xb` (downstream of 2)

How a native wallet drives secondary-identity issuance without the dialog:
email-verification ceremony, authentication, device+config issuance — safely
(password/phishing surface in native apps, rate limits, the mint-authorization
chokepoint stays intact). Probably a subset of the same API family sharing the
bearer-token auth; the chicken-and-egg is only the first issuance, which
necessarily rests on the email ceremony.

## Security invariants to hold while designing

- Fail closed everywhere; no new anonymous surface beyond what exists.
- The mint-authorization chokepoint (`/device/issue` policy) must not gain a
  bypass; token-authed issuance must be at least as strict as session-authed.
- DNSSEC remains the sole root; nothing in the API may introduce a Web-PKI
  downgrade (see open bean kh0j for the existing RP-library instance).
- Consent (warrant approval) remains a human-in-browser act unless explicitly
  redesigned — the API exposes *visibility* (inbox), not approval.
- Bearer tokens must be bound tighter than "whoever holds the string" if
  feasible (DPoP-style proof-of-possession with the device key is worth
  considering — the wallet already holds a signing key).

## Known wallet gaps to fold into the real build

- Keys in a 0600 JSON file → Keychain/secure enclave custody.
- Login warrants minted without status refs (no per-site revocation bit);
  allocate against the registry once the API exists.
- Notifications unverified (macOS notification permission for dev Electron).
- Extension pairing trust model is prototype-grade (any local process may
  attempt to pair; each attempt raises a native dialog).
- Device labels: `lbla`.
- macOS 26: tray requires LaunchServices launch (`run.sh`); packaging as a
  real .app solves it properly.

## Pointers

- Code: `prototypes/menubar-wallet/` (app/, extension/, e2e.mjs, README with
  the full findings list). Branch `proto/menubar-wallet`.
- Ceremony recon (endpoint-by-endpoint map of the dialog login, keystore,
  holder assignment, presentation shape): summarized in the prototype README;
  the canonical reference implementation is `scripts/e2e/smoke-prod-dc.mjs`
  plus `dialog.js` `buildPresentation` (~line 421).
- Registry/pairing recon (agent-provision lane, warrant_requests auth,
  return_url validation): bean bw9q body + 7oi3 summary.
- Related open beans: `kmvm` (client-supplied holder on fallback lane),
  `v96n` (guestbook off the broker), `lq56` (demo RPs off broker — partially
  done by 1826c64), `10n1`/`8eld` (holder re-categorization UX).

## Suggested agenda for the fresh session

1. Design the registry API surface (bw9q): endpoint list, token exchange,
   token binding, error taxonomy — produce a draft spec document.
2. Fold the fallback-IdP lane into it (d0xb): what's shared, what's unique.
3. Spec review against the invariants above + principles doc.
4. Then plan the real wallet build: gxi9 first (no dependencies), registry
   client second, packaging/custody third. Decide what of the prototype
   survives vs. gets rewritten.
