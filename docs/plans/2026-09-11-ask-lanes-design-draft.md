# Request lanes: design draft (reviewed with Dan 2026-09-11, no code yet)

Bean g69e. Context: `2026-09-11-ask-lanes-handoff.md`. Adversarial review
folded in (fta9 filed for the live shim bug). Flows first, then the
vocabulary, then the decisions.

## The one idea

A **request** is "someone wants the user's wallet to sign something". It has
a `kind`. It reaches the wallet by one of two lanes, and the wallet handles it
the same way whichever lane it came by:

- **Present lane.** The page in front of the user calls
  `navigator.id.request(kind, args)`. The mediator (the `navigator.id`
  script in the page: dialog opener, or extension shim → native wallet)
  gets it to whichever wallet is there. The wallet signs and answers.
- **Out-of-band lane.** A party with no user in front of it **files** the
  request at a registry and polls. Whichever wallet sees it (inbox, or a
  deep link) shows the same card, signs, and answers via the registry.

**Trusted origin.** The wallet only ever uses the origin the *browser*
attached to the message it received: `event.origin` for the dialog, the
extension's sender origin for the shim (fta9 fixes the shim, which today
forwards a page-claimed origin). Anything the page or shim says about its
own origin is ignored. Every authority decision below rests on this.

Requests are **inline** (payload in the call, artefact back to the page) or
**filed** (payload at the registry under a `code`; artefact to the filer's
poll). The present lane carries both: an inline request carries its
payload, a filed one carries only its `code`. A filer needs a registry to
file at, known from an identity it holds (agents, resources) or chosen and
carried in the code (provisioning). `login` is present-only.

## Flows

### F1. Login (present, inline)

1. Page: `navigator.id.request("login", { acceptedFallbacks? })`. The
   legacy object form stays as an alias for this.
2. Wallet shows the identity picker, signs the assertion and a login warrant.
3. Result: the presentation bundle via the login observer, and the promise.

### F2. Site asks for a self-grant (present, inline) — the SBO grant

1. Page: `navigator.id.request("warrant", { grants: [{ audience, scopes }],
   message? })`. Present-lane warrants are **self-grants only**; the
   requester channel is the trusted origin. Any other grantee is filed
   (F4) so the device-key signature and the deny-first rule apply.
2. Wallet shows the generic warrant card: verified requesting origin,
   identity, each grant with equal prominence. Scopes render through a
   wallet-owned label table; the raw scope is the fallback, monospace,
   length-capped, control and bidi characters stripped. Bundled with login
   it sits under the picker: "This site also asks for: sign posts,
   attributed to you."
3. Wallet asks the registry for status refs, fails closed if it cannot,
   signs, records, returns `{ warrants, config_cert }`.

### F3. Site asks for a signature (present, inline) — the SBO action

1. Page: `navigator.id.request("signature", { audience, object })`. The
   object is the typed SBO envelope; there is no free-text summary. The
   card renders the object's own fields (mode `prompt` in §5).
2. Wallet finds a stored record whose channel set covers (trusted origin,
   audience) — `coveringRecord` moves from `sbo-signer.js` into the wallet
   signer — else `no_grant` so the page can run F2 first.
3. Result: the four-object presentation (fresh access cert, assertion with
   `req_origin`, warrant, config cert) plus the object signature. The
   native wallet grows a signing-grant store to do this.

### F4. Agent asks for warrants (filed)

1. Agent files `{ kind: "warrant", grantee, holder, grants, grantor?,
   message? }` signed with its device key, gets `code`.
2. Wallet shows the F2 card plus grantee, its unverified label and
   message; never-met grantee renders deny-only. Signs, posts `respond`.
3. Agent's poll delivers the warrants.

### F5. Resource asks to admit a connection (filed; answered present)

1. The resource **backend** files `{ kind: "admission", type:
   "connection", audience, scopes, client }` and gets `code`. The backend
   names the client, never page script. It binds its OAuth session to the
   code, as today.
2. Instead of publishing the nonce and redirecting, the resource's page
   calls `request("admission", { code })`.
3. The wallet fetches the request by code and checks that the audience
   origin equals the trusted origin, exact, port included; http(s)
   audiences only; one audience per connection, one origin per authoring
   set. That check **replaces the well-known fetch**, nothing more. If it
   fails, the wallet answers `origin_mismatch` and the resource falls back
   to the well-known proof plus deep link.
4. Wallet claims (allocating binding id and per-binding status refs at the
   registry), shows the connection card (client name and host marked as
   reported by the site), signs, posts `respond`.
5. The page gets `{ status }` only. The record reaches the backend by its
   poll, so no record can be injected into a session that did not mint
   the request.

Authoring admission is F5 with `type: "authoring"` and a grants list.
The record is never returned to page JavaScript in any variant.

### F6. Agent provisioning (filed; answered present or out of band)

Filed only. Present just means the landing page polls status by JS and
calls `request("provision", { code })` so the local wallet answers; the
page origin carries no authority, the code is the credential. Identity
stage is §7.4 issuance at the IdP, then the grants stage, under one code.
The picker-chosen identity must satisfy the request's `grantor` pin.

### F7. Signature out of band — a labelled spec extension

An agent filing `{ kind: "signature" }` has no web origin, and §5 only
knows web origins as requester sources, so no stored record can cover it.
Allowing it requires a requester source naming an identity or holder in
the record schema (the §5 labelled door). Recorded as a follow-up; not
"already allowed". It matters because it is the real fallback where the
extension does not run.

### F8. Native wallet, any present request

1. The extension shim is the mediator; the background forwards the request
   with the browser-attached sender origin (fta9). Top frame only, or the
   frame origin carried explicitly.
2. Wallet opens the card window for that kind. Templates ship **inside the
   wallet bundle**, not served from the broker origin, so no broker page
   drives the key. Signs natively, answers over the bridge.
3. Filing, claiming, recording go through the wallet's registry session.
4. An unknown kind answers `unsupported_kind`; the shim advertises a
   version so an old extension never turns a warrant request into a login
   popup.

## The vocabulary

Side spec `docs/specs/request-kinds/`: README plus one JSON Schema per
kind. Core §7.3 and registry-api-v1 §5.3 point at it.

| kind | present-lane args | filed by, and proof | card | artefact | to page | to poller |
|---|---|---|---|---|---|---|
| `login` | acceptedFallbacks | nobody | identity picker | presentation | bundle | — |
| `warrant` | grants[] (self only), message? | agent: device-key signature | grants, equal prominence; grantee + deny-first when filed | warrants + config cert | artefact | artefact |
| `signature` | audience, object | (F7, extension) | typed object | presentation + object JWS | artefact | (F7) |
| `admission` | code | resource backend: trusted-origin match or well-known proof | connection / authoring | records + config cert | status | artefact |
| `provision` | code | agent: anonymous until bound | identity, then grants | device cert + warrants | status | artefact |
| `notice` | — | registry | informational | — | — | — |

Inbox items map from today's `agent | connection | authoring` onto
`warrant | admission(type)`. `known` and deny-first apply to filed
`warrant` only.

## Registry surface

```
POST /api/v1/requests            file any kind (body carries kind)
GET  /api/v1/requests/<code>     filer's poll: pending/approved/denied/expired
GET  /api/v1/requests            wallet inbox, items keyed by kind
POST /api/v1/requests/claim      allocates binding id + per-binding status refs
POST /api/v1/requests/respond    lane-blind
POST /api/v1/status/allocate     refs for inline self-grants (per binding)
```

Claim is tied to a card render from a user gesture, never triggered
silently from a code found in a URL. `/warrant/request`,
`/warrant/record-request`, `/agent-provision/*` become aliases, then go.
The registry rate-limits filings per origin; the wallet rate-limits
inline requests per origin, since any page can otherwise make it write a
ledger row.

## Decisions

1. **Authority comes from the browser-attached origin, never from page
   script.** Inline is allowed exactly where that origin is enough:
   self-grants, signatures, and the admission origin check.
2. **Filed admission, present answer.** The backend mints the request and
   collects the record; the page only hands over the code.
3. **Present-lane warrants are self-grants.**
4. **One signer.** `sign(kind, claims)` wallet-internal: keystore on the
   web, native in the app. No broker page signs; the manual card goes.
5. **One generic warrant card**; the SBO grant has no wording of its own.
6. **Names stay `warrant`.** A rename to "grant" is a separate wholesale bean.
7. **Status refs are per binding**, minted by the registry before signing;
   a refless v2 record is malformed, so the wallet fails closed.

## Spec edits (next)

- Core §7.3: "login mediator" → "request mediator"; trusted origin; the
  inline/filed split; login is one kind.
- Core §7.5: keeps the filed lane; "the user, at their broker, signs" →
  "the user's wallet signs"; admission origin check as an alternative to
  the well-known proof; binding id and refs minted at claim.
- registry-api-v1 §5.3: kinds by reference; generic file + poll; allocate.
- §5: note F7 as an unopened door.
