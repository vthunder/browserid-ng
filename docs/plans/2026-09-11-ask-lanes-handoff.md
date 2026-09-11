# Handoff: one way to ask the user's wallet for anything (the "ask lanes")

Written 2026-09-11 at the end of the session that finished zpbh and jo0m.
Resume from bean **g69e**; this note is the context.
Design it with fresh context; nothing below is implemented.

## The problem in one paragraph

Eight flows end at a consent card or a non-login signature. Every one of
them but login signs *inside a broker page* with a config key the login
dialog left in the browser's IndexedDB ("the user, at their broker, signs",
core §7.5). The native wallet holds no such key, so those pages cannot sign
for its users. The one wallet-signed surface — the consent page the wallet
hosts (jo0m) — is reachable only from the wallet's own inbox notification.
Three flows (connection admission, authoring admission, provisioning) are
filed through the server API while the user is present in a browser, then
*redirect* the browser to the card; that redirect is exactly where a
native-wallet user is stranded (Dan, 2026-09-10, mingo "post for you").
Diagram of the current state: <https://claude.ai/code/artifact/c47a05a5-da6c-49f2-9c60-a534b1dcb9e1>.

## The matrix (as built, 2026-09-10)

| Flow | Who asks | How | For what | User present? | Where decided / how it gets there |
|---|---|---|---|---|---|
| Login | RP | JS API | login warrant + assertion | yes | dialog, or extension shim → native wallet |
| SBO grant at login | RP | JS API (bundled) | signing-grant record (v2 self-grant) | yes | dialog only; native wallet has no step |
| SBO action | RP | JS API (signer popup) | signature over an action | yes | signer popup; no native route |
| Agent grant request | agent | server `/warrant/request` | warrants to the agent | no | inbox → consent page, or wallet notification → hosted page |
| Connection admission | resource (e.g. MCP gate) | server `/warrant/record-request` | admission record | yes, in a browser | redirect to `/consent/<code>` only (never listed: unowned until claimed) |
| Authoring admission | resource | same lane, kind `authoring` | admission record | yes, in a browser | redirect to the deep link only |
| Provisioning + bundled grants | agent | server `/agent-provision/*` | identity, then warrants | yes, via a printed/redirected link | `/authorize?code=` only |
| Manual signing card | you | none | a warrant | yes | account page (debug) |

What it exposes: "user present" maps to "JS API" except for the three
redirect flows, which used the server lane only because no JS API existed
for anything but login. And "where is it decided / who signs" is not
represented anywhere: each surface hard-codes `Keystore.sign`.

## The target (agreed with Dan, 2026-09-10)

Two lanes, one consent component, one signing interface. "What is asked
for" is the only variable.

1. **Present ask — JS API.** `navigator.id` grows from "log in" to "ask the
   user's wallet for X". The mediator routes the ask to whichever wallet is
   there (the dialog, or the extension shim → native wallet); that wallet
   shows the card and signs. Login already works this way. Connection and
   authoring admissions, SBO grants, SBO actions, and provisioning approval
   when the user is in a browser all belong here — no server-filed request,
   no redirect.
2. **Out-of-band ask — server API.** A party with no user in front of it
   files a request at the registry (`/api/v1/requests` inbox). Whichever
   wallet polls shows the same card and signs. Agent grant requests, and
   provisioning when the agent cannot reach a browser, belong here.
   **Also the fallback for a platform without the JS API** (Dan): a client
   that cannot run the mediator files server-side and the user answers from
   any wallet. Lane choice is capability, not identity of the asker.
3. **One consent component.** The card is one page the wallet hosts, for
   both lanes and both wallets (jo0m proved the hosting + bridge shape).
4. **One signing interface.** `sign(kind, claims)` answered from the
   keystore by the web wallet and natively by the native wallet. No broker
   page holds a key. The manual signing card is deleted outright (Dan).

## Open design questions (settle these first)

1. **The ask vocabulary.** Dan: consider a set of schemas kept as a side
   spec. Candidate kinds: `login`, `warrant` (grants to a grantee), `admission`
   (`connection` | `authoring` record), `signature` (an object to sign under a
   standing grant — today's SBO action), `provision` (identity + first
   grants). Each kind = request schema + what the card shows + what gets
   signed + where the result goes (presentation, requester poll, resource).
   One JSON-schema-per-kind file set, referenced by core §7.3 and by
   registry-api-v1 §5.3, would keep the vocabulary out of both specs' prose.
2. **Result delivery.** Present lane: back to the page (like login). Out-of-
   band lane: the requester's poll, as today. Connection/authoring records
   are consumed by the *resource*, so a present-lane admission must still
   reach the resource — via the page (the resource's own page asked) or via
   the registry (the resource polls). Decide per kind in the schema.
3. **The extension shim.** Today it answers `login` only over the localhost
   bridge. It needs the full vocabulary, the wallet needs a card window per
   ask (jo0m's host + bridge generalised), and the bridge's origin rules stay
   (127.0.0.1, paired origin).
4. **Claim/ownership for records.** Record requests are unowned until a
   deep link claims them. In the present lane the asking page already has
   the user, so ownership is the mediator's session — no claim step. Keep
   claim for the out-of-band fallback only.
5. **Spec placement.** Core §7.3 (mediator) gains the ask surface; §7.5 keeps
   the out-of-band lane and loses "the user at their broker signs";
   registry-api-v1 §5.3 stays the inbox. Registry `respond` accepts the same
   signed artefacts whichever lane produced them.
6. **Migration order.** Suggested: (a) delete the manual card; (b) define the
   vocabulary/schemas; (c) the signing interface in both wallets (web:
   keystore behind `navigator.id`; native: shim → bridge); (d) move SBO grant
   + action onto it (they are already JS-lane); (e) connection/authoring
   onto the present lane, keeping the server lane as fallback; (f)
   provisioning; (g) delete the redirect paths and the per-page keystore
   signing.

## Where things are (pointers)

- Surfaces that sign today: `browserid-broker/static/consent.html`
  (`localConfig`, `signWarrant`, `signWarrantV2`, `reg`), `authorize.html`
  (~line 1117), `dialog.js` (~531 login warrant, ~2252 SBO grant, 2755 consent
  click), `common/js/sbo-signer.js`, `account.html` advanced card
  (`$('w-create')`, `signDeviceWarrant`).
- Lanes: `browserid-registrar/src/consent.rs` (`warrant_request`,
  `record_request`, `warrant_poll`, `claim_core`, `respond_core`),
  `agent_provision.rs`; routes in `browserid-registrar/src/lib.rs`.
- Native wallet: `wallet/src/consent.js` + `consent-preload.js` (hosted card
  + bridge), `login.js` (login signing), `server.js` (localhost bridge, test
  lanes), `registry.js` (session, inbox poll). Extension shim: see
  `wallet/README` / e2e RP page for `navigator.id` routing.
- Web wallet session client: `common/js/registry-session.js`.
- Specs: `docs/specs/browserid-ng-protocol.md` §7.3/§7.5/§6.4;
  `docs/specs/registry-api-v1.md` §5.3.
- Related beans: e98a (login page's second method; mediator-in-webview,
  deferred attach — mostly subsumed by this), 7wj3 (primary-cert
  revocation), jo0m (done: hosted consent page).

## Verification workflow (learned the hard way this session)

- Rust: `ssh localtest 'cd ~/src/browserid-ng && cargo test --workspace 2>&1 | sed "s/\x1b\[[0-9;]*m//g" | grep -E "^error|FAILED|panicked|^test result"'`
  — strip colour first or `^error` never matches and a non-compiling test
  binary reads as green (it did, twice).
- Playwright needs a warm broker on :3000 (restart pattern in memory);
  wallet e2e: `cd wallet && WALLET_BROKER=http://localhost:3000 ADMIN_TOKEN=localtest-admin node e2e.mjs`
  (kill a stale Electron on :8873 first).
- Inline-script pages carry CSP hashes in `routes/mod.rs`; the guard test
  prints the new one.
- Deploy: `make deploy`; verify prod after.
