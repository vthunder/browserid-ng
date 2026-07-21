# Holder assignment — how a device/agent gets its holder

**Date:** 2026-07-21
**Status:** Spec, ready to implement.
**Companion to:** `2026-07-20-holder-authorization-model.md` (the holder model)
and `../design/browserid-end-to-end-flow.md` (the protocol overview).

The holder is an opaque, broker-assigned id naming *which of your things* holds a
device cert — a browser, an agent, a service — organized into user-private
namespaces (`browsers` / `agents` / `services`) as a randomized `<ns>.<rand>`
prefix. This note specifies **who assigns it and when**, for the two issuance
paths (interactive browser, and headless agent/service). The core rule
(model rule 1) is that the **broker assigns the holder; the requester never
names it** — otherwise a requester could name a colliding id and inherit another
holder's warrants.

## Two brokers (from the flow doc)

- **Client broker** — browserid.me's code operating the keystore **on the
  device** (the dialog). Talks to IdPs **directly**; there is no
  server-to-server broker↔IdP channel.
- **Hosted broker** — browserid.me the **server**: fallback IdP, verifier,
  warrant registry, revocation UI, and owner of the account's holder
  **namespaces**. Records; does not sign warrants.

## Browser path — the client broker assigns

A browser's holder is assigned by the **client broker** and is **one per
browser**, reused across every identity signed on that device.

- On first use the client broker fetches the account's `browsers`-namespace
  prefix from the hosted broker, generates `<prefix>.<rand>`, **stores it in the
  keystore**, and **reuses it for every identity** on that browser.
- Every device-cert request carries that holder; the IdP (fallback *or* primary)
  treats it as **opaque passthrough** and signs it verbatim. The mint copies it
  device→access.

A malicious browser could forge or substitute its own holder — **this is out of
scope.** A compromised browser already owns the keystore, the private keys, and
the client-broker code; there is no boundary to defend there. Rule 1 is about
keeping *separate parties* from naming each other's holders; the browser
assigning its **own** holder is not that case — it is the broker's own client.

Result: one browser = one holder, in `browsers`, carrying certs for however many
identities that browser signs.

## Agent / service path — the hosted broker assigns, at provisioning

An agent can't authenticate interactively, so a **device-grant / pairing
hand-off** brings the user in to approve, and the holder is assigned by the
broker (the requester is a genuinely separate party here — rule 1 bites).

**One URL, one approval.** The agent's request and the user's consent cover
**both** the device cert and its warrant(s) in a **single flow** — the user sees
one verification link and clicks approve once, regardless of the two objects
minted underneath. *(Today these are two separate flows —
`/agent-provision/*` for the device cert and `/warrant/*` for the warrant — to be
merged.)*

1. **Request.** The agent generates its keypair and sends only the **public**
   key plus the desired grant(s) — the `<name>@<domain>` handle, a namespace
   hint (`agents`/`services`), and one or more `audience[+scopes]` — to the
   hosted broker. It gets back one pairing **code** + one verification URL. The
   private key never transits the broker.
2. **Approve (one page).** The user opens the URL — the consent page, where they
   are logged in and their **config cert** is in the keystore — and approves
   once. That single approval:
   - **issues the agent device cert** (`purpose=authentication`, certifying the
     agent's key), signed by the IdP for the agent's `<name>@<domain>` identity,
     with a **broker-assigned holder** from the user's `agents`/`services`
     namespace (`<ns-prefix>.<rand>` — the requester hints the namespace, never
     the id); *(currently the registrar/hosted broker is that IdP and signs
     directly; a primary-domain agent would route to the primary IdP)* and
   - **signs the warrant(s) client-side with the user's config cert** — matcher
     `<id>` (isolate this agent) by default, widenable to `<ns>.*` — binding the
     agent's holder to the requested audience[+scopes]. The config cert is
     non-extractable, so the broker never holds it; it only **stores** the signed
     device cert + warrant(s).
3. **Pickup.** The agent polls once and receives **both** the device cert and its
   warrant(s).
4. **Use.** The agent mints an access cert from the IdP directly (its device key
   signs an access request; the IdP copies the holder into the access cert),
   signs an assertion, and presents `access_cert ~ assertion ~ warrant ~
   config_cert` to the RP.

## Build delta from the current implementation

### Browser path (holder assignment fix)
1. **Client broker (dialog.js + keystore):** a `browserHolder()` that generates
   `<browsers-prefix>.<rand>` once (prefix from a hosted-broker endpoint),
   persists it, and reuses it — threaded into both the broker-rooted device-issue
   request and the primary device-authorize hop.
2. **Hosted broker `/device/issue`:** use the client-supplied browser holder
   (validated to sit in the account's `browsers` namespace) instead of minting a
   fresh random one per call.
3. **Primary IdPs (sandmill, mingo-idp):** `device_cert` accepts a `holder` param
   and passthrough-signs it; drop local `<rand>` holder generation.
4. **Account UI:** the browser's certs across identities now share one holder in
   `browsers`; fold the separate "Agents" card into the unified holder view.

### Agent path (already broker-assigns holders; the merge is new)
The agent path already assigns holders correctly (from the namespace registry).
The change is to **merge device-cert provisioning and warrant issuance into one
request + one approval + one pickup** (§Agent/service path): one `/agent-provision`
request carries the grant(s); the consent page both approves the device cert and
signs the warrant(s) with the config cert; the poll returns both. This is part of
the agent/service (D) work, separate from the browser build above.

## Accepted properties / non-goals

- **Malicious-browser resistance for the holder** — out of scope (above).
- **No cross-device holder** — a different browser is a different holder (its own
  device); holders are deliberately not shared across machines.
- **adopt-after-wipe** — a wiped browser generates a fresh holder; re-binding it
  to an existing slot ("this is Main Laptop again") is the Account-UI refinement
  in the main model note, unchanged here.
