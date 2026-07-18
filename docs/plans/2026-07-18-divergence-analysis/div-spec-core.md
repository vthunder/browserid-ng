# Divergence: browserid SPEC + browserid-core cert chain / JWS

Target: `docs/design/browserid-end-to-end-flow.md` (device-cert model).
Surface: the two spec docs + `browserid-core/src/{certificate,provisioning,warrant,assertion,status,keys}.rs`.

Legend: KEEP / CHANGE / ADD / REMOVE, from the POV of the current impl.

---

## A. The core conceptual gap

The **device-cert model** factors a credential along two orthogonal axes carried
*in the cert*:

- **purpose** ∈ {`authentication` (mints access certs), `authorization` (signs
  warrants)}
- **subject** ∈ {`user`, `agent`, blank/any}

and splits every credential into **durable device cert (never seen by RP)** →
**fresh, IdP-minted access cert (RP-facing)** for authentication, and **config
cert (authorization device cert, RP-facing)** → **warrant** for authorization.

The **current impl has neither axis and neither split.** Today:
- The credential the RP effectively roots on IS the long-lived identity/agent
  cert (chain `certificate.rs`), not a freshly-minted per-login access cert.
- Authorization (warrant) is signed by the **delegator's ordinary identity key**
  (`U_priv`, certified by `U_cert`) — there is no separate authorization-purpose
  cert. `warrant.rs:91` `Warrant::create` takes `identity_key`, and
  `warrant.rs:114` even *rejects an agent cert as delegator* — i.e. only a plain
  user identity signs warrants. There is no config cert.
- Agent authority is bootstrapped by a **user-signed delegation chain**
  (`U_cert~P_cert`, provisioning.rs) + per-request **registrar endorsement**,
  not by an IdP issuing an `agent`-subject device cert directly.

So the migration is structural, not additive.

---

## B. Certificates (`browserid-core/src/certificate.rs`)

| Item | Class | Detail (file:line) |
|---|---|---|
| Ed25519 / base64url / JWS 3-part shape | **KEEP** | `keys.rs`; `encode_and_sign` cert.rs:300, jws in provisioning.rs:51. Reused verbatim for all new cert types. |
| JWT cert shape (`iss/iat/exp/public-key/principal/status`) | **KEEP as base** | `CertificateClaims` cert.rs:59-101. Device/access/config certs are this shape + new fields. |
| `typ: None` == plain user cert | **CHANGE** | cert.rs:63,144,224. Device-cert model has no untyped RP-rooted cert; the RP roots on an **access cert** (new `typ`), and login now *also* carries a warrant (Stage 3). |
| `AgentClaims { parent }` block | **CHANGE/REMOVE** | cert.rs:22-27,83-86. Replaced by the **subject** axis (`subject:agent`) on the device cert; "who it acts for" moves to the warrant's `(identifier, subject)`. Attribution stops living in a bespoke `agent` block. |
| `registrar` claim on agent cert | **CHANGE** | cert.rs:87-94. In the new model the warrant's revocation authority is the **hosted broker registry**, not a per-cert registrar origin; pinning moves onto the warrant/config-cert, so the cert-carried `registrar` largely goes away. |
| `TYP_AGENT_CERT` = `browserid-agent-cert-v1` | **REMOVE** | cert.rs:16. Superseded by device-cert (purpose×subject) + access-cert typs. |
| **`purpose` field** (authentication\|authorization) | **ADD** | not present anywhere. New on device cert. Verifiers must reject unknown values (design L37). |
| **`subject` field** (user\|agent\|blank) | **ADD** | not present. New on device cert AND warrant. |
| **device cert** (durable, non-extractable device key, lists identities one/many/wildcard) | **ADD** | new type. Certifies the **device** key, never presented to RP. `principal` becomes a *set/pattern* of identities, not a single email (cert.rs:30-37 `Principal` is single-email today). |
| **access cert** (certifies a *fresh* key; RP-facing; short-lived; IdP-gated online) | **ADD** | new type. This is what the assertion chains from. No analog today. |
| **config cert** (authorization device cert, RP-facing, signs warrants) | **ADD** | new type. Replaces "U_priv signs the warrant." |
| Host cert (§4.2, planned) | **KEEP** | cert.rs unaffected; design L48-49 still lets access-cert chain root at K_dns via optional intermediate. |
| `Principal::Email{single}` | **CHANGE** | cert.rs:30-56. Device cert must carry *multiple/wildcard* identities (design L68-70). |

---

## C. Provisioning / delegation (`browserid-core/src/provisioning.rs`)

This entire file is the v0.2 **delegation-chain** bootstrap. The device-cert
model **replaces the delegation chain with direct IdP issuance of an agent
device cert** (design L76-80 "Agent variant": the IdP issues the agent device
cert directly, gated by user pairing/device-grant), plus an **access request
token → mint API** for the per-use credential.

| Item | Class | Detail (file:line) |
|---|---|---|
| `ProvisioningCert` (`P_cert`) + `Constraint` | **REMOVE** | prov.rs:157-246,97-155. No `U_priv→P_pub` delegation in device model; the agent device cert is IdP-signed directly. Constraint (names/patterns) → becomes the device cert's **identity list** (one/many/wildcard) — the *idea* survives as a cert field, the delegation vehicle does not. |
| `RequestBundle` = `U_cert~P_cert~R` (+`verify`, signing-time semantics) | **REMOVE** | prov.rs:490-615. Delegation chain retired. |
| `ProvisioningRequest` / `Action::{Mint,List,Revoke,Reserve,Warrant}` | **CHANGE→access request token** | prov.rs:252-466. `mint` (names identity + fresh `agent-key`, posts to IdP) is exactly the **access request token** (design L85-89) — it survives, re-cast: signed by the **authentication device key**, names identity + **fresh access pubkey**. `list/revoke/reserve` are device-mgmt, likely stay on the IdP/broker mgmt API. |
| `Endorsement` (`E`, registrar co-sign) | **REMOVE (from mint path)** | prov.rs:775-876. Device model gates minting **at the IdP online** (design L90-97 "IdP gates every access cert online"); no per-request registrar endorsement to mint. Endorsement/registrar role collapses into the **hosted-broker warrant registry** + revocation, not a mint gate. |
| `ExternalWarrantRequest` (`agent_cert~R`, §6.6) | **CHANGE** | prov.rs:642-769. Still needed (a service agent asks a user to warrant it) but re-rooted: warrant now signed by a **config cert**, subject-scoped, revocation at hosted broker. |
| `typ` domain-separation idiom (`typ` per JWS, reject mismatch) | **KEEP** | prov.rs:33-35,210. Same fail-closed discipline for the new typs. |

---

## D. Warrant (`browserid-core/src/warrant.rs`)

| Item | Class | Detail (file:line) |
|---|---|---|
| Warrant binds **(agent-identity, audience)** | **CHANGE** | warrant.rs:51-77. New: **(identifier, subject) → audience[+scopes]** — a `subject` field is added, and the warrant now covers **user logins too**, not just agents (design L102-118: "A warrant is *always* present at the RP"). |
| Signed by **delegator identity key `U_priv`** | **CHANGE** | warrant.rs:91-138 `create(identity_key)`. New: signed by a **config cert** (authorization device cert). The whole "identity key signs warrants" model is dropped. |
| `parent-cert` embeds `U_cert` for self-containment | **REMOVE** | warrant.rs:68-69,131,185. Replaced by presenting the **config cert** in the bundle; RP verifies warrant against config-cert key, not an embedded parent cert. |
| `verify_for(agent_cert, aud, issuer_key)` cross-checks parent==agent.parent, agent==cert.email, aud, signing-time | **CHANGE** | warrant.rs:178-278. New join is by **(identity, subject, audience)** against the **access cert** (design L133), signed-by check is against the **config cert**, not embedded U_cert. |
| `status` REQUIRED, pinned to cert `registrar` origin | **CHANGE** | warrant.rs:254-275. Revocation authority moves to the **hosted broker registry** (design L119-120); pinning is to the broker, not a cert-carried registrar. |
| `agent cert cannot be a delegator` guard | **CHANGE/REMOVE** | warrant.rs:114-116,186-188. In new model warrants aren't signed by identity certs at all, so the guard is reframed as "warrants are signed only by config certs." |
| Warrant is **long-lived, key-agnostic, stored & reused device-agnostically** | **KEEP/STRENGTHEN** | design L104-110; today's 90-day validity (warrant.rs:32) already long, but impl treats it as part of a self-contained chain rather than a **stored, registry-hosted** object. Storage/reuse model is new. |
| `scopes` opaque array | **KEEP** | warrant.rs:64-66. |
| Warrant `typ` `browserid-agent-warrant-v1` | **CHANGE→ warrant-v2** | warrant.rs:29. New typ carrying `subject`, no `parent-cert`. |

---

## E. Assertions & presentation bundle (`browserid-core/src/assertion.rs`)

| Item | Class | Detail (file:line) |
|---|---|---|
| Assertion JWT (`aud`,`exp`), signed by subject key | **KEEP** | assertion.rs:12-49. Now signed by the **fresh access key** (from the access cert). |
| Presentation `cert~…~assertion` / `agent_cert~warrant~assertion` | **CHANGE** | assertion.rs:157-193,204-281. New RP bundle: **`access_cert ~ assertion ~ warrant ~ config_cert`** (design L48,131) — uniform for user AND agent, warrant no longer embedded mid-chain, config cert appended, order changes. |
| `BackedAssertion` struct (certs + optional warrant + assertion) | **CHANGE** | assertion.rs:166-174. Add `config_cert`; warrant present **always** (both user + agent), not "iff agent". |
| `check_structure` (agent cert must be leaf + warrant; plain must not carry one) | **CHANGE** | assertion.rs:250-271. New rule: warrant + config cert present for **all** logins; join validated by (identity, subject, audience). |
| `verify` chain algorithm (root at K_dns, assertion under leaf key) | **CHANGE** | assertion.rs:295-392. New: verify **access cert** to K_dns → assertion under fresh key; **separately** verify **warrant** under **config cert** to K_dns; **join** the two by (identity, subject, audience) (design L131-134). Two independent DNSSEC-rooted paths joined, vs today's single chain. |
| `VerifiedPresentation` / `AgentAttribution{parent,scopes}` | **CHANGE** | assertion.rs:138-155. `parent` (agent.parent) → replaced by warrant's `(identifier, subject)`; add `subject`. |
| Multi-cert chain support (host cert intermediate) | **KEEP** | assertion.rs:345-371. |

---

## F. Spec-doc section disposition

**`browserid-ng-protocol.md` (core):**
- §2 crypto/keys — **KEEP** (Ed25519, base64url, no JWK).
- §3 DNSSEC trust root + §3.1 support doc — **KEEP** (endpoints; add mint endpoint discovery).
- §4.1 user certificate — **CHANGE** → device cert (purpose×subject) + access cert + config cert; `typ` matrix rewritten.
- §4.2 host cert — **KEEP** (still the optional K_dns→K_host intermediate).
- §5 assertions / backed assertion — **CHANGE** bundle shape to `access_cert~assertion~warrant~config_cert`.
- §6.2 verification algorithm — **CHANGE** to the two-path join.
- §6.4 status list — **KEEP**, but **de-emphasized for authentication**: access certs are **IdP-gated online at mint** (design L90-97), so per-cert status matters mostly for warrants (hosted-broker registry).
- §7 primary IdP / browser integration — **KEEP** (WinChan popup is already the interactive channel; design L58-60 confirms), **ADD** device-cert issuance + mint pages/endpoints.
- §8 fallback IdPs — **KEEP** (fallback IdP == hosted broker browserid.me; design L11-14).

**`agent-provisioning-and-grant-api.md`:** largely **REPLACED**.
- §4 provisioning (delegation chain, endorse/mint/reserve) — **REMOVE/REPLACE** with device-cert issuance (incl. the headless agent device-grant/pairing) + access-cert mint API.
- §5.1 agent cert — **CHANGE** to `subject:agent` device cert.
- §5.2 warrant — **CHANGE** to warrant-v2 (subject, config-cert-signed, registry-stored).
- §5.3 presentation — **CHANGE** to the new bundle.
- §6 consent flow (RFC 8628 shape) — **KEEP shape**, but the approved artifact is a config-cert-signed warrant recorded in the hosted-broker registry.
- §7 grant exchange (RFC 7521/8414, WWW-Authenticate) — **KEEP**.

---

## G. The headless-IdP-endpoint requirement (design → spec/core landing)

Design L84-97 + L143-149: **every IdP MUST implement an HTTP access-cert mint
endpoint** (and device-cert issuance for both purposes) so agents mint
**headlessly, no browser/user in the loop**.

- Today the nearest analog is the provisioning mint API
  (`agent-provisioning §4.3 POST /provision/mint`) — but it is **gated by a
  registrar endorsement** and mints a *long-lived identity cert*, not a
  short-lived access cert. **CHANGE:** the mint endpoint becomes a
  **required core conformance item** (not a layered module), gated by the
  **authentication device cert signature alone** (access request token,
  prov.rs:348 `mint` re-cast), returning a **short-lived access cert**.
- Core §conformance (protocol.md §7/§8 has no MUST-mint clause today) **ADD**:
  "Every IdP MUST implement device-cert issuance (both purposes) and the
  access-cert mint API" (design L143-149).

---

## H. Biggest structural changes (ranked)

1. **Split durable device cert from fresh RP-facing access cert** (new mint
   step). Today the long-lived identity/agent cert is effectively the RP-rooted
   credential; the fresh-key + online-gated-mint indirection is entirely new
   (`certificate.rs` + a new mint path). ITP-proofing + headless agents both ride
   this.
2. **Warrant becomes universal and config-cert-signed.** From "agent-only,
   signed by the delegator's identity key, embeds U_cert" (`warrant.rs`) to
   "always present, over (identifier, subject)→audience, signed by an
   **authorization-purpose config cert**, stored in the hosted-broker registry."
3. **purpose × subject axes on certs** — a new least-privilege factorization
   absent from `CertificateClaims` (login ≠ authorize; user ≠ agent).
4. **Presentation bundle re-shaped** to `access_cert~assertion~warrant~config_cert`
   and verification becomes a **two-path join** by (identity, subject, audience)
   (`assertion.rs`), replacing the single embedded chain.
5. **Delegation chain (U_cert~P_cert) + registrar endorsement retired.** The
   agent device cert is issued directly by the IdP under user pairing; `P_cert`,
   `RequestBundle`, and `Endorsement` (all of `provisioning.rs`) go away or
   collapse into device-cert issuance + the mint API.
</content>
</invoke>
