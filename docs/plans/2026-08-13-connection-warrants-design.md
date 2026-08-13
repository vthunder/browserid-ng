# Connection warrants — resource-held grants for anonymous-client rails

**Date:** 2026-08-13 · **Status:** design proposal, not yet accepted · **Bean:** rjmm
**Companions:** `2026-08-02-mcp-distribution-design.md` (the lanes), core spec §5–§7.5.
**Provenance:** the Lane B design review after the mcp-demo connector E2E — the
"user→gateway consent is incoherent" critique and its resolution.

**One line:** when the party that *holds* a warrant is the same party that
*enforces* it (an OAuth-style gateway redeeming grants at its own token
endpoint), the grantee keypair proves nothing — so let the warrant's grantee be
a **descriptor** the resource evaluates at admission time, keep the user's
signature and the registrar revocation bit (the parts doing real work), and
delete the gateway's fake agent identity.

---

## 1. The problem

The auth-code lane (mcp-auth `createAuthCodeLane`; gate mounts; mcp-demo) lets
stock MCP hosts (claude.ai, Claude Code, Cursor) connect to a warrant-gated
resource through their ordinary OAuth machinery. Because the host is anonymous
— it carries no browserid identity — the lane fills the warrant's `grantee`
slot with the **resource's own service credential** ("gateway-as-agent").

Consequences, observed live on 2026-08-13:

- The consent card reads "`danmills+mcp-demo2@sandmill.org` wants permission"
  — infrastructure presented as an agent. The user is nominally granting the
  resource access to data the resource already has. Semantically incoherent.
- Every gateway deployment starts with an out-of-band provisioning ceremony
  (approve a link to mint the gateway's identity) before anything works. For
  gate — a hobbyist product whose first-run experience is the product — this
  is the single worst onboarding step, spent buying an identity whose key
  (below) proves nothing.
- /account lists the grant under the service's subaddress, so the revocation
  ledger — the protocol's headline surface — displays a fiction.

What the flow *actually* produces is a bearer + refresh capability custodied
by the **host** (claude.ai). The meaningful consent object is that
**connection**. The warrant should say so.

## 2. What each link of the presentation proves — and which are vacuous here

A §5 presentation is `access_cert ~ assertion ~ warrant ~ config_cert`, joined
by §6.1. Split by which party each link speaks for:

| Link | Signed by | Proves | In the gateway lane |
|---|---|---|---|
| `warrant` | user's config key | grantor consented: grantee, audience, scopes, revocation ref | **Load-bearing.** The consent record. |
| `config_cert` | grantor's IdP | the config key is authorized for the grantor | **Load-bearing.** Roots the consent in DNSSEC. |
| `access_cert` | grantee's IdP | this fresh key speaks for the grantee | Vacuous: the "grantee" is the resource itself. |
| `assertion` | grantee's fresh key | *the presenter holds the grantee's key*, for this audience, now | Vacuous: presenter, audience, and custodian are the same process presenting to its own embedded token endpoint. |

The access-cert/assertion half exists to answer "is the presenter really the
grantee?" — essential when grantee ≠ redeemer (a Lane A agent presenting to an
independent verifier). In the gateway lane the redeemer *is* the named
grantee, so the possession proof is self-dealing: the gateway proves to the
gateway that it is the gateway. Deleting it loses nothing — **provided the
deletion is impossible to confuse with the keyed form** (§5 below).

## 3. The proposal

### 3.1 A second warrant kind: `browserid-warrant-v2` with a descriptor grantee

Keyed warrants (`browserid-warrant-v1`) are unchanged, forever — they remain
the form for real agents that prove key possession. A new typ carries the
resource-held form:

```json
{
  "typ": "browserid-warrant-v2",
  "iat": …, "exp": …,
  "grantor": "dan@example.com",
  "grantee": { "kind": "connection",
               "client_host": "claude.ai",
               "client_name": "Claude" },
  "audience": "https://gate.dan.dev/notes",
  "scopes": ["tool:read_file", "tool:search_files"],
  "status": { "uri": "https://browserid.me/.well-known/browserid-status", "idx": 168 }
}
```

Signed by the grantor's config cert exactly as v1. Differences from v1:

- **`grantee` is a descriptor object, not an identity.** `kind` is mandatory.
  The first (and initially only) kind is `connection`: `client_host` is the
  registered redirect-URI host of the OAuth client (the enforceable datum —
  bound by the resource's AS releasing codes only to registered redirect URIs
  and PKCE tying the exchange to the authorize initiator); `client_name` is
  the DCR `client_name`, display-only and marked unverified everywhere.
- **`holder` is absent.** There is no acting keyholder to match.
- **`status` is REQUIRED**, not optional. A keyed warrant leaked without its
  key is inert; a v2 warrant's only kill switch is the registrar bit, so a v2
  warrant without one is unrevocable and MUST be rejected by verifiers and
  refused at signing time by conforming brokers.

**Why a new `typ` rather than an overloaded v1 grantee:** §6.1 step 1 already
requires verifiers to reject "any object bearing an unrecognized `typ`" —
fail-closed by explicit rule, at every conforming verifier already deployed.
An object-valued grantee inside v1 would *also* fail today's verifiers (step 6
equality against `access_cert.identity` can't hold), but that safety would be
incidental. Downgrade protection should be a stated invariant, not an accident
of comparison semantics.

**Descriptor kinds are a fail-closed registry.** A verifier or broker
encountering a `kind` it does not implement MUST reject (mirrors the §4.7
constraints rule). Future kinds sketched in §8 — none specced here.

### 3.2 A second presentation form: the two-object bundle

```
warrant ~ config_cert          (v2 warrants only)
```

Verification algorithm (new §6.1-C branch, mirroring §6.1 steps minus the
grantee path):

1. Parse exactly two objects. The warrant MUST bear `typ:
   browserid-warrant-v2` and a `grantee.kind` the verifier implements;
   the config cert as §4.3. Any other shape or typ ⇒ reject.
2. Resolve `config_cert.iss` via DNSSEC (§3); require it authoritative for the
   grantor's domain (§8.1 fallbacks apply as today).
3. Verify the config cert under the issuer key; unexpired; `purpose ==
   authorization`; `identities` match `warrant.grantor`.
4. Verify the warrant under the config cert's key; unexpired; `audience` ==
   the expected audience (exact match, §5 normalization).
5. Enforce config-cert constraints (§4.7) against the warrant's scopes and
   ttl. Unknown constraint key ⇒ reject.
6. **Two fail-closed status authorities:** the config cert (→ its IdP) and the
   warrant (→ broker registry). (The access-cert authority has no analogue —
   there is no device in the picture.)
7. Return grantor, the grantee **descriptor**, scopes, issuers.

**Hard invariants (the spec text MUST state all four):**

- A v1 warrant MUST NOT verify in the two-object form. (typ gate, step 1.)
- A v2 warrant MUST NOT verify in the four-object form. (§6.1 step 1 already
  rejects unrecognized typs there; state it explicitly anyway.)
- A v2 warrant without a `status` ref MUST be rejected.
- Verification of a v2 bundle establishes only that **the grant record is
  authentic and unrevoked**. It does not authenticate the caller.
  *Redemption authority is custody:* the only party that can turn the record
  into live access is the audience itself, at its own token endpoint, inside
  an OAuth exchange it initiated. Anyone else holding the warrant holds
  attributed paper — readable (a warrant "is not a secret", §5), spendable
  nowhere. The verifier API therefore needs no caller authentication, same as
  today's `/verify-access`.

### 3.3 Raising the consent request without a requester identity (§7.5 change)

Today's JIT flow (§7.5) requires the request to be **signed by the holder's
device key**, and the broker renders unknown holders deny-only — that
signature is the anti-spam/anti-phishing gate, and it is exactly what the
gateway credential currently pays for. Dropping the credential requires a
replacement proof. The request gains a type:

**Connection grant request** — raised by the *audience* (the resource),
authenticated by **proof of audience control**:

1. Resource POSTs the request: `{ type: "connection", audience, scopes,
   client: { client_host, client_name }, message? }`. One audience per request
   (this flow is per-connector-add; the 1–8 batching of agent requests does
   not apply). Broker replies with a `request_id` and a `challenge` nonce.
2. Resource publishes the nonce at
   `https://<audience-origin>/.well-known/browserid-audience-proof/<request_id>`.
   The broker fetches it over TLS (redirects refused, short timeout,
   fail-closed) before the consent page will render. Proof of origin control,
   rooted in WebPKI — the same root the audience string itself relies on when
   the RP verifies presentations.
   - *Path audiences* (gate mounts: `https://host/notes`): the proof is at
     origin scope. Origin control ⇒ authority over all its paths — true for
     gate (one operator per origin) and consistent with how audiences already
     trust their origin. The consent card always renders the **full audience**
     including path.
3. Consent page: card copy is the connection variant — "**Connect Claude
   (claude.ai) to `https://gate.dan.dev/notes`.** It will be able to use:
   read_file, search_files — attributed to you. Revocable here." The verified
   audience is rendered with the §7.5 anti-phishing prominence rules;
   `client_name` is displayed marked as reported by the site (the broker
   cannot verify the host's involvement — the *enforcement* of the client
   binding is the audience's redirect-URI + PKCE mechanics, and the card copy
   must not imply the broker verified more than it did). Approval signs one v2
   warrant with the config cert and records it in the registry with the
   descriptor, for /account display.
4. Poll/return: unchanged shape (the lane already polls the return).

Rejected alternatives for the proof: an ephemeral per-request keypair endorsed
at a well-known URL (same TLS trust root, more moving parts); unauthenticated
requests (consent-spam/phishing vector — violates the §7.5 stance). Note the
*stakes* of a forged request are bounded either way: an attacker-raised
warrant is only redeemable by the genuine audience, inside a dance the
audience initiates — the attack is annoyance-phishing, not authority theft.
The proof exists to keep the consent surface clean, not to guard a vault.

### 3.4 Redemption, refresh, revocation at the resource

- The resource holds the v2 warrant; mints bearers from it (same embedded AS,
  same scope-ceiling rule); refresh re-mints from the held warrant with **no
  re-consent and no assertion**, until warrant `exp` or revocation.
- Per-call enforcement is unchanged: bearer validation re-checks the warrant's
  status ref fail-closed (`/status/check`), same cache window, same
  revocation latency as today.
- /account renders the registry entry as a connection:
  `Claude (claude.ai) ↔ gate.dan.dev/notes · read_file, search_files ·
  Revoke`. Revoking flips the same per-grant bit as today.

## 4. What this buys

- **gate first-run drops the provisioning ceremony entirely.** No gateway
  identity, no approval link before the console works, no
  `danmills+gateway@…` artifacts. The only approvals that ever exist are
  per-connection consents that say what they mean. (This is the concrete
  prize; the demo was just the reconnaissance.)
- **The consent card and /account stop lying.** Grants name the connection.
- **The aggregation property becomes the product.** Vanilla OAuth co-locates
  consent + revocation with each resource's AS — which is why revocation is
  scattered across every site you ever consented to. Here the per-resource AS
  is demoted to commodity redemption plumbing, while consent and the kill
  switch live at the broker — the one place that scales with the *user*, not
  with the number of services. Together with keyed warrants, /account becomes
  one signed ledger with two symmetric halves: *what my agents may do
  elsewhere* (agent-held) and *who may enter my things* (resource-held).

## 5. Security analysis

**Theft matrix.**

| Compromise | Today (keyed, gateway-held) | Proposed (v2, resource-held) |
|---|---|---|
| Warrant exfiltrated from resource | Inert without the gateway key — but the key lives in the same process/env, so realistically both leak together; attacker can then mint bearers *only by being the resource* | Attributed paper; redeemable only by the genuine audience. Attacker with resource-db access already has the bearer store — identical blast radius |
| Host (claude.ai) compromise | Bearer + refresh theft | Identical — the host's custody is the real attack surface in both designs |
| Resource fully compromised | Game over (it fronts the tools) | Identical |
| Broker compromise | Consent + revocation authority lost | Identical |

Net: no attack gets cheaper. The keypair being deleted was not guarding any
transition an attacker could otherwise make.

**Downgrade:** typ-gated both directions (§3.2 invariants). A conforming v1
verifier rejects v2 objects today by the existing unknown-typ rule.

**Consent phishing:** the audience-proof plus the §7.5 rendering rules carry
the weight. Residual: a malicious *resource* can claim any `client_name` —
bounded consequence: it can only ever grant access to itself, attributed to
the approver, revocable; equivalent residual exists today.

**Privacy:** v1's "a warrant is not a secret" carries over; v2 adds the
client descriptor to the record. The bulk-enumeration caveat (§5) now also
discloses which hosts a user connects — same class of metadata, note it in
the spec's privacy paragraph.

**What is genuinely lost:** cryptographic possession proof at redemption.
That is the correct trade **exactly and only when custodian = enforcement
point**. The spec text must scope v2 to that topology in plain words, so
nobody reaches for it to represent an agent that merely *hasn't* got keys yet.

## 6. Component impact

| Component | Change |
|---|---|
| Core spec | §5: v2 warrant table + descriptor registry + privacy note. §6.1: the two-object branch + the four invariants. §6.3: status REQUIRED for v2. §7.5: connection grant request + audience proof. |
| Broker | Request endpoint + challenge fetch; consent-card connection variant; registry stores descriptor; /account connection rendering. |
| Verifier (crate + hosted `/verify-access`) | Accept the two-object bundle per §6.1-C; expose grantee descriptor in the result. |
| mcp-auth | Lane gains a credential-less mode: when the broker advertises connection requests, raise them with the audience proof; else fall back to the credential path (capability detection keeps old brokers working). `ctx.client` already shipped (0.2.1) and is unchanged. |
| gate | Once the broker + mcp-auth support lands: delete first-run provisioning; mounts raise connection requests directly. Existing installs with credentials keep working indefinitely (v1 path untouched). |
| wallet / Lane A / python SDK | Untouched — keyed warrants are the agent path, forever. |

## 7. Rollout

0. **Done (0.2.1):** bearers carry `ctx.client`; demo/gate attribution can say
   "via claude.ai" — display honesty independent of the spec change.
1. Spec PR: §5/§6/§7.5 text with the invariants above. Verifier + broker land
   behind support advertisement (AS metadata / broker discovery flag).
2. mcp-auth lane: opportunistic credential-less mode with fallback.
3. gate: first-run without provisioning; console copy update. Demo follows.
4. Revisit sunset: if MCP hosts ever carry real client identities (client
   attestation is drifting this way), keyed warrants absorb the connection
   case honestly and v2 mints can taper. v2 is deliberately shaped to be
   sunset-able: nothing downstream depends on it except the anonymous-host
   bridge.

## 8. Future descriptor kinds (directions, not commitments)

- **`person`** — "audience: admit `friend@gmail.com`, scopes S, attributed to
  me." Evaluated by making the visitor log in (§7.3 / verifyPresentation).
  This is gate's *roles table as signed grants*: today "Alice gets 4 tools on
  /notes" is an unsigned config row revocable only in the admin console; as a
  resource-held warrant signed by the admin it appears at the admin's /account
  and gains the registrar kill switch. Sharing and connecting become one
  primitive with different descriptors.
- **`origin`** — "accept calls from `zapier.com`", evaluated by TLS/origin
  auth. Standing service-to-service consent without OAuth.
- Each kind must ship with its evaluation rule and its card copy; kinds are
  fail-closed at verifiers and brokers that don't implement them.

## 9. Open questions

1. Should `grantee.connection` pin a hash of the full redirect URI set rather
   than the host? (Tighter binding vs. brittle across host-side redirect
   changes; host-only matches what the card can honestly convey.)
2. Audience-proof granularity for path audiences: is origin-scope proof
   acceptable long-term, or should multi-tenant origins (not gate's shape
   today) require path-scope proof?
3. Registry/account grouping: by client, by audience, or flat? (UX question,
   but it shapes what the registry row must store.)
4. Does the broker rate-limit connection requests per audience origin, and
   how does that interact with legitimate reconnect storms?
5. Descriptor-kind governance: spec-enumerated only, or a registry with
   x-prefixed experimental kinds?
