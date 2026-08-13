# Warrant v2 — one authorization record, two operations (presentation & admission)

**Date:** 2026-08-13, revised 2026-08-14 after review · **Status:** design proposal · **Bean:** rjmm
**Companions:** `2026-08-02-mcp-distribution-design.md` (the lanes), core spec §5–§7.5.
**Provenance:** the Lane B design review after the mcp-demo connector E2E — the
"user→gateway consent is incoherent" critique — refined in review: one record
format rather than an agent-warrant/resource-warrant split; instance binding
(`connection_id`) in the signed descriptor; "presentation" vocabulary reserved
for the operation that actually presents.

**One line:** a warrant is a grantor-signed, registrar-revocable
**authorization record**; the record format is one thing (`browserid-warrant-v2`),
and what varies is the **operation** — an agent *presents* it with proof of key
possession, or a resource *holds* it and matches an independently authenticated
subject against it, like a signed row in `/etc/passwd`. This lets OAuth-style
gateways (gate, mcp-demo) drop their self-dealing service identities while
keeping the user's signature and the broker-aggregated kill switch — the parts
doing real work.

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
  gate — whose first-run experience is the product — this is the worst
  onboarding step, spent buying an identity whose key (§2) proves nothing.
- /account lists the grant under the service's subaddress: the revocation
  ledger — the protocol's headline surface — displays a fiction.

What the flow *actually* produces is a bearer + refresh capability custodied
by the **host** (claude.ai). The meaningful consent object is that
**connection**. The warrant should say so.

## 2. What each link of a presentation proves — and which are vacuous here

A §5 presentation is `access_cert ~ assertion ~ warrant ~ config_cert`, joined
by §6.1. Split by which party each link speaks for:

| Link | Signed by | Proves | In the gateway lane |
|---|---|---|---|
| `warrant` | user's config key | grantor consented: grantee, audience, scopes, revocation ref | **Load-bearing.** The consent record. |
| `config_cert` | grantor's IdP | the config key is authorized for the grantor | **Load-bearing.** Roots the consent in DNSSEC. |
| `access_cert` | grantee's IdP | this fresh key speaks for the grantee | Vacuous: the "grantee" is the resource itself. |
| `assertion` | grantee's fresh key | *the presenter holds the grantee's key*, for this audience, now | Vacuous: presenter, audience, and custodian are the same process presenting to its own embedded token endpoint. |

The access-cert/assertion half answers "is the presenter really the grantee?"
— essential when grantee ≠ redeemer (a Lane A agent presenting to an
independent verifier). In the gateway lane the redeemer *is* the named
grantee: the possession proof is self-dealing. Deleting it loses nothing —
provided the deletion can never be confused with the keyed form (§3.3).

## 3. The proposal

### 3.1 One record format: `browserid-warrant-v2`

There is **one** warrant object. It is not "the resource-held kind" — it is
the successor format for all warrants, a strict superset of v1. What differs
per use is which operation (§3.2) consumes it and which grantee kind it names.

```json
{
  "typ": "browserid-warrant-v2",
  "iat": …, "exp": …,
  "grantor": "dan@example.com",
  "grantee": { … one of the kinds below … },
  "audience": "https://gate.dan.dev/notes",
  "scopes": ["tool:read_file", "tool:search_files"],
  "status": { "uri": "https://browserid.me/.well-known/browserid-status", "idx": 168 }
}
```

Signed by the grantor's config cert exactly as v1. `audience` (exactly one,
exact match) and `scopes` are unchanged. Two format-level differences:

- **`grantee` is an object with a mandatory `kind`.** Kinds are a fail-closed
  registry: a verifier, broker, or resource encountering a kind it does not
  implement MUST reject (mirrors the §4.7 constraints rule).
- **`status` is REQUIRED.** In v1 it is optional because a leaked warrant is
  inert without the grantee's key; v2 records can authorize with no key in
  the picture, so the registrar bit is the kill switch and a record without
  one is malformed. (This also makes the /account ledger complete by
  construction: every v2 grant is listed and revocable.)

**Grantee kinds.** Every kind defines two things: how a subject is
**authenticated**, and what its **instance-binding** field is — the axis of
"not just who, but which instance of who":

| Kind | Subject authenticated by | Instance binding | Fields |
|---|---|---|---|
| `identity` | key possession (presentation) or a browserid login (admission) | `holder` matcher — `*`, `ns.*`, or exact — v1 semantics verbatim | `{ "kind": "identity", "id": "<email>", "holder": "<matcher>" }` |
| `connection` | the resource's OAuth mechanics: codes released only to the registered redirect URI, PKCE binding the exchange to the authorize initiator | `connection_id` — broker-minted at consent, exact match, no wildcard | `{ "kind": "connection", "connection_id": "<id>", "client_host": "<redirect-URI host>", "client_name": "<DCR name, display-only>" }` |

`holder` and `connection_id` are the same concept at different layers.
`holder` pins an identity grant to a device (or device class) of that
identity — anti-fungibility across the grantee's holders (§5/§6.1). Without
`connection_id`, a connection grant naming only `client_host: claude.ai`
would be satisfiable by **any** claude.ai connection to this audience —
including someone else's, whose agent would then act attributed to the
grantor, within the grantor's scopes, on the strength of the grantor's
record. The signed record must pin the instance; resource-internal state must
not be the only thing standing between "my connection" and "any connection"
(a buggy rebind or a restore-from-backup is not an attack, and must still be
unable to cross grants). The broker mints `connection_id` at consent time —
the same moment it allocates the status index — and records both in the
registry row; the resource's AS MUST bind the bearers and refresh capability
it mints to that id.

`client_name` is display-only and marked unverified everywhere it appears.
`client_host` is the enforceable client datum (registered redirect-URI host)
and is what the consent card renders.

**v1 compatibility.** `browserid-warrant-v1` remains valid indefinitely and
is interpreted as `{ kind: "identity", id: <grantee string>, holder:
<holder claim> }`. New signing surfaces SHOULD emit v2; verifiers accept
both. Nothing deployed breaks; nothing forces migration.

### 3.2 Two operations

**Operation P — presentation verification** (§6.1, unchanged in substance):
the grantee proves possession of its key. The bundle is exactly
`access_cert ~ assertion ~ warrant ~ config_cert`; the join requires
`grantee.kind == "identity"`, `grantee.id == access_cert.identity`, and the
`holder` matcher to cover `access_cert.holder`. Only the `identity` kind can
appear here — it is the only kind that *can* prove possession.

**Operation A — record validation + subject matching** ("admission"): the
resource **holds** the record. Nothing presents the warrant — the warrant is
the row that an independently authenticated subject is matched against
(review analogy, kept deliberately: a signed row in `/etc/passwd`). Three
steps, each fail-closed:

1. **Validate the record** (on acquisition, and re-check status per use):
   a. parse; `typ` must be `browserid-warrant-v2`; `grantee.kind` must be
      implemented; `status` must be present;
   b. resolve `config_cert.iss` via DNSSEC (§3); require it authoritative for
      the grantor's domain (§8.1 fallbacks as today); verify the config cert
      (unexpired, `purpose == authorization`, `identities` cover
      `warrant.grantor`);
   c. verify the warrant under the config cert's key; unexpired; `audience`
      == this resource (exact);
   d. enforce config-cert constraints (§4.7) against scopes/ttl; unknown
      constraint key ⇒ reject;
   e. check the two status authorities fail-closed: config cert (→ its IdP)
      and warrant (→ broker registry). (No access-cert authority — no device
      in the picture.)
2. **Authenticate the subject** by the kind's method — the OAuth dance it
   custodies (`connection`), or a browserid login (`identity`). Note the
   authenticated artifact here is real and *may itself be a presentation*
   (a login bundle) — but it is the **subject's own** credential, not the
   held record.
3. **Match** the subject against the grantee, including the instance
   binding: `connection` — the dance is the one bound to `connection_id`
   (the resource MUST maintain and check this binding on every mint and
   refresh); `identity` — the login's identity equals `id` AND the `holder`
   matcher covers the login's holder. If the subject was authenticated by a
   holder-less method, a non-`*` matcher cannot be evaluated and MUST fail
   closed; `*` imposes nothing.

The same record may legitimately serve **both** operations when its kind
allows both: "Dan authorizes `alice@gmail.com` (holder `*`) at `/notes`" can
be held by the resource and satisfied by Alice's login (A), or presented by
Alice's agent with her access cert (P). The authority granted is identical
and P is the stronger proof, so nothing is gained by forbidding it; the
`holder` matcher is evaluated in both paths wherever a holder exists.

**Verifier API note.** Operation A's steps 1b–1e are exactly the §6.1
grantor-side path; the hosted verifier grows a *record validation* call (two
objects: `warrant ~ config_cert`) alongside `/verify-access`. Validation
establishes only that **the record is authentic and unrevoked** — it does not
authenticate a caller, and needs no caller authentication: redemption
authority is custody plus subject matching, which happen at the resource.
Anyone else holding the record holds attributed paper (a warrant "is not a
secret", §5) — readable, spendable nowhere.

### 3.3 Hard invariants

The spec text MUST state all of these:

1. Operation P accepts only `grantee.kind == "identity"` (v1 or v2). A
   `connection` record MUST NOT verify in a four-object bundle — there is no
   access cert it could join with, and verifiers MUST reject the kind in
   that position explicitly, not incidentally.
2. Conforming v1 verifiers already reject v2 objects (unknown `typ` ⇒ reject,
   §6.1 step 1) — downgrade protection at every deployed verifier is by
   explicit rule, and the new text restates it.
3. A v2 record without `status` MUST be rejected by verifiers and refused at
   signing time by conforming brokers.
4. In operation A, a subject-matching step that cannot be evaluated (unknown
   kind; non-`*` holder matcher with a holder-less authentication; missing
   `connection_id` binding) MUST fail closed.
5. Record validation authenticates no one. Only presentation (P) or the
   kind's subject authentication (A step 2) establishes an acting party.

### 3.4 Raising the consent request without a requester identity (§7.5 change)

Today's JIT flow (§7.5) requires the request to be **signed by the holder's
device key** — the anti-spam/anti-phishing gate, and exactly what the gateway
credential currently pays for. Connection grants need a replacement proof.
The request gains a type:

**Connection grant request** — raised by the *audience* (the resource),
authenticated by **proof of audience control**:

1. Resource POSTs `{ type: "connection", audience, scopes, client:
   { client_host, client_name }, message? }`. One audience per request (this
   flow is per-connector-add; §7.5's 1–8 batching does not apply). Broker
   replies with `request_id` and a `challenge` nonce.
2. Resource publishes the nonce at
   `https://<audience-origin>/.well-known/browserid-audience-proof/<request_id>`;
   the broker fetches it over TLS (redirects refused, short timeout,
   fail-closed) before the consent page will render. Proof of origin control,
   rooted in WebPKI — the same root the audience string itself relies on.
   *Path audiences* (gate mounts): the proof is at origin scope; origin
   control ⇒ authority over its paths (true for gate's one-operator-per-origin
   shape). The card always renders the **full audience** including path.
3. Consent card, connection variant: "**Connect Claude (claude.ai) to
   `https://gate.dan.dev/notes`.** It will be able to use: read_file,
   search_files — attributed to you. Revocable here." The verified audience
   is rendered with §7.5's anti-phishing prominence; `client_name` is marked
   as reported by the site — the broker cannot verify the host's
   involvement, and the card must not imply it did (the client binding is
   enforced by the audience's redirect-URI + PKCE mechanics, §3.1). Approval
   mints `connection_id`, signs the v2 record with the config cert, and
   stores the registry row (descriptor + status idx) for /account.
4. Poll/return: unchanged shape (the lane already polls the return).

Rejected alternatives for the proof: ephemeral per-request keypair endorsed
at a well-known URL (same TLS trust root, more moving parts); unauthenticated
requests (consent-spam vector — violates §7.5's stance). Stakes of a forged
request are bounded either way: an attacker-raised record is redeemable only
by the genuine audience, inside a dance the audience initiates — the attack
is annoyance-phishing, not authority theft. The proof keeps the consent
surface clean; it is not guarding a vault.

### 3.5 Redemption, refresh, revocation at the resource

- The resource holds the record; mints bearers from it (same embedded AS,
  same scope-ceiling rule), **bound to `connection_id`**; refresh re-mints
  with no re-consent and no assertion, until record `exp` or revocation.
- Per-call enforcement unchanged: bearer validation re-checks the record's
  status ref fail-closed (`/status/check`), same cache window — revocation
  latency identical to today.
- /account renders the registry row as a connection: `Claude (claude.ai) ↔
  gate.dan.dev/notes · read_file, search_files · Revoke`. Two connections
  from the same host are two rows (distinct `connection_id`s), independently
  revocable.

## 4. What this buys

- **gate first-run drops the provisioning ceremony entirely.** No gateway
  identity, no approval link before the console works, no
  `danmills+gateway@…` artifacts. The only approvals that ever exist are
  per-connection consents that say what they mean. (The concrete prize; the
  demo was the reconnaissance.)
- **The consent card and /account stop lying.** Grants name the connection,
  with per-connection revocation rows.
- **The aggregation property becomes the product.** Vanilla OAuth co-locates
  consent + revocation with each resource's AS — which is why revocation is
  scattered across every site you ever consented to. Here the per-resource AS
  is demoted to commodity redemption plumbing while consent and the kill
  switch live at the broker — the one place that scales with the *user*, not
  the number of services. /account becomes one signed ledger with two
  symmetric halves: *what my agents may do elsewhere* (records they present)
  and *who may enter my things* (records my resources hold).
- **Sharing and connecting become one primitive.** `identity`-kind records in
  operation A are gate's roles table as signed grants — "admit
  `friend@gmail.com`, these tools" — listed and revocable at the granting
  admin's /account. No new kind needed; it falls out of the model.

## 5. Security analysis

**Theft matrix.**

| Compromise | Today (keyed, gateway-held) | Proposed (v2, resource-held) |
|---|---|---|
| Record exfiltrated from resource | Inert without the gateway key — but the key lives in the same process/env, so realistically both leak together; the thief can mint only *by being the resource* | Attributed paper; redeemable only by the genuine audience, and `connection_id` pins it to one connection even inside that audience |
| Sloppy resource (buggy rebind, restore-from-backup) | Same class of bug possible in bearer↔warrant state | **Improved:** the instance binding is in the signed record; honest-but-buggy state cannot silently attach a grant to a different connection without failing the `connection_id` match |
| Host (claude.ai) compromise | Bearer + refresh theft | Identical — host custody is the real surface in both designs |
| Resource fully compromised | Game over (it fronts the tools) | Identical |
| Broker compromise | Consent + revocation authority lost | Identical |

Net: no attack gets cheaper; the sloppy-resource row gets strictly harder.

**Downgrade:** invariants 1–2 (§3.3): kind-gated at operation P, typ-gated at
v1 verifiers.

**Consent phishing:** audience-proof (§3.4) plus §7.5 rendering rules.
Residual: a malicious *resource* can claim any `client_name` — bounded: it
can only grant access to itself, attributed and revocable; the equivalent
residual exists today.

**Privacy:** v1's "a warrant is not a secret" carries over; v2 adds the
client descriptor, so bulk enumeration (§5's existing caveat) now also
discloses which hosts a user connects — same class of metadata; the spec's
privacy paragraph gains a sentence.

**What is genuinely lost:** cryptographic possession proof at redemption, for
`connection` records only. That is the correct trade exactly and only when
custodian = enforcement point; the spec text scopes the kind to that
topology in plain words, so nobody reaches for it to represent an agent that
merely hasn't got keys yet. `identity` records lose nothing — operation P
remains available and preferred wherever the subject can present.

## 6. Component impact

| Component | Change |
|---|---|
| Core spec | §5: v2 record format, grantee-kind table, instance-binding concept, status REQUIRED, privacy sentence. §6: operation A ("record validation + subject matching") beside §6.1, invariants §3.3. §7.5: connection grant request + audience proof. Vocabulary: "presentation" reserved for operation P. |
| Broker | Request endpoint + challenge fetch; consent-card connection variant; `connection_id` mint; registry row (descriptor + status idx); /account connection rendering. |
| Verifier (crate + hosted) | v2 parsing (both operations); record-validation call (`warrant ~ config_cert`); v1 accepted as identity-kind sugar. |
| mcp-auth | Lane gains a credential-less mode: when the broker advertises connection requests, raise them with the audience proof; else fall back to the credential path (capability detection keeps old brokers working). Bearer/refresh binding to `connection_id`. `ctx.client` (0.2.1, shipped) gains the id. |
| gate | Once broker + mcp-auth land: delete first-run provisioning; mounts raise connection requests directly. Existing installs with credentials keep working indefinitely (v1 path untouched). Later: roles-as-signed-grants via identity-kind records (§4). |
| wallet / Lane A / python SDK | Untouched — keyed presentation is the agent path, unchanged. |

## 7. Rollout

0. **Done (mcp-auth 0.2.1):** bearers carry `ctx.client`; demo/gate
   attribution says "via claude.ai" — display honesty independent of the
   spec change.
1. Spec PR: §5/§6/§7.5 text per above, including the five invariants.
   Verifier + broker land behind support advertisement (broker discovery
   flag).
2. mcp-auth lane: opportunistic credential-less mode with fallback;
   `connection_id` binding.
3. gate: first-run without provisioning; console copy update. Demo follows.
4. Revisit sunset: if MCP hosts ever carry real client identities (client
   attestation is drifting this way), identity-kind presentation absorbs the
   connection case honestly and `connection`-kind mints taper. The kind is
   deliberately shaped to be sunset-able: nothing depends on it except the
   anonymous-host bridge.

## 8. Future grantee kinds (directions, not commitments)

- **`origin`** — "accept calls from `zapier.com`", subject authenticated by
  TLS/origin auth; instance binding TBD (per-integration id, same pattern as
  `connection_id`). Standing service-to-service consent without OAuth.
- Each kind must ship with its authentication method, its instance-binding
  field, and its consent-card copy; kinds are fail-closed everywhere they are
  not implemented. (`person` from the earlier draft is not a kind — it is
  `identity` in operation A.)

## 9. Open questions

1. Audience-proof granularity for path audiences: is origin-scope proof
   acceptable long-term, or should multi-tenant origins (not gate's shape
   today) require path-scope proof?
2. `connection_id` shape: opaque broker UUID (proposed) vs something
   derivable (e.g. hash of client registration) — opaque is safer (no
   cross-audience correlation), but consider whether the resource should be
   able to recognize a re-consent for the "same" connection.
3. Registry/account grouping: by client, by audience, or flat? (UX; shapes
   the registry row.)
4. Broker rate-limiting of connection requests per audience origin, and the
   interaction with legitimate reconnect storms.
5. Grantee-kind governance: spec-enumerated only, or a registry with
   x-prefixed experimental kinds?
6. Should operation-A validation results be cacheable at the resource
   (record validated once at acquisition, status re-checked per use — the
   proposed split), or must the full chain re-verify per mint? (Proposed:
   the split above; the chain is immutable, status is the live part.)
