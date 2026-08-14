# Warrant v2 — one authorization record, two operations, email-rooted bindings

**Date:** 2026-08-13, revised 2026-08-14 (six review rounds) · **Status:** design proposal · **Bean:** rjmm
**Companions:** `2026-08-02-mcp-distribution-design.md` (the lanes), core spec §5–§7.5.
**Provenance:** the Lane B design review after the mcp-demo connector E2E — the
"user→gateway consent is incoherent" critique — refined across review into:
one record format (not an agent-warrant/resource-warrant split); grantee
always an email, with **bindings** (holder / connection) as the instance
qualifier; connection records as **self-grants narrowed to a custody
channel**; composition of policy × connection records; "presentation"
vocabulary reserved for the operation that actually presents.

**One line:** a warrant is a grantor-signed, registrar-revocable
**authorization record** whose grantee is always an email identity; a
**binding** pins the instance — a `holder` matcher (device; presentable) or a
`connection` (custody channel; admission-only, always a self-grant). An agent
*presents* a holder-bound record with proof of key possession; a resource
*holds* a record and matches an independently authenticated subject against
it, like a signed row in `/etc/passwd`. This lets OAuth-style gateways (gate,
mcp-demo) drop their self-dealing service identities while keeping the user's
signature and the broker-aggregated kill switch — the parts doing real work.

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
**connection** — and the identity behind it was never in doubt: the person
who approved it. The problem was never that the grantee was an email; it was
the **wrong** email (infrastructure's). The format lacked a way to say "this
person, via this custody channel."

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

There is **one** warrant object — the successor format for all warrants, a
strict superset of v1. The grantee is **always an email identity** (a string,
exactly as v1); what varies is the **binding** — the instance qualifier that
pins *which instance of the grantee* may exercise the grant — and which
operation (§3.2) consumes the record.

```json
{
  "typ": "browserid-warrant-v2",
  "iat": …, "exp": …,
  "grantor": "friend@example.com",
  "grantee": "friend@example.com",
  "connection": { "id": "cn_8f3a…", "client_host": "claude.ai",
                  "client_name": "Claude" },
  "audience": "https://gate.dan.dev/notes",
  "scopes": ["tool:read_file", "tool:search_files"],
  "status": { "uri": "https://browserid.me/.well-known/browserid-status", "idx": 168 }
}
```

Signed by the grantor's config cert exactly as v1. `grantor`, `grantee`
(email strings), `audience` (exactly one, exact match) and `scopes` are
unchanged from v1. Format-level changes:

- **Exactly one binding claim** is present — `holder` or `connection`:

  | Binding | Meaning | Subject authenticated by | Operations |
  |---|---|---|---|
  | `holder` | v1 semantics verbatim: a matcher (`*`, `ns.*`, exact) over the grantee's device holders | key possession (access cert + assertion), or a browserid login carrying a holder | P and A |
  | `connection` | a custody channel: `{ id, client_host, client_name }` — `id` broker-minted at consent, exact, no wildcard | the resource's OAuth mechanics: codes released only to the registered redirect URI, PKCE binding the exchange to the authorize initiator | A only |

  Binding kinds are a fail-closed registry: a verifier or resource
  encountering a binding it does not implement MUST reject (mirrors the
  §4.7 constraints rule). Bindings are **not identities** and never appear
  where identities live.

- **`connection` implies a self-grant:** a record carrying a `connection`
  binding MUST have `grantor == grantee`. The connection record is the
  grantor's own grant to themselves, narrowed to one custody channel — the
  exact shape §5 already gives self-logins (grantor == grantee), plus the
  qualifier. Identities are always emails; a connection is not an identity,
  but every connection is bound to one: **its record's signer**.
- **`status` is REQUIRED.** In v1 it is optional because a leaked warrant is
  inert without the grantee's key; a connection-bound record authorizes with
  no grantee key in the picture, so the registrar bit is the kill switch and
  a record without one is malformed. (Requiring it on all v2 records also
  makes the /account ledger complete by construction.)

**Why `connection.id` must be in the signed record.** Without it, a record
naming only `client_host: claude.ai` would be satisfiable by **any**
claude.ai connection to this audience — including someone else's, whose
agent would then act attributed to the grantor, within the grantor's scopes.
The signed record must pin the instance; resource-internal state must not be
the only thing standing between "my connection" and "any connection" (a
buggy rebind or a restore-from-backup is not an attack, and must still be
unable to cross grants). `holder` and `connection.id` are the same concept
at different layers: not just *who*, but *which instance of who* — which
device of the identity, or which custody channel of the identity.

`client_name` is display-only and marked unverified everywhere it appears.
`client_host` is the enforceable client datum (registered redirect-URI host)
and is what the consent card renders.

**v1 compatibility.** `browserid-warrant-v1` remains valid indefinitely and
is interpreted as a v2 record with a `holder` binding. New signing surfaces
SHOULD emit v2; verifiers accept both. Nothing deployed breaks; nothing
forces migration. (Old verifiers reject v2 by the existing unknown-`typ`
rule — see invariants.)

### 3.2 Two operations

**Operation P — presentation verification** (§6.1, unchanged in substance):
the grantee proves possession of its key. The bundle is exactly
`access_cert ~ assertion ~ warrant ~ config_cert`; the join requires
`grantee == access_cert.identity` and the `holder` matcher to cover
`access_cert.holder`. **Presentability is governed mechanically by the
binding:** §6.1 already fail-closes on a missing `holder`, so a
connection-bound record (which has none) cannot present — no new rule
needed, only the existing one restated.

**Operation A — record validation + subject matching** ("admission"): the
resource **holds** the record. Nothing presents the warrant — the warrant is
the row that an independently authenticated subject is matched against
(review analogy, kept deliberately: a signed row in `/etc/passwd`). Three
steps, each fail-closed:

1. **Validate the record** (on acquisition, and re-check status per use):
   a. parse; `typ` must be `browserid-warrant-v2` (or v1, as a
      holder-binding record); exactly one binding claim, of an implemented
      kind; `status` present (v2);
   b. resolve `config_cert.iss` via DNSSEC (§3); require it authoritative for
      the grantor's domain (§8.1 fallbacks as today); verify the config cert
      (unexpired, `purpose == authorization`, `identities` cover
      `warrant.grantor`);
   c. verify the warrant under the config cert's key; unexpired; `audience`
      == this resource (exact); if `connection` is present, `grantor ==
      grantee`;
   d. enforce config-cert constraints (§4.7) against scopes/ttl; unknown
      constraint key ⇒ reject;
   e. check the two status authorities fail-closed: config cert (→ its IdP)
      and warrant (→ broker registry).
2. **Authenticate the subject** by the binding's method — the OAuth dance it
   custodies (`connection`), or a browserid login (`holder`). The
   authenticated artifact here is real and *may itself be a presentation*
   (a login bundle) — but it is the **subject's own** credential, not the
   held record.
3. **Match** the subject against grantee + binding: `connection` — the dance
   is the one bound to `connection.id` (see the 1:1 rule below);
   `holder` — the login's identity equals `grantee` AND the matcher covers
   the login's holder. A matching step that cannot be evaluated (unknown
   binding; non-`*` matcher with a holder-less authentication) MUST fail
   closed; `*` imposes nothing.

The same record may serve **both** operations when its binding allows: "Dan
authorizes `alice@gmail.com` (holder `*`) at `/notes`" can be held by the
resource and satisfied by Alice's login (A), or presented by Alice's agent
with her access cert (P). The authority is identical and P is the stronger
proof; nothing is gained by forbidding it.

**Why both operations exist** (rationale, for the spec's design notes). The
two operations are the capabilities/ACL duality: P is **authority that
travels with the actor** — self-contained, verifiable by anyone, anywhere,
later; A is **authority that sits at the resource** — a signed row, right for
anonymous-client rails where the resource is the enforcement point anyway.
Neither subsumes the other:

- A cannot replace P, structurally: admitting an email subject means
  authenticating a browserid login — which *is* a presentation (the §7.3
  self-login bundle). The regress bottoms out at P; A is a composition
  pattern over it for subjects that cannot present.
- Dropping *delegated* P (agent-held records) specifically would lose:
  (1) **stateless first contact** — a presenting agent shows up cold and the
  resource verifies without becoming a registry (the guestbook shape);
  (2) **third-party and offline verifiability** — a presentation is checkable
  by anyone via detached DNSSEC proofs (§6.2); the on-chain attribution
  module verifies presented chains trustlessly, and an admission decision is
  only a local yes in the resource's logs;
  (3) **the actor as an independently accountable principal** — P
  establishes the agent (identity, holder, certs) with its own revocation
  axis at its own IdP: two kill switches on orthogonal authorities, where a
  connection admission has exactly one (the record's bit);
  (4) **non-interactive actorhood** — a headless agent mints and presents
  with no human present (§7.4 → §7.2).

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

1. Operation P requires a `holder` binding; a `connection`-bound record MUST
   NOT verify in a four-object bundle. (Mechanically: no holder ⇒ §6.1
   step 1 reject; state it explicitly anyway.)
2. Conforming v1 verifiers already reject v2 objects (unknown `typ` ⇒ reject,
   §6.1 step 1) — downgrade protection at every deployed verifier is by
   explicit rule, and the new text restates it.
3. A v2 record without `status`, or with zero or multiple binding claims, or
   with an unimplemented binding kind, MUST be rejected. Signing surfaces
   MUST refuse to mint such records.
4. A `connection`-bound record MUST be a self-grant (`grantor == grantee`).
5. **`connection.id` is 1:1 with its record:** the id is minted by the
   broker in one consent flow and bound to the record signed in that same
   flow; the resource MUST bind bearers/refresh to that (id, record) pair,
   and any other record naming the same id is invalid. The registry stores
   the pairing, making conflicts detectable.
6. In operation A, a subject-matching step that cannot be evaluated MUST
   fail closed.
7. Record validation authenticates no one. Only presentation (P) or the
   binding's subject authentication (A step 2) establishes an acting party.
8. **Containment:** email is the protocol's only identity type. Bindings are
   warrant-local instance qualifiers, not identities; they MUST NOT appear
   in identity slots (grantor, grantee, certs, principal registries) or be
   treated as authenticatable identities anywhere. Grants to unattributable
   subjects ("anyone with this link") are out of scope by design — every
   grant roots in a signing email; bearer-style anonymous access is
   antithetical to an attribution protocol. (Invite-link UX, if wanted, is a
   broker flow converting acceptance into an email policy record.)

### 3.4 Composition: policy records × connection records

A connection is never anonymous: its identity is **its record's signer**,
pinned at the only moment it can be — consent — when the broker mints
`connection.id` during a flow in which the connecting user is logged in and
their config cert signs the (self-grant) record.

The shared-resource scenario (admin G grants friend E access to R; E later
connects via host A) is a **two-record chain** — each record signed by the
party who knows its contents at signing time; no signed object is ever
amended or late-bound:

1. **Policy record** (G-signed, at role-grant time):
   `{grantor: G, grantee: E, holder: "*", audience: R, scopes: S}`.
   G knows E, R, S — and nothing about future connections (G does not need
   to know A or C).
2. **Connection record** (E-signed, at connection time):
   `{grantor: E, grantee: E, connection: {id: C, client_host: A},
   audience: R, scopes: S′}`. Born when C is born, at E's own consent card
   ("Connect Claude to Dan's notes — a grant to yourself, exercised through
   this connection").

Admission at R conjoins them: authenticate the dance bound to C (§3.2 A);
C's record is signed by E; E matches a policy record; **effective scopes =
S ∩ S′**. Composition rules:

- **Attribution vs. permission.** The connection record's signer (E) is the
  *attributed* identity — E acted. The policy record's grantor (G) is the
  *permitter* — the reason it was allowed, never the author. Audit
  rendering: "E, via <client> (<host>), under G's grant." Conflating these
  is the self-serve special case G = E, where the distinction is invisible.
- **Two-sided revocation.** E revokes the connection record at E's /account
  (kills E's own connection, touches nothing else); G revokes the policy
  record (kills E's access through every connection). Each side holds its
  own registrar bit.
- **Host constraints — future work.** G MAY want to constrain custody in the
  policy record ("E may connect via claude.ai but not X"). Warrants
  currently carry **no** constraints mechanism (§4.7 constraints live on
  certs and are checked *against* warrants); a policy-record host constraint
  would be the first warrant-level constraint. Deliberately deferred; the
  cert-constraint machinery is the precedent to follow if/when.
- **The chain is exactly two layers, fail-closed.** Policy records (who may
  enter) and connection records (which custody channel, attributed to whom)
  conjoin at admission; records MUST NOT confer the authority to mint
  further records. (A general delegation-chain mechanism is UCAN's product;
  depth-two conjunction is deliberately all this design admits.)
- **Self-serve degenerate case:** G = E; the policy record is the admin's
  implicit full access (today's gate roles for the admin); only the
  connection record exists concretely — exactly the current flow.

Deployment note: gate's roles table is the policy layer already, unsigned;
§4's roles-as-signed-grants migrates it to email policy records
incrementally. The conjunction semantics above hold either way — config-row
policy and record policy answer the same admission question.

### 3.5 Raising the consent request without a requester identity (§7.5 change)

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
   mints `connection.id`, signs the self-grant record with the approver's
   config cert, and stores the registry row (id ↔ record pairing + status
   idx) for /account.
4. Poll/return: unchanged shape (the lane already polls the return).

Rejected alternatives for the proof: ephemeral per-request keypair endorsed
at a well-known URL (same TLS trust root, more moving parts); unauthenticated
requests (consent-spam vector — violates §7.5's stance). Stakes of a forged
request are bounded either way: an attacker-raised record is redeemable only
by the genuine audience, inside a dance the audience initiates — the attack
is annoyance-phishing, not authority theft. The proof keeps the consent
surface clean; it is not guarding a vault.

### 3.6 Redemption, refresh, revocation at the resource

- The resource holds the record; mints bearers from it (same embedded AS,
  same scope-ceiling rule), **bound to the (connection.id, record) pair**;
  refresh re-mints with no re-consent and no assertion, until record `exp`
  or revocation.
- Per-call enforcement unchanged: bearer validation re-checks the record's
  status ref fail-closed (`/status/check`), same cache window — revocation
  latency identical to today.
- /account renders the registry row as a connection: `Claude (claude.ai) ↔
  gate.dan.dev/notes · read_file, search_files · Revoke`. Two connections
  from the same host are two rows (distinct ids), independently revocable.

## 4. What this buys

- **gate first-run drops the provisioning ceremony entirely.** No gateway
  identity, no approval link before the console works, no
  `danmills+gateway@…` artifacts. The only approvals that ever exist are
  per-connection consents that say what they mean. (The concrete prize; the
  demo was the reconnaissance.)
- **The consent card and /account stop lying.** Grants name the person and
  the connection, with per-connection revocation rows.
- **The aggregation property becomes the product.** Vanilla OAuth co-locates
  consent + revocation with each resource's AS — which is why revocation is
  scattered across every site you ever consented to. Here the per-resource AS
  is demoted to commodity redemption plumbing while consent and the kill
  switch live at the broker — the one place that scales with the *user*, not
  the number of services. /account becomes one signed ledger with two
  symmetric halves: *what my agents may do elsewhere* (records they present)
  and *who may enter my things* (records my resources hold).
- **Sharing and connecting become one primitive.** Email policy records in
  operation A are gate's roles table as signed grants — "admit
  `friend@gmail.com`, these tools" — listed and revocable at the granting
  admin's /account. It falls out of the model.

## 5. Security analysis

**Theft matrix.**

| Compromise | Today (keyed, gateway-held) | Proposed (v2, resource-held) |
|---|---|---|
| Record exfiltrated from resource | Inert without the gateway key — but the key lives in the same process/env, so realistically both leak together; the thief can mint only *by being the resource* | Attributed paper; redeemable only by the genuine audience, and the 1:1 `connection.id` rule pins it to one channel even inside that audience |
| Sloppy resource (buggy rebind, restore-from-backup) | Same class of bug possible in bearer↔warrant state | **Improved:** the instance binding is in the signed record; honest-but-buggy state cannot silently attach a grant to a different connection without failing the id match |
| Host (claude.ai) compromise | Bearer + refresh theft | Identical — host custody is the real surface in both designs |
| Resource fully compromised | Game over (it fronts the tools) | Identical |
| Broker compromise | Consent + revocation authority lost | Identical |

Net: no attack gets cheaper; the sloppy-resource row gets strictly harder.

**Downgrade:** invariants 1–2 (§3.3): binding-gated at operation P, typ-gated
at v1 verifiers.

**Consent phishing:** audience-proof (§3.5) plus §7.5 rendering rules.
Residual: a malicious *resource* can claim any `client_name` — bounded: it
can only grant access to itself, attributed and revocable; the equivalent
residual exists today.

**Privacy:** v1's "a warrant is not a secret" carries over; v2 adds the
client descriptor, so bulk enumeration (§5's existing caveat) now also
discloses which hosts a user connects — same class of metadata; the spec's
privacy paragraph gains a sentence.

**What is genuinely lost:** cryptographic possession proof at redemption, for
connection-bound records only. That is the correct trade exactly and only
when custodian = enforcement point; the spec text scopes the binding to that
topology in plain words. Holder-bound records lose nothing — operation P
remains available and preferred wherever the subject can present.

## 6. Component impact

| Component | Change |
|---|---|
| Core spec | §5: v2 record format, bindings table (holder/connection), instance-binding concept, status REQUIRED, self-grant rule, privacy sentence. §6: operation A ("record validation + subject matching") beside §6.1, invariants §3.3, composition §3.4. §7.5: connection grant request + audience proof (§3.5). Vocabulary: "presentation" reserved for operation P; identities are always emails. |
| Broker | Request endpoint + challenge fetch; consent-card connection variant; `connection.id` mint + id↔record registry pairing; /account connection rendering. |
| Verifier (crate + hosted) | v2 parsing (both operations); record-validation call (`warrant ~ config_cert`); v1 accepted as holder-binding sugar. |
| mcp-auth | Lane gains a credential-less mode: when the broker advertises connection requests, raise them with the audience proof; else fall back to the credential path (capability detection keeps old brokers working). Bearer/refresh binding to (connection.id, record). `ctx.client` (0.2.1, shipped) gains the id. |
| gate | Once broker + mcp-auth land: delete first-run provisioning; mounts raise connection requests directly. Existing installs with credentials keep working indefinitely (v1 path untouched). Later: roles as email policy records (§4). |
| wallet / Lane A / python SDK | Untouched — keyed presentation is the agent path, unchanged. |

## 7. Rollout

0. **Done (mcp-auth 0.2.1):** bearers carry `ctx.client`; demo/gate
   attribution says "via claude.ai" — display honesty independent of the
   spec change.
1. Spec PR: §5/§6/§7.5 text per above, including the eight invariants.
   Verifier + broker land behind support advertisement (broker discovery
   flag).
2. mcp-auth lane: opportunistic credential-less mode with fallback;
   (connection.id, record) binding.
3. gate: first-run without provisioning; console copy update. Demo follows.
4. Revisit sunset: if MCP hosts ever carry real client identities (client
   attestation is drifting this way), holder-bound presentation absorbs the
   connection case honestly and connection-binding mints taper. The binding
   is deliberately shaped to be sunset-able: nothing depends on it except
   the anonymous-host bridge.

## 8. Future binding kinds (directions, not commitments)

- **`origin`** — "accept calls from `zapier.com`", a self-grant bound to an
  origin, subject authenticated by TLS/origin auth; instance binding per
  integration, same pattern as `connection.id`. Standing service-to-service
  consent without OAuth, attributed to the signer.
- Each binding must ship with its authentication method, its
  instance-binding field, and its consent-card copy; bindings are
  fail-closed everywhere they are not implemented.

## 9. Open questions

1. Audience-proof granularity for path audiences: is origin-scope proof
   acceptable long-term, or should multi-tenant origins (not gate's shape
   today) require path-scope proof?
2. `connection.id` shape: opaque broker UUID (proposed) vs something
   derivable — opaque is safer (no cross-audience correlation), but consider
   whether the resource should be able to recognize a re-consent as "the
   same connection."
3. Registry/account grouping: by client, by audience, or flat? (UX; shapes
   the registry row.)
4. Broker rate-limiting of connection requests per audience origin, and the
   interaction with legitimate reconnect storms.
5. Binding-kind governance: spec-enumerated only, or a registry with
   x-prefixed experimental kinds?
6. Should operation-A validation results be cacheable at the resource
   (record validated once at acquisition, status re-checked per use — the
   proposed split), or must the full chain re-verify per mint? (Proposed:
   the split above; the chain is immutable, status is the live part.)
7. **DIDs — considered, disfavored (review round 4).** Could grantee (or
   grantor) be a DID, making the warrant a generic "A grants B" object?
   Findings: (a) emails have no standard DID method — a `did:browserid:` would
   be our namespace in a `did:` costume, same DNSSEC root, plus a translation
   layer on every user-facing surface; (b) a connection is not a DID-shaped
   subject — no keys, no document, and the load-bearing field is the
   *instance binding*, which DID semantics don't model (`did:web:claude.ai`
   names the client, not the connection); (c) a DID grantor breaks §6.1
   step 5 while certs stay email-bound — it needs either a second trust root
   (DID-document key control beside DNSSEC) or an email adapter that makes
   the email canonical anyway; (d) the generic DID-capability product exists
   (UCAN/ZCAP) — the warrant's differentiator is precisely what they lack:
   human-legible email attribution + registrar revocation on DNSSEC roots.
   Resolution: **email stays the protocol's only identity type; bindings are
   warrant-local instance qualifiers, valid nowhere else** (invariant 8).
   Foreign identity systems integrate via the existing adapter direction:
   mapped *into* email space at a bridge domain (the bsky pattern, `did:plc`
   → `<handle>@bsky.browserid.me`), never the core reaching outward.
   *(Round 6 note: the grantee-kind vocabulary this entry originally argued
   about was retired entirely — grantee is now always an email string, and
   the extension point moved to bindings, which nobody can mistake for
   identities.)*
8. Canonical **string rendering** for connections (logs, audit lines,
   attribution): the structured claim is normative, but a printable form is
   wanted. An email-shaped synthetic namespace
   (`<connection-id>@connections.<broker-domain>`) was considered and is
   disfavored: email-shape in this ecosystem connotes an authenticatable
   principal (can log in, can hold certs, can be added to roles/address
   books), and the gateway-as-agent problem this design removes was exactly
   an email-shaped name wrapped around infrastructure. Current lean: a
   deliberately non-email URI form (e.g. `connection:claude.ai/cn_8f3a…`),
   with minting authority carried by the registry row rather than an
   @-domain. Open whether that form appears in the spec or stays an
   implementation convention.
