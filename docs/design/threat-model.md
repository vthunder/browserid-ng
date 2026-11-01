<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# browserid-ng threat model

> **Status: review draft, 2026-11-01.** Written for the 2026-11 security
> audit (bean `browserid-ng-ag1l`, workstream WS1). It names the
> adversaries, what each can see and send, the assets each is after, and the
> invariants the rest of the audit tests. Section references are to
> `docs/specs/browserid-ng-protocol.md` unless prefixed `reg` (registry-api-v1)
> or `fb` (fallback-idp-api-v1).

## 1. The flows, and who touches what

Five flows carry every credential in the system. Each line names the parties
that see an object in transit; an adversary is whichever of them is hostile.

**F1. Issuance (§7.1, §7.4, fb §3).** Wallet generates device + config keys →
opens the issuer's ceremony page (fallback: browserid.me; primary: the
domain's own IdP; hosted primary: browserid.me acting under a tenant key) →
user authenticates → issuer signs auth cert + config cert, returns them to
`return_url`. Headless: the agent's pubkey is paired via the user's wallet and
the IdP signs on the user's approval. Sees the certs: wallet, issuer, any
origin that receives the return fragment.

**F2. Mint (§7.2).** Holder signs an access request with its auth key → IdP
checks the device cert online (signature, status bit, validity, identity in
list) → returns a 24 h access cert on a fresh key. Sees it: holder, IdP.

**F3. Presentation and verification (§5, §6.1).** Wallet signs an assertion
for one audience and a login warrant (or reuses a stored one) → delivers
`access_cert~assertion~warrant~config_cert` to the RP → RP verifies through two
DNSSEC paths, three status lists, and the join. Sees the bundle: RP, hosted
verifier at browserid.me if the RP uses it, any page script on the RP origin.

**F4. Warrant consent (§7.5, reg §5.3).** Agent or resource files a request →
registry allocates status index (and `binding.id` for connections) → user's
wallet renders the card, signs with the config cert → registry stores the
record → filer polls once. Sees the record: wallet, registry, filer, and for
admission records the resource that holds it.

**F5. Account management (reg §4–5).** Wallet logs in to the registry with a
login key (page or stored key) → session → attach certs, revoke, policy,
approvals, inbox. Sees the session: wallet, registry.

## 2. Adversaries

| # | Adversary | Position | Sees | Can send | Wants |
|---|---|---|---|---|---|
| A1 | Malicious RP / page | Any web origin the user visits | Bundles presented to it; whatever `navigator.id` leaks | Login requests, filed requests with spoofed origins, return_url tricks, FedCM calls | A bundle valid at *another* audience; a warrant wider than consented; a config cert bound to its keys (fb §3.1) |
| A2 | Malicious agent / MCP server / resource | Holds a device cert for an agent identity, or runs an audience | Warrants granted to it, access certs it mints | JIT requests, connection requests, mint requests, scope strings | Scope widening, attribution to a grantor who never consented, acting after revocation, reaching a second audience |
| A3 | Malicious primary IdP | Controls DNSSEC for its own domain | Its own users' device certs | Certs for any identity in *its* domain | Issue for identities in another domain; make a fallback or registry treat it as authoritative where it is not |
| A4 | Hosted-IdP co-tenant | A tenant on browserid.me's IdP-as-a-service | Its own tenant key use | Tenant onboarding, DNS delegation records | Another tenant's key; issuance for a domain it does not control |
| A5 | Compromised broker (browserid.me) | Fallback IdP + registry + hosted verifier + web wallet origin | Everything in F1, F4, F5 for fallback users; bundles sent to `/verify` | Anything | Full impersonation of fallback users. The question is blast radius for *primary* users and what remains detectable |
| A6 | Compromised wallet origin or extension | Holds the user's keys | All keys | Any signature | Not a security boundary (§5 honesty tier). Audit interest: what the *signed record* still constrains, and what is auditable after the fact |
| A7 | Network attacker | Between any two parties | TLS-protected traffic metadata; DNS answers | DNS forgery, redirects, SERVFAIL | Downgrade DNSSEC to fallback; point a status fetch at a lying list; SSRF via broker fetchers |
| A8 | Account-lifecycle attacker | Knows the victim's email; unauthenticated | Error responses, timing | Reset/create/add-email codes, login guesses, approvals | Enrol a login key on the victim's account; takeover via mailbox races |
| A9 | Local attacker on the user's machine | Can bind loopback ports, register URL schemes | Return fragments to loopback origins (fb §3.1) | A ceremony with its own keys | A config cert for the victim bound to attacker keys |
| A10 | Insider at the registry | DB and key access | All records | Edits rows, flips bits | Revive revoked records; forge admissions. Mitigated only where the spec makes rows signed by the user |

A5 and A6 are not boundaries the protocol claims to hold; they are included
so the audit states plainly what breaks and what stays auditable.

## 3. Assets, ranked

1. **Config cert + key.** Signs warrants for every identity it covers, with
   `+*` subaddressing. Theft = silent delegation of the account.
2. **Auth cert + key.** Mints access certs for 90 days. Theft = login as the user
   until revoked.
3. **Registry login key / session.** Manages the account: revoke, attach,
   approve new devices, answer consent requests.
4. **IdP signing keys** (broker root key, tenant keys). Compromise = A5/A3.
5. **Status lists.** Lying "all clear" defeats every revocation.
6. **Pending request codes, login tokens, reset codes.** Single-use bearer
   secrets with short windows; their entropy and burn rules are the whole defense.
7. **Metadata**: which sites a user uses (warrant ledger), parent↔derived
   identity mapping (§7.1), RP↔user association (status proxy rationale §6.3).

## 4. Trust boundaries the spec claims

- **B1. DNSSEC is the sole root for IdP keys** (§3). No Web-PKI path to a key;
  SERVFAIL rejects; insecure means fallback, never "trust the TLS answer".
- **B2. Per-identity issuer authority** (§6.1 step 2, §8). An issuer vouches
  only for domains it is DNSSEC-authoritative for, or is an RP-accepted
  fallback for a no-primary domain. Checked separately for grantee and grantor.
- **B3. Holder isolation** (§4.5). The requester never chooses its holder; the
  mint copies it verbatim; warrants bind by matcher.
- **B4. The wallet is the only signer** (§7.5, §6.6 inv. 9, 11). The registry
  never signs or alters a warrant; no broker page signs; a request only matches
  a stored record or triggers a ceremony.
- **B5. Fail-closed everywhere** (§6.6 inv. 14). Unknown typ, purpose,
  binding kind, scope parameter, constraints key, or unreachable status list
  rejects.
- **B6. Return-origin gating of issuance** (fb §3.1). Certs go only to loopback,
  custom-scheme, or issuer-trusted web origins, enforced at the endpoint.
- **B7. Login is the account boundary** (reg §4.1–4.3, §8). A cert proves an
  address, never account membership; a session needs a login; an issuer
  session is identity-scoped until bound to an enrolled login key.
- **B8. Browser-attached origin is the only requester authority** (§7.3).
  Nothing a page claims about itself is trusted.

## 5. Invariants to test

Each is phrased so WS2 (vectors), WS3 (property tests), or WS5 (authz matrix)
can turn it into a check. Derived from the boundaries above.

**Verification (WS2, WS6)**
- I1. A bundle with ≠ 4 objects, or any object with unknown `typ`/`purpose`, rejects.
- I2. Signatures are checked before any claim is read or any network fetch runs.
- I3. `access_cert.iss` must be authoritative for the grantee domain and
  `config_cert.iss` for the grantor domain, independently; a fallback-issued
  cert for a domain with a DNSSEC primary rejects; an issuer outside the RP's
  accepted set rejects.
- I4. `aud` on the assertion, `audience` on the warrant, and the RP's expected
  audience are all byte-equal after one normalization; no prefix or origin-vs-URL slack.
- I5. Identity comparison is domain-lowercased A-label, local part byte-exact,
  everywhere (core and registry disagree on this; see spec findings).
- I6. A grantee matcher, a `connection` entry, or a missing `holder` entry never
  verifies in op P; a `requester` entry never admits in op A.
- I7. `req_origin` must be present and equal when a `requester` entry exists.
- I8. Any `constraints` key, binding `kind`, connection `protocol`, or scope
  parameter the verifier does not implement rejects. Today no verifier implements
  §4.7, so any `constraints` claim at all must reject.
- I9. An unreachable, unparseable, over-TTL, or mis-signed status list rejects;
  a status fetch never follows redirects or reaches non-public addresses; a cert
  `status.uri` host equals its `iss`.
- I10. A v1 warrant without `status` is accepted by verifiers but no signing
  surface in this repo can emit one.
- I11. Every verifier in the repo (Rust core, hosted `/verify`, JS SDK, Python
  mcp-auth, gate, wallet) returns the same verdict on the same vector.

**Chain narrowing (WS3)**
- I12. No composition of policy record × connection record × scope parameters
  yields effective scopes outside S ∩ S′, or a `cap`/`max_duration`/
  `min_reputation` looser than either record's.
- I13. A config cert for `user@d` can sign a warrant whose grantor is
  `user+tag@d` but an auth cert for `user@d` never mints for `user+tag@d`.
- I14. The holder in a minted access cert always equals the device cert's holder.

**Issuance and consent (WS4, WS5, WS8)**
- I15. No endpoint issues a device or config cert to an origin outside fb §3.1's
  accepted set, and the check is in the handler, not the page.
- I16. A `+*` config cert is issued only at the password/session bar; a
  mailbox-proof-only ceremony issues exact-address certs.
- I17. Holder is assigned server-side, never read from the request or the page session.
- I18. A JIT or connection request's artefact is deliverable exactly once; codes
  are ≥128-bit and expire; polls faster than `interval` get 429.
- I19. Audience-proof fetches refuse redirects and private ranges; the present-lane
  origin match is exact on scheme, host, port.
- I20. `respond` rejects a warrant whose grantor, grantee, audience, scopes,
  binding id, or status ref differs from the claimed request, in the spec's order.
- I21. A consent card never renders requester-typed prose except the quoted,
  capped `message`; the verified origin is always shown.

**Account boundary (WS5)**
- I22. Every `/api/v1` mutation requires a session plus a body-hash proof; jti
  replay within the window rejects; `htu` is built from the public origin.
- I23. A fresh config cert alone creates or takes over an account only with
  `confirm_takeover`, and inherits nothing; an auth cert alone creates nothing.
- I24. A suspended identity is refused like a stranger's; its warrant bits are set.
- I25. Policy can only tighten; approvals cannot chain (`approver_unproven`);
  unknown accounts and spent tokens answer identically.
- I26. Revoking a login key ends its sessions and retires the certs under it;
  revoking a cert or warrant is sticky and its index is never reused.
- I27. An issuer cookie session cannot list or manage the account until bound
  to an enrolled login key.
- I28. Reset, creation, add-email, and sign-in codes burn after N attempts and
  are IP-throttled (July C1); password guessing is rate-limited (July M6).

## 6. Out of scope for this audit

Compromise of the user's device OS; cryptanalysis of Ed25519; DNSSEC root
compromise; the SBO ledger's own consensus. A compromised wallet origin (A6) is
analyzed for blast radius only.
