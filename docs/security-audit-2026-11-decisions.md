# Security audit 2026-11: open decisions

> **Status: for Dan's review, 2026-11-02.** Findings from WS5 (broker HTTP
> surface) and WS6 (crypto core and verifiers) that need a product or
> design call before remediation. Everything else confirmed by those
> workstreams has a clear fix and is encoded as an `#[ignore]`d
> `AUDIT-2026-11` test; un-ignoring the test is the acceptance criterion.
> Full reports: `docs/security-audit-2026-11-ws5-http-surface.md`,
> `docs/security-audit-2026-11-ws6-core-verifier.md`. Branch `audit-2026-11`.

## 1. Where things stand

| Workstream | Result |
|---|---|
| WS1 threat model + spec review | Done. 13 spec findings decided 2026-11-01; all spec edits landed (bean kgjr). |
| WS6 core / verifier / DNSSEC | Done. 7 candidates: 6 confirmed, 1 refuted. 5 new findings (W6-1..W6-5). Tests: core 18 pass / 10 ignored, verifier 6 / 4, dnssec 0 / 2, rp 0 / 2. |
| WS5 broker HTTP surface | Done. 8 candidates: 4 confirmed, 2 partial, 2 refuted. 15 new findings (W5-1..W5-15). Authz matrix: 10 pass / 15 ignored. July items re-verified; H1 still open for discovery fetch and /status/proxy. |
| WS2, WS3, WS4, WS7 | Ready, not started. |
| WS8 PoCs, WS9 report + remediation beans | Blocked on the above. |

**Highs confirmed so far**

| ID | Finding | Where |
|---|---|---|
| D1 | An auth cert for `user@d` mints access certs for `user+tag@d`; the subaddress rule is purpose-blind. Direction settled 2026-11-02: spec §4.6 stands, code moves. Downgraded to Medium (holder-pinned warrants unaffected). | `browserid-core/src/device.rs` identity_matches; both mint routes |
| D2 | Consent `respond` never checks the config cert: no issuer signature, not checked as recorded on the account, no status check. | `browserid-registrar/src/consent.rs` |
| W6-3 / W5-8 | Status-list decoder inflates the whole zlib stream before the 4 MiB cap; 256 KiB in, ~768 MiB allocated; reachable unauthenticated via `/status/proxy`. | `browserid-core/src/status.rs` |
| W5-10 | Registry login endpoint mints the login-page token with no return-origin check (code side of S1). | `browserid-broker/src/routes/registry_login.rs` |

## 2. Decisions

Each item: what was found, the options, and my recommendation. Reply per
item number.

### Q1. D1 fix ordering (Medium)

**Direction decided 2026-11-02 (Dan):** spec §4.6 stands. An auth cert
issued for `user@d` mints for `user@d` exactly; speaking as `user+tag@d`
needs an auth cert issued for that sub-identity. A config cert for
`user@d` keeps signing warrants for `user+tag@d`. The code's wide mint was
deliberate (comment in `identity_matches`) but incomplete: the user's own
config cert can sign the self-login warrant for `user+tag@d`, so a base
auth key could log in as any sub-identity and present under any `*`-holder
agent warrant, which breaks attribution, the per-agent revocation axis,
and widens browser-key compromise. Holder-pinned warrants are unaffected,
hence Medium.

Still open: ordering. The fix is two lines in core plus flipping one unit
test that currently pins the wrong behaviour. WS6 recommends letting WS8
demonstrate the live mint first so the report carries a shown impact
rather than a test.

- (a) Fix now on the branch, PoC later against the fixed code's parent commit.
- (b) Hold until WS8 PoCs it against a local broker, then fix.

**Decided 2026-11-02: (b).**

### Q2. D14 resolver transport failure (Medium)

DoT connect failure, timeout, malformed answer, and REFUSED all map to
"insecure" today, which demotes a primary domain to the fallback path. The
spec now says hard reject. A literal hard reject turns resolver blips into
login failures.

- (a) Reject immediately.
- (b) Retry once with a short budget (reference 2 s), then reject.
- (c) Retry against a second configured resolver, then reject.

**Decided 2026-11-02: (b).** No second resolver exists.

### Q3. D15 browserid-rp pinned status path (Medium)

The RP SDK's pinned-table status refresh follows redirects (to loopback in
the test), has no private-address guard, and honours a ten-year TTL. The
DNSSEC path in the same crate reuses the hosted verifier's guard and is clean.

- (a) Fix the pinned path to reuse the guard.
- (b) Deprecate `refresh`/`refresh_status` and route everything through `verify_dnssec`.

**Decided 2026-11-02: (b).**

### Q4. W5-4 password change vs login keys (Medium)

Changing the account password leaves every registry login key and session
alive, including keys that were enrolled *by* the old password. A user who
changes their password after a compromise does not log the attacker out.

- (a) Password change retires login keys whose `enrolled_by` is `password` and ends their sessions; keys enrolled by proofs or approval stay.
- (b) Password change retires all login keys except the one making the change.
- (c) Leave as is; the device list is the recovery path.

**Decided 2026-11-02: (a).**

### Q5. D8 rate limiting on /api/v1 (Medium)

No endpoint under `/api/v1` returns 429. Approval-code brute force was
refuted as a takeover (the approver must already hold an enrolled session),
so the remaining exposure is enumeration, proof-replay-window pressure, and
cost.

- (a) Blanket per-source and per-account limiter on all of `/api/v1`, before any network fetch, as registry-api-v1 §3 says.
- (b) Targeted limiters on `accounts`, `accounts/lookup`, `login`, `approvals`, `requests/claim`, `requests/respond` only.

**Decided 2026-11-02: (a)** with generous defaults.

### Q6. W5-7 agent-provision mint bar (Medium)

`/agent-provision/complete` signs device certs without going through
`authorize_mint`, the one place the issuance bar (password session, bridge
grant, mint policy) is enforced. Every other issuance lane passes through it.

- (a) Intended exemption: the user's approval in the provisioning card is the bar. Document it in fallback-idp-api-v1 §3.2.
- (b) Not intended: route through `authorize_mint` under the approving session.

**Decided 2026-11-02: (b), and as-you agents for bridged (E2) parents
must keep working** via the existing bridge-grant mechanism: the approval
page runs `/oidc/claim` (or the Bluesky attestation) when the chokepoint
answers Delegate(bridge), the ceremony records a bridge grant, and
`complete` redeems it like `/device/issue` does; the cert TTL is the
bridge's. Analysis that led here, with the minted identity as input:

| identity_mode | identity minted | `authorize_mint` says | Right? |
|---|---|---|---|
| handle / standalone | `user+handle@d` (EmailType::Agent) | Full session, else NeedPassword | Yes. This is the bar W5-7 asks for. |
| self, parent is E3 (mailbox-proofed) | the parent address | Full session; Reverify if the SMTP proof is older than 90 d | Yes. |
| self, parent is E2 (Google / Bluesky bridged) | the parent address | Delegate(bridge) | Policy says yes, but it is a behaviour change: today the registrar signs as-you agents for bridged addresses with no bridge proof, and it has no hook to run one. Either refuse (consistent with every other lane) or add a bridge re-proof hop like the primary hop. |
| self, parent is E1 (primary) | the parent address | Delegate(Primary) | Already handled: the page hops to the primary and hands back a primary-signed cert; the registrar signs nothing. Only the registrar-signed branch needs the check. |

Remediation bean should cover the page hop plus a test for the E2-self
lane. Plumbing: the registrar crate sees only `user_id` and the CSRF token, and
`authorize_mint` lives in the broker, so this is a new host-trait method
implemented in `registrar_glue.rs` with the session level. For a handle or
standalone agent the Agent email row does not exist until after signing,
so the glue applies the Agent rule from the parent's record rather than
looking one up.

### Q7. W5-6 X-Forwarded-For (infra check)

The broker's throttles trust the first `X-Forwarded-For` hop. If the
dokku proxy appends rather than overwrites, a client can spoof its source
address and dodge every per-IP limit.

- (a) Confirm in sandmill-infra that the proxy sets the header from the connection address; nothing to change in the repo.
- (b) Change the broker to take the last hop, or a configured trusted-proxy count.

**Decided 2026-11-02: both.** Confirm the proxy in sandmill-infra and change the broker so it never depends on proxy config.

## 3. Already settled by the spec edits (no decision needed)

- S5 corner: a `scopes` allowlist never restricts a scope-less login; use `aud`.
- I9 / W6-4: a cert's `status.uri` host must be its `iss` or the DNSSEC `host=` delegate; code fix is to mirror the list-signer handling.
- D7, D14 wording, S3, S6: now normative spec text; remediation follows the tests.

## 4. Next

On your go: WS2, WS3, WS4, WS7 in parallel (independent), then WS8 PoCs
(local broker only), then WS9 consolidates the ignored tests into
remediation beans. Work stays on `audit-2026-11`; a PR opens when you say.
