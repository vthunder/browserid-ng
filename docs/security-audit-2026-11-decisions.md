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
| WS7 supply chain, build, deploy, secrets | Done (c0acdd7). 16 Rust advisories (14 close with `cargo update`), npm all patched within ranges, 1 Python pin. New CI gate `supply-chain.yml` (cargo-audit, npm audit, pip-audit, gitleaks). 12 findings W7-1..12; no secret ever committed; July M8 holds. |
| WS4 agent/MCP, wallet, hosted IdP, OIDC bridge | Done (8e4ab00). D3, D5, D6, D13, D17, D19, D20 confirmed; D12 refuted. 17 new findings W4-10..44 (2 Medium: W4-22 wallet-service admits delegated presentations as the human, W4-30 hosted-tenant onboarding squat). Tests: broker 13/7, mcp-auth 12/8, gate 11/6, python 7/2, wallet 6/2, wallet-service 7/3, agent 5/5. |
| WS2 conformance vectors | Done (d72d53a). 177 vectors, 6 runners (core, hosted, sdk/js, python, mcp-auth, gate) green in CI with expected-fail tables. Only 4 cross-verifier disagreements: D7 (core keeps scope parameters, everything behind HTTP flattens), W2-1 (resource-shaped SDKs strip trailing slash from the audience), D5 and D17 in mcp-auth. Everything else is the stack agreeing with itself against the spec; the core fix resolves it for all six. New: W2-1, W2-5 (sdk/js omits holder/grantee_issuer), W2-6 (duplicate TXT field takes the last value). |
| WS3 fuzz + proptest | Running (smoke run in flight). |
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

### Q8. WS7: supply-chain gate is red until the bumps land

The new gate fails on main today: `cargo update` (R7-1), `npm audit fix`
in 7 packages plus redeploy of 3 services and republish of gate/wallet
(R7-2), fastmcp pin to 3.4.10 (R7-3).

- (a) Land the bumps on the branch now so the gate is green at PR time.
- (b) Pre-fill the ignore lists and bump later.

**Recommend (a)**; the MCP SDK memory-exhaustion items are reachable on every StreamableHTTP service.

### Q9. W7-8 containers run as root (Medium)

Broker (root key + db) and all Node/Python images have no `USER`, no
healthcheck, no read-only fs. Fix needs a storage-dir chown on each dokku
host, so it is infra-coordinated.

- (a) Add non-root users to the Dockerfiles and a chown step in sandmill-infra, one app at a time, broker first.
- (b) Leave as is.

**Recommend (a)**.

### Q10. W7-11 / W7-10 identifiers in logs (Medium)

Registrar access log prints raw paths (single-use filer codes, approval
ids); consent/device/account logs print delegator email + audience and
agent identity, enough to reconstruct the RP-user association the spec
treats as metadata.

- (a) Opaque ids in log lines (hashed email, record id instead of audience) and path redaction for `requests/:code`.
- (b) A separate PII log target, off in prod.

**Recommend (a)**; (b) tends to get switched on during incidents.

### Q11. W7-2 GitHub Actions pinned by mutable tag (Medium)

All 9 workflows, including `publish.yml` with `id-token: write`. WS7 resolved the SHAs but did not apply them to deploy recipes.

- (a) Apply the SHA pins now and add Dependabot for actions only.
- (b) Apply the pins only; bump by hand.

**Recommend (a)**; Dependabot limited to `github-actions` is low noise.

### Q12. W7-9 one age recipient for every secret (Low, infra)

- (a) Add a second recipient (recovery key kept offline) and a rotation note in sandmill-infra.
- (b) Leave as is.

**Recommend (a)**.

### Q13. PostHog ids are unsalted sha256 (Low)

- (a) Salt with a server secret.
- (b) Leave as is.

**Recommend (a)**; cheap, and it closes the rainbow-table argument.

Also from WS7, no decision needed: X-Forwarded-For is overwritten with
the connection address by dokku's shipped nginx template, so W5-6 is not
exploitable today; the value should be declared in `id.conf` and asserted
by `audit-host.sh` (infra), and the broker last-hop change stays a
remediation bean per Q7.

### Q14. D6 gate admission during a broker outage (Medium)

The self-hosted gateway keeps last-known-good rows; a thrown fetch fails open (unreachable today), while a 5xx is read as a definitive `invalid_grant` and the gate deletes signed rows (W4-12).

- (a) Fail closed on any status failure, keep last-known rows only for the console diff, and never delete a row on 5xx. Spec §6.4.
- (b) Allow last-known-good admission for a bounded window (e.g. 10 min) for availability.

**Recommend (a)**; the 5xx row deletion must go either way.

### Q15. D5 policy-row bindings in mcp-auth and gate (Medium)

They filter policy rows by grantee only; a narrowed holder matcher or requester entry still admits.

- (a) Refuse to store any policy record whose binding is not exactly `{holder, "*"}`.
- (b) Implement full binding evaluation.

**Recommend (a)** now, (b) when a wallet actually authors narrowed records.

### Q16. W4-22 hosted wallet admits delegated presentations as the human (Medium)

The wallet-service is the hosted wallet (`wallet-service/`, the remote MCP
connector claude.ai uses): it custodies an agent's device key server-side
and its OAuth sign-in page is a browserid relying party. That sign-in never
checks that the grantee is the human or that the login scope is present, so
any identity holding a warrant for the wallet origin, including an agent
the user delegated to, signs in as the human and takes over the custodied
key. One approved consent card for the wallet origin is enough (July M2
recurrence in a layer never audited before).

- (a) Hosted wallet is human-only: reject delegated and non-login presentations.
- (b) Document that an as-you agent may own a wallet tenant.

**Recommend (a)**.

### Q17. W4-30 hosted-tenant onboarding squat (Medium)

Pending tenant rows never expire; the real owner gets 409.

- (a) Expire pending rows (e.g. 7 days) and let a DNSSEC-validated record for a different key replace a pending row.
- (b) Expiry only.

**Recommend (a)**.

### Q18. W4-34 bridge grant redeemable by any session of the account (Low)

- (a) Bind the grant to the proving session.
- (b) Leave account-wide.

**Recommend (a)**; it also matters for Q6, where agent-provision will redeem grants.

### Q19. W4-40 assertions carry no `iat` (spec gap)

Amended §6.1 puts a lower bound on `iat` for every object, but assertions have none.

- (a) Add `iat` to assertions (spec §5, core, Rust agent, JS SDK).
- (b) Scope §6.1's lower bound to objects that carry `iat`.

**Recommend (a)**; one rule for every object.

### Q20. D19 FedCM objects without status refs (Low)

Every FedCM object expires in 5 min.

- (a) Accept as the documented exception; say so in core §6.3 and fb §3.2.
- (b) Allocate broker-list refs for both throwaway keys.

**Recommend (a)**.

### Q21. D13 hosted wallet revoke/disconnect (Low)

wallet-service drops status refs, refreshes for 30 days with no re-check, has no revoke.

- (a) In scope: keep refs, re-check status on refresh, add disconnect.
- (b) Accept RP-session semantics for now.

**Recommend (a)**, after the Mediums.

### Q22. W4-21 loopback-page pairing with the wallet in release builds (Low)

- (a) Gate on `WALLET_TEST` and pin the extension id.
- (b) Keep the allowance.

**Recommend (a)**.

### Q23. Small ones (Low / Info)

- W4-13 Lane A bearer outlives the warrant: fold the `/verify` expiry field into the D7 scope-parameter work. **Recommend yes.**
- W4-44 legacy `Agent`/`Credential` lane in `@browserid-ng/agent` is dead but exported: delete (breaking) or leave documented. **Recommend delete at the next major.**
- D12 stored-grant signature check in the wallet: refuted as a finding; add the check as defence in depth or record as accepted. **Recommend add; it is cheap.**

### Q24. S5 direction: §4.7 constraints (spec vs core)

§4.7 now says nothing implements constraints, so any `constraints` claim
rejects. But core already enforces `aud`, `scopes`, `max-ttl` and fails
closed on unknown keys (WS6 S5 tests, WS2 vectors P-CONS-01/06).

- (a) Amend §4.7 to name core as implementing those three keys; the two vectors flip to accept.
- (b) Strip the core implementation so any constraints claim rejects.

**Recommend (a)**; the code is tested and fail-closed, and throwing it away buys nothing.

### Q25. W2-1 SDKs normalize the `resource` audience (Low)

python-mcp-auth, mcp-auth and gate strip trailing slashes and send the altered audience to `/verify`, so a record for `sbo+raw://avail:turing:506/` never verifies through them.

- (a) Stop normalizing; spec §5 is byte-exact.
- (b) Keep normalizing and document it.

**Recommend (a)**.

### Q26. W2-4 gate allowlists lowercase the whole email (Low)

- (a) Byte-exact comparison per spec (domain lowercased only).
- (b) Normalize at config time with a warning.

**Recommend (a)**; same rule as everywhere else, and it is the D17 fix.

## 3. Already settled by the spec edits (no decision needed)

- S5 corner: a `scopes` allowlist never restricts a scope-less login; use `aud`.
- I9 / W6-4: a cert's `status.uri` host must be its `iss` or the DNSSEC `host=` delegate; code fix is to mirror the list-signer handling.
- D7, D14 wording, S3, S6: now normative spec text; remediation follows the tests.

## 4. Next

On your go: WS2, WS3, WS4, WS7 in parallel (independent), then WS8 PoCs
(local broker only), then WS9 consolidates the ignored tests into
remediation beans. Work stays on `audit-2026-11`; a PR opens when you say.
