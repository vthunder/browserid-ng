<!-- This Source Code Form is subject to the terms of the Mozilla Public
   - License, v. 2.0. If a copy of the MPL was not distributed with this
   - file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Security audit 2026-11 — WS7: supply chain, build, deploy, secrets, logging

**Status:** workstream output, 2026-11-02. Epic `browserid-ng-ag1l`, bean
`browserid-ng-djdz`. Oracle: `docs/design/threat-model.md` §3 items 4, 6, 7
and the July ledger (`docs/security-audit-2026-07-29.md`, M8/L12). Nothing in
production code, infra or hosts was changed. `~/src/sandmill-infra` was read,
not modified; no host was contacted.

**Method.** Reviewer pass: run every scanner (cargo-audit 0.22.2, `npm audit`
on 19 packages, pip-audit via uv, gitleaks 8.x) on `localtest`, then read all
six Dockerfiles, nine workflows, `.dockerignore`/`.gitignore`, the age/key
layout in sandmill-infra, `config.rs` for the key file, every `tracing!`/
`println!` in broker and registrar, and the PostHog capture sites. Skeptic
pass: for each advisory ask who pulls the crate/package and whether our code
reaches the vulnerable path; for each finding ask what an attacker needs.
Deliverables committed with this report: `.github/workflows/supply-chain.yml`,
`scripts/supply-chain-audit.sh` (`make audit`), `.cargo/audit.toml`,
`.github/supply-chain/{npm,pip}-ignore.txt`, `.gitleaks.toml`.

**Headline.** No leaked credential in 1020 commits. The root key file is 0600
(M8 holds). Nothing secret ships in any image. The dokku proxy overwrites
`X-Forwarded-For` with the connection address (Q7 infra half: confirmed by
default, but undeclared). The dependency picture is stale rather than
dangerous: 16 RUSTSEC advisories of which 14 close with a plain
`cargo update`, and 9–11 npm advisories per Node service that all close
inside the current semver ranges. The new CI gate is **red on main until the
remediation bean lands those bumps**; that is intentional and stated below.

## 1. Dependency advisories

### 1.1 Rust workspace (`cargo audit`, 2026-11-02 database)

16 vulnerabilities, 3 unsound warnings. Who pulls what (from `cargo tree -i`):
rustls/webpki come in through `hickory-client` (DNS-over-TLS), `lettre` (SMTP)
and the direct `rustls` dependency; `reqwest` uses native-tls (hyper-tls is in
the tree), so HTTP fetches do **not** go through rustls-webpki.

| Advisory | Crate | Title | Reachable? | Fix |
|---|---|---|---|---|
| RUSTSEC-2026-0382 | rustls-webpki 0.103.8 | Accepts distrusted intermediates | **Yes**: DoT to resolvers, SMTP TLS | `cargo update` → 0.103.16 |
| RUSTSEC-2026-0098 / 0099 | rustls-webpki | Name-constraint bypass (URI names, wildcard) | Yes, same paths; needs a CA-issued constrained cert | `cargo update` |
| RUSTSEC-2026-0104 | rustls-webpki | Panic in CRL parsing | No: we load no CRLs | `cargo update` |
| RUSTSEC-2026-0049 | rustls-webpki | CRL distribution-point matching | No: no CRLs | `cargo update` |
| RUSTSEC-2026-0381 | webpki-roots 1.0.4 | Distrusted emSign roots bundled | Yes (lettre, dnssec trust store) | `cargo update` → 1.0.11 |
| RUSTSEC-2026-0285 / 0349 | rustls 0.23.35 | TLS1.3 handshake level confusion; downgrade to classical KEX | Yes, client side (DoT, SMTP); confidentiality: low | `cargo update` → 0.23.46 |
| RUSTSEC-2026-0348 | rustls | 1 GiB Brotli cert decompression pre-auth | Only if a hostile server is dialled; DoT resolvers are configured, SMTP host is ours | `cargo update` |
| RUSTSEC-2026-0346 | rustls | `Debug` impls leak TLS secrets | No: nothing `{:?}`-prints sessions | `cargo update` |
| RUSTSEC-2026-0141 | lettre 0.11.19 | Hostname check off with Boring TLS | No: rustls backend | `cargo update` → 0.11.23 |
| RUSTSEC-2026-0258 | h2 0.4.12 | Unbounded empty DATA frames | **Yes**: inbound HTTP/2 to axum (behind nginx, which speaks h1 upstream, so only via a local client) | `cargo update` → 0.4.20 |
| RUSTSEC-2026-0007 | bytes 1.11.0 | Integer overflow in `reserve` | Theoretical | `cargo update` → 1.12.1 |
| RUSTSEC-2026-0009 | time 0.3.44 | Stack exhaustion (CVSS 6.8) | Via `cookie`/`jsonwebtoken` parsing of attacker input: plausible | `cargo update` → 0.3.55 |
| RUSTSEC-2026-0118 | hickory-proto 0.25.2 | NSEC3 closest-encloser loop | Yes: DNSSEC validation of a hostile answer, under lookup timeout | **No fix published.** Ignored in `.cargo/audit.toml`, review 2027-02-01 |
| RUSTSEC-2026-0119 | hickory-proto 0.25.2 | O(n²) name compression on encode | Our own short queries; not attacker-driven | Fixed only in 0.26 (alpha). Ignored, same review date |
| warnings | anyhow 1.0.100, rand 0.8.5, tokio 1.48 | unsound | Not failing the gate | pick up with `cargo update` |

`cargo update --dry-run` on the current lockfile resolves every patched
advisory in one step (bytes, h2, lettre, rustls, rustls-webpki, time,
webpki-roots, plus thiserror/hyper-rustls). **Remediation R7-1:** run
`cargo update`, re-run `cargo test --workspace`, commit `Cargo.lock`.

### 1.2 Node packages (`npm audit --omit=dev`)

Clean: `wallet`, `sdk/express`, `sdk/hono`, `sdk/nextauth`, `sdk/fastify`,
`sdk/mcp-auth` (audited from a temporary lock), `examples/rp-quickstart`,
`prototypes/menubar-wallet/app`. No deps: `sdk/js`, `sdk/agent`. Skipped
(file: dep, private example): `examples/nextauth-app`.

Every finding in the remaining seven (`wallet-service`, `mcp-demo`,
`guestbook-mcp`, `github-mcp`, `sdk/gate`, `sdk/wallet`,
`examples/mcp-agent-auth`) comes through one import:
`@modelcontextprotocol/sdk@1.30.0` → express 5 / body-parser / proxy-addr /
qs / hono / express-rate-limit → ip-address / zod / fast-uri.

| Advisory | Package | Severity | Reachable? | Fix (all inside current ranges) |
|---|---|---|---|---|
| GHSA-f897-62hf-6gxq, GHSA-46jr-4wx8-v453 | @modelcontextprotocol/sdk ≤1.31 | high | **Yes**: every service uses `StreamableHTTPServerTransport`; unbounded body / batch length and memory exhaustion are plain DoS on the public MCP endpoints | sdk ≥1.32.0 |
| GHSA-22jm-h49p-29qw | sdk | high | No: experimental tasks unused | sdk 1.32 |
| GHSA-6qxp-vccf-f47h, GHSA-6prh-2h8m-c8cw | sdk (client side) | high/med | Partial: `github-mcp` and `sdk/agent` examples use the client transports; we do not use the SDK OAuth client | sdk 1.32 |
| GHSA-rvq5-wwqv-78pq | sdk bearer auth | medium | No: our gates do their own warrant/status checks, `requireBearerAuth` unused | sdk 1.32 |
| GHSA-jqcg-44mw-7w3h | proxy-addr 2.0.7 | critical | No: no `trust proxy` setting anywhere; express is pulled but our handlers run on node http/hono | 2.0.8 |
| GHSA-27r3-jxmh-p828 | body-parser 2.3.0 | high | No: express app not mounted | 2.4.0 |
| GHSA-mrhx-c7xc-m3w5 | zod <4.6.6 | high | Yes: tool-argument validation on attacker input | 4.6.6 |
| fast-uri (11 ids) | fast-uri 3.x | high | No: transitive via ajv/express, not used on our inputs | 3.1.9 |
| ip-address (5–8 ids) | ip-address ≤10.7.3 | mod/high | No: only express-rate-limit, unused | 10.7.4 |
| hono (9 ids), @hono/node-server | hono ≤4.13.10 | moderate | `serveStatic` double-decode: only if a service serves static files through hono (none does) | 4.13.11 / 2.1.3 |
| qs (3 ids) | qs ≤6.16.0 | moderate | No | 6.16.1 |

**Remediation R7-2:** in each of the seven packages run `npm audit fix`
(no `--force` needed; every patched version is inside the declared ranges),
run the package tests, commit the lockfiles. For the three deployed services
this is a redeploy. For `sdk/gate` and `sdk/wallet` it is a publish (bump +
`publish.yml`).

### 1.3 Python

`sdk/python-mcp-auth` has no third-party dependencies (stdlib only; pip-audit
confirms). `python-mcp-demo/requirements.txt` pins `fastmcp==3.4.6`:

| Advisory | Severity | Reachable? | Fix |
|---|---|---|---|
| GHSA-7xgj-8392-5q4r | high (authz bypass via transforms) | No: `server.py` uses no transforms or component `AuthCheck`; our gate is per-call | pin 3.4.10 (**R7-3**) |

## 2. CI and build findings (W7-n)

| # | Finding | Severity | Where | Remediation |
|---|---|---|---|---|
| **W7-1** | No dependency or secret scanning gate existed. Nothing would have surfaced any of §1. | Medium | `.github/workflows/` | **Done this WS:** `supply-chain.yml` (cargo-audit, npm, pip-audit, gitleaks; push/PR/weekly), one script shared with `make audit`, per-ecosystem ignore files with reason + review date. Red on main until R7-1/2/3 land. |
| **W7-2** | Every third-party action is pinned by mutable tag (`actions/checkout@v7`, `docker/build-push-action@v6`, `pypa/gh-action-pypi-publish@release/v1`, …). A tag move (the 2025 tj-actions class) runs arbitrary code with `packages: write` and the dokku deploy key in the deploy workflows, and with `id-token: write` in `publish.yml` (npm + PyPI trusted publishing). | Medium | all nine workflows | Pin by SHA with the tag in a comment. Resolved today: checkout `3d3c42e5…`, setup-node `949feb24…`, setup-python `6d4fd22b…`, setup-buildx `8d2750c6…`, login-action `c94ce9fb…`, build-push `10e90e36…`, rust-cache `d1527c8f…`, setup-uv `20cfd1bf…`, rust-toolchain 1.85.0 `cfcaf53b…` (full SHAs in `supply-chain.yml`). `pypa/gh-action-pypi-publish` needs its own lookup. Mechanical; not applied to the deploy recipes here because a deploy cannot be test-run from this branch. |
| **W7-3** | One shared `DOKKU_SSH_KEY` repo secret serves six deploy workflows; it is a dokku-user key (`keys/dokku/browserid-ng-ci.pub`, never sudo), so blast radius is "release any app on either host", not host root. The key is written to `~/.ssh/dokku_key` on the runner each run (fine; runner is ephemeral) and never echoed. `GITHUB_TOKEN` scope is `contents: read, packages: write`. No `pull_request_target`, no `${{ github.event.* }}` in any `run:` step, deploys fire only on `push: main`. | Info | deploy-*.yml | None. Optionally per-app dokku keys, but the dokku ACL cannot scope a key to one app anyway. |
| **W7-4** | `type=gha` build cache: PR builds never run the deploy workflows, and Actions cache written from a non-default branch is not readable by `main`, so a fork cannot seed the cache a release build reads. | Info | deploy-*.yml | None. |
| **W7-5** | `publish.yml` runs `npm install -g npm@latest` unpinned before publishing with OIDC. A malicious npm release would execute in the job that holds the publishing identity. | Low | `.github/workflows/publish.yml:37` | Pin `npm@<version>` and bump deliberately. |
| **W7-6** | `test.yml`/`sdk-tests.yml` use `npm install` (not `npm ci`) in five SDK dirs, so CI can resolve a different tree than the committed lock and install post-install scripts from a newly published version. | Low | `sdk-tests.yml:26-38` | `npm ci --ignore-scripts` where a lock exists; commit locks for `sdk/js`, `sdk/agent`, `sdk/mcp-auth`. |
| **W7-7** | Dockerfile builds `rust:1.85-bookworm` and runs `debian:bookworm-slim`, both by floating tag; Node and Python images likewise. Reproducibility only; GHCR keeps the per-sha image. | Low | all Dockerfiles | Pin by digest if build reproducibility is wanted; otherwise accept. |

**Image contents (verified from the Dockerfiles + `.dockerignore`).** The
broker image contains `/app/browserid-broker` (release binary),
`/app/static` (public pages, `sbo_wasm_bg.wasm`, one `.test.mjs` file that is
test code, not a secret), and ca-certificates. `.dockerignore` excludes
`.git`, `.env`, `broker-key.json`, `browserid.db*`, `*.md`, `.beans/` (the
July L12 fix). No `.age` files exist in this repo. Node images copy only
`package.json`, lockfile and `src/`; the wallet image also copies `sdk/agent`
and `sdk/js` (source, no secrets). The Python image copies `sdk/python-mcp-auth`
and `server.py`. The www image copies the listed static files. No source,
database, key or env file is in any shipped layer. (Not built locally: a full
Rust image build is tens of minutes on the shared target dir.)

## 3. Runtime hardening (Dockerfiles)

| Image | User | Healthcheck | Exposed | Shell/tools | Note |
|---|---|---|---|---|---|
| broker | **root** (no `USER`) | none | 5000 | full debian-slim userland | **W7-8** |
| wallet-service | root (`node:24-slim` has a `node` user, unused) | none | 3100 | node + sh | W7-8 |
| mcp-demo, guestbook-mcp | root | none | 3300 / 3200 | node + sh | W7-8 |
| python-mcp-demo | root | none | 3400 | python + sh | W7-8 |
| www | nginx master root, workers `nginx` (image default) | none | 80 | alpine | fine for static nginx |

**W7-8 (Medium).** The broker, the process that holds the root signing key
and the account database, runs as uid 0 inside its container, with `/data`
(key + db) owned by root. Container escape is the attacker's problem, but any
RCE in the broker gets root in the namespace and can read/replace the key
file regardless of its 0600 mode. Remediation: `RUN useradd -r -u 10001
broker && chown broker /data`, `USER broker`; dokku's storage mount then needs
the host dir chowned to 10001 (`dokku storage:ensure-directory --chown
<uid>` or by hand), which is an infra step that must go through
sandmill-infra. Same for the three Node images (`USER node` is one line) and
the Python image. Read-only root filesystem and `no-new-privileges` are dokku
`docker-options` (`--read-only --tmpfs /tmp --security-opt
no-new-privileges`) and belong in `apps/identity/id.conf`. No healthcheck is
defined; dokku's zero-downtime check uses `CHECKS`/`app.json` instead, which
is also absent, so a release that fails to bind is only detected by the
proxy returning 502. Low, but cheap: an `app.json` healthcheck on
`/.well-known/browserid`.

## 4. Secrets

**Repo hygiene.** `.gitignore` covers `broker-key.json`, `browserid.db*`,
`.env`, the wallet dev KEK and session secret, `guestbook.json`. `git ls-files`
holds none of them; `git log --all --diff-filter=A` for `broker-key.json`,
`browserid.db`, `*.env`, `*.age`, `*.pem` returns nothing: never added in any
branch.

**History scan.** gitleaks over all 1020 commits reported 12 hits; every one
is test material and is now allowlisted in `.gitleaks.toml` with the reason:

| Hit | Commit | Verdict |
|---|---|---|
| 9 × JWS / 1 × "api key" in `test-vectors/device-cert-v1.json` | 89e21e1f, e5c72217, 2582555a | Published conformance vectors; seeds are `0x03…`, `0x04…` |
| RSA PKCS#8 in `browserid-broker/src/oidc/tests.rs:13` and `tests/oidc_claim_test.rs:27` | a2d2bc4c, 5a07031d | Throwaway JWKS test key, labelled as such |
| `POSTHOG_TOKEN=phc_...` in a bean note | — | Literal placeholder |

Targeted greps for `BEGIN … PRIVATE KEY`, `AGE-SECRET-KEY-1`, `ghp_`,
`github_pat_`, `xox[bp]-`, `sk-`, `AKIA`, `npm_`, `SMTP_PASS=`,
`BROKER_KEY_SECRET=`, `TENANT_KEYSTORE_KEY=` across `git log -p --all`
found the same two test PEMs and nothing else. **No credential has ever been
committed to this repository.** With `.gitleaks.toml` the scan is clean
(`no leaks found`) and runs on every push and weekly.

**Age-encrypted env files.** They live in `sandmill-infra/secrets/*.env.age`
(one per app; `id.env.age` is the broker's). Recipient: a single age key whose
public half sits at `~/backups/sandmill/age-recipient.pub` and whose private
half is in the password manager and on the mac mini backup path
(`AGE_IDENTITY`). `seed-secrets.sh` re-encrypts from a host backup;
`apply-apps.sh` decrypts locally and pushes with `config:set --encoded`
with stdout suppressed so values never hit a terminal log. Observations:

- **W7-9 (Low, infra).** One recipient, no rotation story written down. The
  age key encrypts every app's secrets on both hosts plus the host backups.
  Losing the private half loses recoverability; leaking it exposes everything
  at once. Recommend a second recipient (`age -r … -r …`, a hardware or
  offline key) and a dated rotation note in `keys/README.md`. Decision for Dan.
- The broker's root key is **not** in `id.env.age` (it is the file at
  `/data/broker-key.json` on the storage mount). `BROKER_KEY_SECRET` exists as
  an env override but is not used in production as far as the declared config
  shows. A host backup (`backup-snapshot`, age-encrypted) is therefore the only
  copy of the root key. That is a deliberate design (DNS is the root of trust,
  memory `sandmill-idp-key-rotation`), fine as long as the backup path is
  tested; nothing to change here.
- `apply-apps.sh` writes the decrypted env to a `mktemp` file for the duration
  of the call; acceptable on the operator laptop.

**July M8 re-verification: HOLDS.** `browserid-broker/src/config.rs:116-144`
`save_keypair` writes with `fs::write` then `set_permissions(0o600)` on unix,
and zeroizes the transient encodings. Residual: a window of a few
microseconds at 0644 between create and chmod, and the chmod is skipped on an
existing file (`load_keypair` does not re-assert mode, so a file that was
created 0644 before the July fix stays 0644 until someone chmods it). Both are
moot while the container runs as root (W7-8) and the data dir is root-owned.
Hardening if W7-8 is done: open with `OpenOptions::mode(0o600)` and assert the
mode on load.

## 5. Logging and analytics

Default filter is `browserid_broker=debug,browserid_registrar=info,
tower_http=debug` (`main.rs:39`) unless `RUST_LOG` is set; there is no
`TraceLayer`, so no per-request access log from the broker. The registrar
has one: `session.rs:60` logs `method path status` for every `/api/v1` call.

| Line | Identifier in the log | Threat-model asset | Severity |
|---|---|---|---|
| `browserid-registrar/src/session.rs:60` `registry api` | the raw path, which for `GET /api/v1/requests/:code` is the filer's **pending-request code** (a single-use bearer secret, §3 item 6) and for `/api/v1/approvals/:id[/cancel]` the approval id | item 6 | **W7-10 Medium** |
| `browserid-registrar/src/consent.rs:1241` `warrant revoked` | `delegator = email`, `audience = RP origin` | item 7: RP↔user association | **W7-11 Medium** |
| `consent.rs:498` `warrant consent approved` | `delegator = email`, grant count (audience not printed here, but the preceding `record request raised`/approval flow plus timestamps correlate) | item 7 (partial) | W7-11 |
| `consent.rs:1483` `warrant request raised` | `agent = identity`, `delegator = email` | parent↔derived mapping, item 7 | W7-11 |
| `routes/device.rs:380` `device/issue: minted on a login key` | `kid`, `email` | key↔identity, item 7 | W7-11 |
| `routes/guestbook.rs:320` | `agent = email` | low (public feed anyway) | Info |
| `routes/hosted_idp.rs:470,1014,1074,1274,1306,1342,1470` | tenant admin emails, roster locals, revoked counts | tenant PII | Low |
| `registrar/src/account.rs:369,375,735` | `%identity` on create/takeover/attach | account↔identity | Low |
| `email/console.rs:24-42` (**only** when `SMTP_HOST` is unset) | **verification and reset codes with the email**, at info and on stdout | item 6 | **W7-12 Medium (conditional)** |
| `email/smtp.rs:148,163` | `email` on every send | PII | Low |
| `routes/email.rs:686` (debug) "Using mock primary IdP for domain" | domain | — | Info, debug default in prod is noisy |
| `main.rs:59` database path, `:102,112,121` config | none | — | fine |

No line logs a session id, cookie, CSRF token, bearer token, password hash,
or client IP. No IP is logged anywhere (the throttles key on it but do not
print it).

**W7-10.** The registrar access log prints the request path verbatim. The
filer-poll code is the bearer that releases the approved warrants to the
filer (single pickup); anyone reading the dokku log (`dokku logs id`,
or a log shipper later) can race the filer. Remediation: log the matched
route pattern (`axum::extract::MatchedPath`) instead of the path, or redact
the last segment for `/requests/` and `/approvals/`.

**W7-11.** With log access an operator reconstructs the RP↔user association
the spec treats as metadata to be protected: `warrant revoked` prints
delegator email + audience outright; `warrant request raised` + `consent
approved` + `device/issue` give agent↔delegator↔key with timestamps that
line up with the registrar access log. Remediation: log opaque ids (the
hashed `distinct_id_for_email` already exists in `analytics.rs:114`) and
drop `audience` from the revoke line, or gate identifier fields behind a
`RUST_LOG` target (`browserid_registrar::pii=debug`) that is off in prod.

**W7-12.** If the `SMTP_*` config is ever missing or mistyped on the `id`
app, the broker silently falls back to the console sender and every
verification and reset code lands in the dokku log with the address. Nothing
fails. Remediation: in production (`BROKER_ENV=production` or
`DOMAIN != localhost`) refuse to start without SMTP, or require an explicit
`EMAIL_SENDER=console` opt-in.

**PostHog.** Server side (`analytics.rs`): the five capture sites send
`distinct_id = u_<sha256(email)[:12]>` plus `email_domain` /
`agent_domain`, `scopes`, `is_agent`; no raw email, code, IP, RP origin.
`$lib` and `source` are constants. The project token (`phc_…`) is a public
write key by design. Client side (`marketing/analytics.js`): pinned bundle,
`/ingest` first-party proxy, autocapture/recording/surveys/flags off,
localStorage only, an email/OTP redactor on every event; the explicit events
carry CTA labels, `href`, `location.pathname`. Nothing from the auth origin
runs analytics JS. No CSP `report-uri`/`report-to` is configured on either
origin (nothing leaks there; violation reports simply go nowhere).
**Verdict: analytics is PII-safe as documented;** the one caveat is that
`sha256(email)` is unsalted, so anyone with PostHog access and an email
guess can confirm membership. Salt with a per-deployment secret if that
matters (Low, decision).

## 6. Q7: X-Forwarded-For on the infra side

**Finding.** sandmill-infra declares nothing about the header: no
`nginx:set … x-forwarded-for-value`, no `set_real_ip_from`, no custom
`nginx.conf.sigil` (`grep -ri forwarded ~/src/sandmill-infra` is empty;
`apps/identity/id.conf` sets only domains, image, ports, storage, letsencrypt).
Both hosts run dokku 0.38.31 (`bin/provision-host.sh:14`). Dokku's shipped
template for that version (`plugins/nginx-vhosts/templates/nginx.conf.sigil`,
fetched from the v0.38.31 tag) emits

```
proxy_set_header X-Forwarded-For {{ $.PROXY_X_FORWARDED_FOR }};
```

and the documented default for `x-forwarded-for-value` is **`$remote_addr`**,
i.e. nginx **overwrites** the header with the TCP peer address. It does not
append (`$proxy_add_x_forwarded_for`). The template sets no `X-Real-IP` at
all, so the broker's `X-Real-IP` fallback in `routes/auth.rs:47-61` is never
populated by the proxy and only ever sees client-supplied values when
`X-Forwarded-For` is absent, which behind nginx it never is. The firewall
(`UFW_TCP="22 80 443"`) blocks direct access to the container port, so there
is no path to the broker that skips nginx.

**So the first hop is the connection address today.** W5-6 is not currently
exploitable on the identity host. Three caveats that justify Dan's "both"
decision:

1. The guarantee lives in a dokku default, not in anything the repo declares
   or `bin/audit-host.sh` checks. One `dokku nginx:set id
   x-forwarded-for-value '$http_x_forwarded_for'` (the documented recipe for
   "behind another proxy") silently reintroduces the hole. **Recommend** (infra,
   not done here): pin `nginx:set id x-forwarded-for-value '$remote_addr'` in
   the app definition and have `audit-host.sh` assert
   `dokku nginx:report id --nginx-computed-x-forwarded-for-value`.
2. If the identity host is ever put behind Cloudflare or a load balancer,
   `$remote_addr` becomes the proxy, every client shares one bucket, and the
   "fix" operators reach for is exactly the append variant.
3. The broker change (take the last hop / configured trusted-proxy count)
   stays a remediation bean per Q7; nothing here changes code.

## 7. Decisions needed

1. **Gate colour.** `supply-chain.yml` fails on main until R7-1 (`cargo
   update`), R7-2 (`npm audit fix` × 7) and R7-3 (fastmcp pin) land. The
   alternative is pre-populating the ignore files with every current id and a
   review date, which hides nothing but makes the first week green. I
   recommend landing the bumps; they are all in-range.
2. **W7-8 non-root containers** needs a one-time chown of the storage dir on
   the identity host (infra), so it is a coordinated change, not a Dockerfile
   PR alone.
3. **W7-9 age recipient**: add a second recipient / write the rotation note?
4. **W7-11 identifier logging**: opaque ids everywhere, or a PII log target
   off in prod? Affects how useful the logs are for support.
5. **Action pinning (W7-2)** for the deploy workflows: apply the SHAs listed
   above now, or wait for Dependabot-style automation (`.github/dependabot.yml`
   with `github-actions` + `cargo` ecosystems; not added, because it opens
   PRs nobody asked for).
6. **Salted PostHog ids** (§5): worth a deployment secret?

## 8. Remediation items (for WS9)

| Id | Item | Severity | Owner lane |
|---|---|---|---|
| R7-1 | `cargo update` + tests + lockfile | Medium | code |
| R7-2 | `npm audit fix` in 7 packages; redeploy 3 services, publish gate/wallet | Medium | code |
| R7-3 | `fastmcp==3.4.10` | Low | code |
| W7-2 | SHA-pin actions in all workflows | Medium | CI |
| W7-5 / W7-6 | pin global npm; `npm ci --ignore-scripts`; commit SDK locks | Low | CI |
| W7-8 | `USER` in every Dockerfile; read-only fs / no-new-privileges via dokku docker-options; `app.json` healthcheck | Medium | code + infra |
| W7-9 | second age recipient, rotation note | Low | infra |
| W7-10 | log matched route, not the raw path, in `session.rs:60` | Medium | code |
| W7-11 | opaque ids / PII log target in consent, device, account logs | Medium | code |
| W7-12 | fail closed without SMTP in production | Medium | code |
| Q7-infra | declare `x-forwarded-for-value '$remote_addr'` and audit it | Low | infra |
| M8 residual | `OpenOptions::mode(0o600)` and assert mode on load | Low | code |
