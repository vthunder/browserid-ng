# Divergence inventory — landing page, README, developer docs

Target: `docs/design/browserid-end-to-end-flow.md` (device-cert model).

## The core model shift (applies to every surface)

The current narrative across all docs is the **old BrowserID chain model**:
one `<certificate>~<assertion>[~<warrant>]`, where the certificate binds
email→key and (for agents) the warrant is "signed by the **delegator's identity
key**," with the agent cert chaining *under* the human's identity cert.

The device-cert design replaces this with:
- **Device certs** (purpose × subject) held on each device, **never seen by the RP**:
  user cert / agent cert (`authentication`) mint access certs; config cert
  (`authorization`) signs warrants.
- **Access cert** — short-lived, certifies a **fresh** key, minted online via a
  **mandatory HTTP mint API**; this is what the RP sees, not the device cert.
- **Warrant** — over `(identifier, subject) → audience[+scopes]`, **signed by a
  config cert (NOT the raw identity key)**, stored device-agnostically, always present.
- **RP presentation is 4 objects:** access cert + assertion + warrant + config cert.
- **Every IdP MUST implement** device-cert issuance (both purposes) + the mint API;
  browser is just one device among many; agents mint **headless**.

Nothing in the current docs mentions: access certs, device certs, purpose×subject,
config certs, the mint API, mandatory conformance, or cookie-free/ITP-proof minting.

---

## README.md  — REWRITE-HEAVY

- **§Backed assertion format** (`166-178`): WRONG. `<certificate>~<assertion>[~<warrant>]`
  and "Warrant — signed by the delegator's **identity key**" both contradict the design.
  REWRITE to access cert + assertion + warrant + config cert; warrant signed by a config
  cert. This is the single most load-bearing wrong snippet.
- **"The agent model in one picture"** (`100-113`): the ASCII chain
  `identity cert → warrant → agent cert + assertion` is the old chain model. REWRITE:
  device certs aren't presented; RP sees access cert + assertion + warrant + config cert;
  DNS root → IdP issuance, not human-identity-cert → agent-cert chaining.
- **§Human sign-in** (`139-157`): `navigator.id.watch/request` + "verifies the returned
  `certificate~assertion`" — UPDATE. Popup channel (WinChan) is KEPT per design Stage 1,
  but framing must say browser is one device minting an access cert, and the verified
  bundle is the 4-object presentation.
- **Repo layout** (`85-98`): `browserid-registrar` is described as "unbundled from the IdP
  role" delegation authority — reconcile with design's config-cert-holder (client broker or
  hosted broker); KEEP crates but re-caption to device-cert roles (issuance + mint live in
  the IdP/broker; warrant signing is the config cert). Check registrar framing against design.
- **KEEP:** DNS/DNSSEC discovery section (`179-199`) — fully consistent with design's
  trust root. "Why" attribution/bounded/revocable pillars (`18-33`) survive as positioning.
- **ADD:** mandatory-conformance statement (every IdP implements issuance+mint), agent-native
  headless minting, least-privilege authn≠authz. Currently absent.
- The one-call `/verify` example (`40-58`) stays at the RP surface (RP doesn't care about
  internal cert shapes), but `r.email` / `r.agent.parent/scopes` should reconcile with
  identifier+subject vocabulary.

## docs/verify-quickstart.md — MOSTLY KEEP, one wrong field

- The `/verify` HTTP contract is RP-facing and the design says "specifies what the RP
  receives, not how it verifies" — so the endpoint shape, fail-closed rules, and
  Python/Go/curl examples KEEP.
- `"assertion": "<certificate~assertion string>"` (`26`, `48`) — UPDATE the wording: the
  presented blob is now access cert + assertion + warrant + config cert, not
  `certificate~assertion`. The field name can stay; the description is stale.
- `accepted_fallbacks` / no-primary framing (`50-55`) — reconcile with design Conformance:
  fallback IdP only serves **no-primary** domains; a fallback-issued cert for a domain that
  HAS a primary must fail. Worth a sentence.

## sdk/js/README.md (`@browserid-ng/verify`) — KEEP

RP-side hosted-verify wrapper; result shape (`email/issuer/expires/agent`) and fail-closed
semantics are all RP-surface and consistent. No cert-shape claims to fix. Minor: `agent`
attribution vocabulary (parent/scopes) vs design's (identifier, subject, audience).

## sdk/agent/README.md (`@browserid-ng/agent`) — UPDATE

- "How it maps to the protocol" (`77-88`): provision endorse→mint and warrant
  request→poll roughly track the design, but the mental model is old: assertion "signed with
  the agent's own key; presented as `agent_cert ~ warrant ~ assertion`" — REWRITE to the
  device-cert/access-cert split (agent device cert mints an **access cert**; presents access
  cert + assertion + warrant + config cert). "the human signs the warrant with their own key"
  → the human's **config cert** signs it.
- KEEP: provision-a-delegated-identity, request-warrant, revoke API surface.

## sdk/wallet/README.md — UPDATE (light)

Tool surface (`provision/authorize/get_assertion/sign_guestbook`) is fine. "the private key
is generated locally and never transmitted" (`38`) is consistent with device-keypair
generation. Framing "delegated from yours" should reconcile with IdP-issued agent device cert
+ user-authorized issuance (agent variant, design Stage 1) rather than key-chaining.

## examples/rp-quickstart/README.md — KEEP

RP-surface; `verifier.verify(assertion, RP_ORIGIN)` and agent-rejection default are correct.
"loads the dialog from browserid.me" (`24`) stays (browser = one device). No wrong snippets.

## examples/mcp-agent-auth/README.md — UPDATE (light)

- The flow diagram (`19-23`) and `authorize` helper (`87-94`) are RP/verify-surface and
  correct. But `wallet.get_assertion ─▶ agent_cert ~ warrant ~ assertion` (`21`) shows the old
  3-part blob — UPDATE to the access-cert bundle.
- KEEP the "hoist auth to transport" note and scope-enforcement helper.

## marketing/index.html (landing) — KEEP narrative, one wrong artifact

- Positioning ("Identity for agents, answerable to humans", problem trio, per-site
  user-signed warrants, revocable, DNS-rooted, verify-in-one-call) is fully compatible with
  the design and should KEEP.
- The **agent.ts code card** (`476-483`): `provision({as})` → `obtainWarrant` → `assert` is
  illustrative and survives, but note it presents the assertion abstractly (fine).
- The **credential card** CSS/markup describes an abstract signed credential — no wrong
  protocol claim.
- ADD (optional, positioning): agent-native + headless-minting + "browser is one device"
  angle is a strength the landing under-sells; the mandatory-conformance ("works with any
  email/domain because every IdP implements it") reinforces the existing "any email, any
  domain" chip (`442`).
- Nothing here hard-asserts `certificate~assertion`, so landing is the least-diverged surface.

## marketing/fedcm-demo.html — UPDATE / re-evaluate

- Uses `navigator.id.request()` + include.js popup + "SMTP-verified (Secondary) email …
  that's what FedCM surfaces" (`26-48`). This is browser-login plumbing; the popup channel is
  KEPT by design (Stage 1 WinChan), but the FedCM account-chooser framing and the
  "certificate~assertion" mental model behind `/verify` need reconciling with access-cert
  minting. Low priority (demo page), flag as UPDATE.

## marketing/README.md — KEEP

Pure ops/deploy doc (origin split, Dokku, DNS/TLS). No protocol narrative to diverge.

---

## Priority wrong snippets (fix first)
1. `README.md:166-178` — backed-assertion format + "warrant signed by identity key".
2. `README.md:100-113` — chain-model "one picture".
3. `sdk/agent/README.md:77-88` — protocol mapping (agent_cert~warrant~assertion).
4. `docs/verify-quickstart.md:26,48` — `certificate~assertion` field description.
5. `examples/mcp-agent-auth/README.md:21` — `agent_cert ~ warrant ~ assertion`.

## Missing across all docs (ADD)
- Access cert vs device cert (fresh-key, online mint, ITP-proof/cookie-free).
- purpose × subject device-cert taxonomy; config cert as warrant signer.
- Mandatory conformance: every IdP implements issuance + mint API; fallback only for
  no-primary domains.
- Agent-native headless minting; browser = one device among many.
- Least privilege: authentication ≠ authorization.
</content>
</invoke>
