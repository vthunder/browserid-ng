# browserid.me website — design brief (hub-and-spoke, unified product)

*Bean browserid-ng-c7um. Feed this to Claude Design. Written 2026-08-10.*

## 0. What we're making

One product, told as one story, entered through three doors. Today's site is a
single agent-first page (`marketing/index.html`). We're expanding it into a
**hub-and-spoke** site: one home page that carries the whole story and routes,
plus three focused spoke pages by audience, a demos index, and a thin docs
router. It is **not** three products — it's one identity primitive with three
entry points, and the design must make that oneness felt (shared language, one
nav, cross-links between spokes).

**The spine every page reinforces:** *one identity primitive for humans and
their agents — scoped, attributed, revocable — rooted in DNS, answerable to a
human.*

## 1. Voice, tone, lineage

- **Agent-first**, humans a close second. The current hero nails the voice —
  keep it. Confident, concrete, a little contrarian; no enterprise mush.
- **Descended from Mozilla Persona / BrowserID.** Say it in the footer; it buys
  instant credibility with the technical skeptic.
- **Proof over adjectives.** Live links, real code, and verifiable facts
  (DNSSEC, one-DNS-record off-ramp) do the persuading. Every page should have
  more things-you-can-click-and-verify than things-we-assert.
- Audience is technical (developers, agent builders, domain owners/CTOs).
  Technical-but-approachable. Short sentences. Real terminology, lightly
  explained.

## 2. Skeptic-handling — implicit, never a FAQ

Do **not** add "But what about…?" sections. Instead each page leads with a
**positive claim that leaves the top objection nowhere to land**, and we only
spend words on an objection where our answer is genuinely differentiating.
Everything else (is it real? maintained?) is answered silently by live demos +
open source. The four to dissolve implicitly:

| Audience | Unspoken objection | The positive claim that dissolves it |
|---|---|---|
| App devs | "My users don't have BrowserID accounts (chicken-and-egg)" | **"Works with the email your users already have."** |
| Domain owners | "Putting my identity on your server = lock-in" | **"Your domain, your DNS — flip one record to self-host whenever."** |
| Everyone | "Will you exist in a year? Privacy?" | **"Verifies offline against DNS — no one sits in the middle, nothing breaks if we disappear."** (persistent trust line) |
| Agent builders | "Another auth dependency / API keys are fine" | Lead with the **PAT-vs-warrant contrast** — it's our unique answer, so it's the narrative, not a defense. |

## 3. Global elements

**Nav (sticky):** Home · **Agents** · **Developers** · **Domains** · Demos · Docs · [Sign in]
Sign-in and the domains CTA route to the app origin (browserid.me/account,
browserid.me/domains).

**Footer:** GitHub · Docs/Spec · Live services (browserid.me, idp.browserid.me,
mcp-demo.browserid.me, python-mcp-demo.browserid.me) · "Descended from Mozilla
Persona" · License.

**Reusable components (design once, use everywhere):**
1. **Audience-router card** — three cards (Agents / Developers / Domains), each a
   one-line promise + link. The hub's core navigation device.
2. **Live-demo card** — title, one-line "what this shows", status dot, launch
   link. Used on home, /agents, and the demos index.
3. **Code-snippet block** — tabbed by language/framework; copy button. The
   visual anchor of the developer-facing pages.
4. **Revoke / kill-switch visual** — the signature moment: a human clicks
   revoke, the agent's next action fails closed. Reused on /agents, /developers,
   and end-user reassurance. Worth real motion-design investment.
5. **Trust badge/line** — "verifies offline against DNS" — a persistent,
   quiet element, not a one-off.

**Existing design system to preserve** (from `marketing/index.html` — keep it,
it's good):
- Palette: light default + dark toggle over one hierarchy — ground/panel/wells,
  two border weights, text/muted, and three accents: **gold** (primary accent /
  humans / filled CTA), **cyan** (agents), **green** (success/verified).
- Mono **kicker** labels (uppercase, letter-spaced, gold or cyan) above section
  heads. System-ui body, ui-monospace for code/kickers.
- Card shadows, 1080px max width, generous section rhythm with hairline
  section borders.
- 🪪 favicon; theme persisted in localStorage, set before first paint.
- Self-hosted PostHog analytics on the marketing origin only (no keystore/cookies
  there); ingestion reverse-proxied via `/ingest`. Keep this wiring.

**Live vs coming:** everything below is **live** unless tagged `[coming soon]`.
Per the owner's call, features we've built but not yet flipped on (the
"claim your Gmail / Workspace by signing in with Google" bridge) are shown as
**live**. Only genuinely-unbuilt roadmap gets `[coming soon]`.

## 4. Pages

### 4.1 Home (the hub)

- **Audience:** everyone; routes onward.
- **Hero — KEEP THE CURRENT ONE (agent-first, humans secondary):**
  - H1: *"Identity for **agents**, answerable to **humans**"* (agents in cyan,
    humans in gold).
  - Lede: *"Your agent gets an identity of its own — created once, under the
    email you already use. Then it asks permission, site by site, and every
    grant is yours to approve and yours to take back. Works anywhere; human
    sign-in included."*
  - Actions: primary "See the agent demo", secondary "Add sign-in to your app".
  - Sub-line: *"Works with the email you already use · no passwords · no lock-in"*
  - Keep the replayable **two-step approval animation** that's in the current
    hero — it's a strong first-screen proof.
- **Section — the one-primitive story:** the short spine, one diagram. A human
  signs a warrant → the agent presents exactly that → revoke kills it,
  fail-closed, no key rotation.
- **Section — audience router:** the three cards (Agents / Developers / Domains).
- **Section — see it working, live:** demo cards (guestbook, mcp-demo,
  python-mcp-demo, Bluesky).
- **Section — why trust it:** verifies offline against DNSSEC; rides existing
  standards (MCP OAuth, DNSSEC); descended from Persona; open source.
- Footer.

### 4.2 /agents — the wedge (build first)

Broader than MCP: **give your agent a real, revocable, attributed identity.**
Two threads.

- **Audience:** agent / MCP-server builders (sharpest, hottest market).
- **Hero:** *"Stop putting API keys in your agent's config."* Sub: give it its
  human's scoped, revocable warrant instead — every action attributed, revoke in
  one click. CTA: "Try the live demo" · "Add it to your server".
- **Section — the contrast (lead):** PAT-in-config (unscoped, unattributed,
  revoke = rotate everywhere) **vs.** warrant (scoped, "agent X for human Y",
  one-click revoke, no rotation). Side-by-side. This is the narrative.
- **Section — the signature demo:** the revoke-kills-the-agent moment (component
  #4) + links to `mcp-demo.browserid.me` and `python-mcp-demo.browserid.me`.
- **Thread 1 — integrate it (MCP):** tabbed quickstart — `@browserid-ng/mcp-auth`
  (JS) / `browserid-mcp-auth` (Python/FastMCP). ~10-line snippet. "Rides MCP's
  own OAuth 2.1; your host (Claude, Cursor, …) speaks it unmodified and never
  learns BrowserID exists."
- **Thread 2 — see it act, attributably, in the wild:** the **Bluesky** demo (an
  agent posts to a real platform, verifiably attributed to its human, revocable)
  and the **guest wall / guestbook**. This is the differentiator: not an MCP
  shim — a general "this action was taken by agent X under authority Y,
  verifiable offline" primitive that already works on real platforms.
- **Section — for the agent's human:** the wallet (`npx @browserid-ng/wallet`)
  and where you revoke (browserid.me/account).
- `[coming soon]` teaser: the warrant-gated **GitHub** flagship server.

### 4.3 /developers — Sign in with BrowserID

- **Audience:** app developers adding user login.
- **Hero (chicken-and-egg killer up front):** *"Passwordless sign-in in ~10
  lines — works with the email your users already have."* Sub: no passwords to
  store, no user-secret table, no client IDs. CTA: "Pick your framework".
- **Section — drop-in adapters:** four cards — **NextAuth · Express · Hono
  (edge) · Fastify** — each with its one-liner and a snippet.
- **Section — or verify in one call:** the `@browserid-ng/verify` snippet + the
  `POST /verify` HTTP contract for any language.
- **Section — what you get back:** `{ email, grantee, scopes, issuer }`;
  fail-closed; no registration/secrets. "No company sits between you and your
  users; verification is offline against DNS."
- **Section — claim the email you already have:** sign in with Google to prove a
  Gmail / Workspace mailbox and use it as a BrowserID identity. (Shown live.)
- **Section — the same identity your users' agents use** → bridge to /agents.

### 4.4 /domains — run identity for your domain

- **Audience:** domain owners, orgs, CTOs (the hardest skeptic — lock-in / trust).
- **Hero (lock-in killer up front):** *"Be your own identity provider — with one
  DNS record."* Sub: browserid.me issues certs **as your domain**; your users
  manage nothing; every RP accepts you with zero config. CTA: "Add your domain"
  → browserid.me/domains.
- **Section — how it works:** publish one DNSSEC `_browserid` record → `iss =
  yourdomain.com`. **Woven-in off-ramp (the anti-lock-in trump card, stated as a
  property not a rebuttal):** "It's your domain and your DNS — issue as yourself
  today, flip one record to self-host whenever you want. Nothing you depend on is
  un-leaveable."
- **Section — sign in with Google (for Workspace/Gmail domains):** users
  authenticate with Google, no passwords, mailbox-verified. (Shown live.)
- **Section — the security model (stated positively):** per-tenant custodial
  keys, sealed and exportable — a compromise is isolated to one domain, never a
  shared master key. Rooted in DNSSEC; RPs never call our servers to verify your
  users.
- `[coming soon]`: **directory sync** (your Workspace directory *is* the roster —
  auto-provision / deprovision) and a **self-host primary kit**.

### 4.5 Demos (index)

- Simple gallery of every live demo, each a component-#2 card with a one-line
  "what this shows": guestbook, mcp-demo, python-mcp-demo, Bluesky, fedcm-demo.

### 4.6 Docs / Spec

- Thin routing page → GitHub README, protocol spec, verify quickstart,
  integration READMes. Deep-link to GitHub rather than re-host. Clean index, not
  marketing.

## 5. Content inventory (real names/URLs to wire)

- **Origins:** www (marketing), browserid.me (broker/app: /account, /domains),
  idp.browserid.me (hosted-primary tenant surface).
- **Live demos:** mcp-demo.browserid.me, python-mcp-demo.browserid.me, guestbook,
  Bluesky bridge, fedcm-demo.
- **Packages:** `@browserid-ng/verify`, `@browserid-ng/mcp-auth`,
  `@browserid-ng/wallet`, `browserid-mcp-auth` (PyPI/FastMCP);
  adapters: `@browserid-ng/nextauth`, `@browserid-ng/express`,
  `@browserid-ng/hono`, `@browserid-ng/fastify`.
- **HTTP contracts:** `POST /verify-access`, `POST /status/check`,
  `POST /token` (MCP AS).

## 6. Build order

1. **Home + /agents** first (unified story + the sharpest wedge).
2. Then **/developers** and **/domains**.
3. **Demos** index + **Docs** router last (thin).

Keep `guestbook.html` and `fedcm-demo.html`. The single-page `index.html` is
superseded by the new Home; migrate its strongest sections into the spokes.
