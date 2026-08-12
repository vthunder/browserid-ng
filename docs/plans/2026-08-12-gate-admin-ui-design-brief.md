# Design brief — the MCP Gateway admin console

**For:** a fresh visual + interaction design of the gateway's web admin console.
**Audience:** a designer with no prior context on this product. Everything you
need is here. Deliver screen designs (all states below) + a component/visual
system; production is static HTML/CSS/JS (constraints at the end).

---

## 1. What the product is (plain language)

**MCP Gateway** is a small self-hosted tool a developer runs on their own
machine with one command. It takes local "MCP servers" — little programs that
let an AI assistant (like Claude) use a tool or read some data (your notes
folder, a database, your smart-home hub) — and safely publishes them on the
internet so an AI assistant can reach them **from anywhere**, with **per-person
access control** and **no shared passwords or API keys**.

Think **Tailscale for AI tool access**: a personal, developer-grade utility
that turns a fiddly, dangerous task (exposing a local service to the internet)
into a couple of clicks, with security built in.

The **admin console** you're designing is the web page where the owner manages
that gateway: signs in, and adds/removes the servers they want to publish.

Mental model to convey: *"This is MY gateway. I decide what's published and who
can reach it."*

---

## 2. Who uses it & the vibe

- **Primary user:** a technically-comfortable hobbyist / developer running this
  on a home server or laptop. Comfortable with a terminal, but wants the web UI
  to make the fiddly parts obvious and safe.
- **Growth user (later):** a small team / startup exposing their own product to
  AI assistants — same console, higher stakes.
- **Emotional target:** *calm confidence.* This tool controls access to a
  person's files and services, and it runs commands — the UI should feel
  trustworthy, precise, and in control, never toy-ish or noisy. Reference
  points: Tailscale admin, Vercel/Railway dashboards, 1Password — clean,
  developer-serious, quietly premium. Not a consumer SaaS with big gradients.

---

## 3. The core concepts the UI must make legible

You don't need the crypto, but these ideas must come through clearly, because
they're *why the product exists*:

1. **Sign in with your identity, gated to the admin.** Only ONE identity (an
   email the owner set at launch, e.g. `dan@example.com`) can get into the
   console. Login is "Sign in with BrowserID" (a passwordless identity system —
   treat it like "Sign in with Google," a button that opens a sign-in dialog).
   Everyone else is refused.
2. **A "mount" = one published MCP server.** Each has: a **name** ("Dan's
   Notes"), a **mount path** (a URL slug, `notes`), the **command** that runs it
   (`npx -y @modelcontextprotocol/server-filesystem ~/notes`), and an
   **allowlist** (the emails of people whose AI agents may connect). Once added,
   it's reachable at a **shareable URL**: `https://<host>/<mount>/mcp`. That URL
   is the thing the owner copies and pastes into Claude (or gives a friend).
3. **You decide who connects, by email.** The allowlist is the access control —
   "friend@gmail.com can use this, nobody else." This is a headline feature, not
   a footnote.
4. **No tokens, and revocable.** Whoever connects presents a short-lived,
   scoped, **revocable** permission from a human — not a stored password/API
   key. Every action is attributed ("agent X acting for human Y"). The owner (or
   the connecting person) can revoke access and it dies on the next call. Convey
   this as the trust story; the UI doesn't manage the revocation itself but
   should reinforce "safe, attributed, revocable."
5. **⚠ Changes are STAGED — a restart applies them (deliberate safety).** This
   is the single most important, most unusual interaction to design well. When
   the owner adds/edits/removes a mount, **nothing happens to the running
   gateway immediately** — the change is saved to config, and the owner must
   **restart the gateway** (stop it in the terminal and run it again) for it to
   take effect. This is on purpose: the console can run arbitrary commands, so
   staging changes means a break-in can't instantly execute a malicious command
   — a human has to restart. The UI must make the **"running vs. saved / pending
   changes — restart to apply"** distinction impossible to miss, without being
   alarming. This is the interaction most in need of a great design.

---

## 4. Screens & states to design (cover all of these)

**A. Signed-out**
- Brand + one line of what this is. A single primary action: **Sign in with
  BrowserID**. Note that only the gateway's admin can get in. Handle a sign-in
  error state (wrong identity / failed) inline.

**B. Signed-in — empty**
- Header: product mark, the signed-in admin's email, **Sign out**.
- Empty state: "No MCP servers yet" + a prominent **Add an MCP** call to action,
  ideally with a one-line "here's what that does."

**C. Signed-in — with mounts (the main screen)**
- A list of mounts. Each row/card should show:
  - **Name** + its **mount path**.
  - The **public URL** (`https://<host>/<mount>/mcp`) with a **copy button**
    (copy is the primary thing people do here — make it effortless).
  - **Status**: running · stopped/disabled · **pending (needs restart)**.
  - **Allowlist**: how many people, ideally who (emails), editable.
  - **Tools**: how many tools this server exposes (a small count/detail).
  - Row actions: **enable/disable**, **remove** (with an in-content confirm — NOT
    a browser popup).
- A persistent, clear **"N pending changes — restart to apply"** affordance when
  the saved config differs from what's running — explain briefly *how* to
  restart (it's a terminal action), and show *what* changed (added/removed/edited
  mounts). Design this as a first-class element, not a toast.

**D. Add / edit an MCP (a form or dialog)**
- Fields: **Name**, **Mount path** (slug; show the resulting URL live as they
  type, e.g. `https://<host>/[notes]/mcp`; validate: unique, url-safe),
  **Command** (the argv to run — treat as a power-user field; reassure that it
  runs as literal arguments, not a shell, and show the exact argv on confirm),
  **Allowlist** (emails).
- On save: make crystal clear this is **staged** — "Saved. Restart the gateway
  to publish it." Don't imply it's live.

**E. Micro-states**
- Copy-URL success feedback.
- Save success → the pending-changes state appears.
- Remove → confirm inline → moves to pending.
- Errors (bad slug, duplicate mount, save failure) inline near the field.

---

## 5. The current UI (reference only — improve on it, don't copy)

Today it's a bare-bones page: a header with the admin email + sign-out; a
"Your MCP servers" heading with an "Add an MCP" button; a plain list; and a
modal for adding one. It works but is visually flat and doesn't sell the
concepts in §3 — especially the **staged/restart** model (currently just a text
banner) and the **share-a-URL** and **allowlist** stories, which are the
product's whole point. The redesign should make those legible and confident.

---

## 6. Constraints (important for production)

- **Tech:** ships as **static files** served by the gateway — one `index.html`,
  one CSS file, one JS file. **All CSS/JS must be self-contained and in external
  files** (no inline `<script>`; a strict content-security-policy forbids it). No
  build step, no framework required (vanilla is fine); if you spec components,
  keep them implementable in plain HTML/CSS/JS. No external network requests
  (no CDN fonts/scripts/images — inline or system fonts only).
- **Theme:** should look right in **both light and dark** (developer tools are
  used in both). System-font stack is fine and on-brand.
- **Responsive-ish:** primarily a desktop tool, but shouldn't break on a narrow
  window / tablet.
- **Security-serious tone:** this console gates access to files and runs
  commands. It should *feel* secure and deliberate — clarity over flash. Avoid
  anything that reads as consumer-marketing.
- **Accessibility:** real focus states, keyboard-operable dialogs, sufficient
  contrast in both themes, no reliance on color alone for status.

---

## 7. What "great" looks like (success criteria)

1. A first-time user immediately understands: *this publishes my local servers,
   I control who connects, and I copy a URL to share.*
2. The **staged → restart-to-apply** model is understood without reading docs —
   the difference between "running" and "saved/pending" is unmistakable and
   calm, and the user knows the next step is a restart.
3. Adding a server feels safe and precise — especially the command field (the
   scary part) and the resulting shareable URL (the rewarding part).
4. Copying a mount's URL and seeing its allowlist are effortless.
5. It looks like a tool a security-minded developer would trust with access to
   their machine.

---

## 8. Deliverables requested

- All screen states in §4 (light + dark), desktop first.
- A small visual system: type scale, color roles (incl. status colors for
  running/pending/disabled), spacing, the primary components (mount row/card,
  the add form/dialog, the pending-changes banner, buttons, inputs, copy
  affordance, status pills).
- Notes on the one interaction that matters most: how "pending changes —
  restart to apply" is surfaced and explained.
