---
# browserid-ng-m8wc
title: Evaluate keeping the redirect (consent_uri) path for admission
status: todo
type: task
created_at: 2026-09-11T14:25:08Z
updated_at: 2026-09-11T14:25:08Z
---

After g69e the gate hands the admission code to the wallet on its own origin (present lane) and only falls back to a redirect to /consent/<code> when the mediator script is unavailable (no-JS platforms, blocked popups). Decide whether to keep that fallback long-term or delete it: inventory who still needs it (no-JS clients, the authoring share link, native-wallet users on browsers without the extension), what it costs (the well-known audience-proof fetch, a broker-hosted card path, redirect UX), and what replaces it if removed. Related: g69e; connection-sharing.spec.ts covers the fallback today.
