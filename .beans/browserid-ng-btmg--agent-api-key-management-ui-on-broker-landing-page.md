---
# browserid-ng-btmg
title: Agent API-key management UI on broker landing page
status: todo
type: task
priority: normal
created_at: 2026-07-08T19:05:55Z
updated_at: 2026-07-10T23:26:02Z
parent: browserid-ng-l8lw
---

Backend endpoints exist (/wsapi/agent_keys, /wsapi/create_agent_key, /wsapi/revoke_agent_key — session+CSRF gated) but there is no browser UI. Add a minimal section to /account (static/account.html — the landing page /agents was retired into /account by ddd7189) to mint (show-once), list, and revoke API keys when agent provisioning is enabled.
