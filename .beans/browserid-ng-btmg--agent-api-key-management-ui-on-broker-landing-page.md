---
# browserid-ng-btmg
title: Agent API-key management UI on broker landing page
status: todo
type: task
created_at: 2026-07-08T19:05:55Z
updated_at: 2026-07-08T19:05:55Z
parent: browserid-ng-l8lw
---

Backend endpoints exist (/wsapi/agent_keys, /wsapi/create_agent_key, /wsapi/revoke_agent_key — session+CSRF gated) but there is no browser UI. Add a minimal section to the landing page (static/index.html) to mint (show-once), list, and revoke API keys when agent provisioning is enabled.
