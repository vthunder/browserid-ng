---
# browserid-ng-oenx
title: 'Agent display name: rename surface on the account page'
status: todo
type: task
created_at: 2026-07-26T18:23:05Z
updated_at: 2026-07-26T18:23:05Z
---

Follow-up to eywc: display_name is set at Flow I step 2 and stored on the agent email record (emails.display_name, migration v20), but there is no way to edit it later. Add a small /wsapi endpoint (session+csrf, ownership-gated — host.set_agent_display_name already exists registrar-side, and the store has set_email_display_name) and an edit affordance where agents are listed on account.html. Until then the P cards fall back to the agent's local part for pre-v2 agents.
