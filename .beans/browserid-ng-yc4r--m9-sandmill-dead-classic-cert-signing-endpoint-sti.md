---
# browserid-ng-yc4r
title: '[M9] sandmill dead classic-cert signing endpoint still routed (/api/browserid/cert_key)'
status: todo
type: bug
priority: normal
created_at: 2026-08-07T16:03:44Z
updated_at: 2026-08-07T16:03:44Z
parent: browserid-ng-8g49
---

POST /api/browserid/cert_key -> certKey (sandmill BrowserIdController.php:381, routed web.php:205) signs classic principal.email certs (no current verifier accepts) with the live IdP key; admin can mint for any @sandmill.org. 500s on seed-only key (createCertificate uses base64urlDecode(privateKey) raw at :463 instead of secretKey()). Removal commit 9f81aaa removed a different endpoint. Remove it. See audit M9.
