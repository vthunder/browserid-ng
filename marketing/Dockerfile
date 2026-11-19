# Static marketing site (www.browserid.me) — a separate origin from the broker.
# Tiny nginx image; no build step. Deployed as its own Dokku app so it shares
# no origin (keystore/cookies/wsapi) with the auth/issuer broker.
# Base image pinned by digest (audit 2026-11 W7-7): the tag names the
# version a human chose, the digest makes the build reproducible. Bump by
# re-resolving the tag (multi-arch manifest list, 2026-11-19).
FROM nginx:1.30.7-alpine@sha256:bef154735288bc38d99fac41ae63730684bcc661503673a04a0f9bc526ba8598

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html developers.html domains.html demos.html gate.html mcp-demo.html about.html contact.html privacy.html principles.html config.js analytics.js fedcm-demo.html llms.txt site.css site.js /usr/share/nginx/html/
# Agent-readable surface: markdown page variants (Accept: text/markdown
# negotiation), the markdown 404, the OpenAPI spec, and crawl metadata.
COPY index.md developers.md domains.md demos.md gate.md mcp-demo.md about.md contact.md privacy.md principles.md 404.md openapi.json robots.txt sitemap.xml /usr/share/nginx/html/
COPY vendor/ /usr/share/nginx/html/vendor/
COPY img/ /usr/share/nginx/html/img/

EXPOSE 80
