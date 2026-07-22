---
# browserid-ng-jgta
title: 'post.v1/comment.v1: require the HLC + bound it by DA block time'
status: draft
type: task
created_at: 2026-07-22T19:16:45Z
updated_at: 2026-07-22T19:16:45Z
parent: browserid-ng-oup3
---

Dan (2026-07-22, first CLI post): a post submitted without an HLC lands at the bottom of mingo-web with no timestamp — the wire's hlc is Optional, readers sort/display by it, and the schema doesn't require it. The CLI now sets one (immediate fix), but the schema should enforce it:

- [ ] require hlc (or an equivalent authored-at) for content schemas (post.v1, comment.v1, reaction.v1) — a content write without a timestamp should be rejected at validation, not accepted and rendered undated
- [ ] bound it against DA block/inclusion time both directions (the space _config max_authoring_lag_s already bounds backdating when hlc is present — decide the forward bound too)
- [ ] decide layer: sbo schema validation vs mingo policy/_config (leaning schema for the presence requirement, _config for the bounds — sbo repo change either way)
