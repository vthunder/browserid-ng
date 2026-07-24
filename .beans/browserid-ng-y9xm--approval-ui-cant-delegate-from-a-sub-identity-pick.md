---
# browserid-ng-y9xm
title: Approval UI can't delegate FROM a sub-identity (picker lists roots only)
status: todo
type: bug
priority: high
created_at: 2026-07-24T22:01:55Z
updated_at: 2026-07-24T22:01:55Z
---

Found 2026-07-25 while testing the bsky on-behalf flow (browserid-bsky-nr8p).

The approval page's identity picker offers only ROOT identities
(danmills@sandmill.org, dan@mingo.place). It has no way to approve AS a `+tag`
sub-address, even one the account demonstrably owns and that the page itself
minted earlier.

Consequence: a request that pins `grantor` to a sub-identity is
UNAPPROVABLE — the page cannot satisfy the pin, so
check_grantor_pin() can never pass. Hit live: an agent-provision request with
grantor=danmills+bskyjs@sandmill.org could not be approved at all, dead end.

Note the asymmetry — the page CAN MINT sub-identities (that is where
danmills+bskyjs@ and danmills+posting@ came from, via the handle/name field),
it just cannot DELEGATE FROM one afterwards. So sub-identities are
second-class: creatable, then unusable as a grantor.

This matters beyond the demo: it means any RP account owned by a
sub-identity can never later delegate to a separate actor. On the bsky bridge
the account is bound to the exact grantor email, so an account provisioned by
danmills+bskyjs@ is permanently stuck as-itself.

Fix direction: the picker should list owned sub-addresses too (the
`approver_owns_identity` rule already says a +tag of a verified email is
owned), or accept a typed identity validated against that same rule.
