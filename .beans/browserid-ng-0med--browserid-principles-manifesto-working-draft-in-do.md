---
# browserid-ng-0med
title: BrowserID principles manifesto (working draft in docs/principles.md)
status: completed
type: task
priority: normal
created_at: 2026-08-26T15:43:15Z
updated_at: 2026-08-26T22:18:50Z
---

Develop a declaration of principles for BrowserID — what we're solving and what constrains the solutions. Audience: fellow-travelers. Format: bold principle sentence + short explanation, optional below-the-fold detail. First draft lives in docs/principles.md.

Decisions so far:
- Opening = the "we lost the open-identity battle once; agents force the question open again" story, NOT an aspirational "a web where..." preamble
- Principles must be tight and non-duplicative; kill switch/fail-closed/expiry all live inside "all authority is borrowed"
- Broker stance: loyal in interest, neutral in fact (verifiability, not goodwill)
- Attenuation (delegation can only narrow) = derivable from borrowed authority; implementation (chained warrants) is roadmap, not manifesto
- Operator commitments excluded unless they pass the test "would we demand this of someone else's deployment"
- Contrast-pairs coda: parked, decide later

Open items:
- [x] Workshop bold lines for principles 2 and 3 — (2) "No gatekeepers.", (3) reframed around ownership ("Every identity answers to its owner")
- [x] Decide whether a diagnosis beat joins the opening story — decided: no, "Why now" stands as-is
- [x] Decide on contrast-pairs coda — decided: omitted, the eight principles stand alone
- [x] Tighten below-the-fold texts; cut anything that repeats a sibling principle (full tightening pass in v3)
- [x] Final pass for "will" language leaking into principles (dreams belong in the opening, promises in the principles)

## Notes moved out of the doc (2026-08-26 — doc now holds only Why-now + principles)

**Bold-line history (don't re-litigate):**
- (2) "No gatekeepers." adopted. Rejected: "Entry requires a domain, not a deal" (AI-punchy); "need no one's blessing" (brokers weakened it).
- (3) ownership framing adopted so managed identities are the same rule with a different owner, not an exception. Rejected: "Attestation is not dominion" (opaque), "Issuers vouch; they don't watch" (misses the veto half).
- (7) Dan's line in is/does form. Standby headline if it wobbles: something built on "no chicken-and-egg". Historical claim ("what killed the last generation") deliberately removed.

**Settled:**
- (1) requirements now stated abstractly (understood-as-identity, open issuance, trust root in the name); domain registration and split-on-@ are email's realization, not the requirement.
- (2) names the browserid.me defaults honestly: a default is not a gate; escape hatches everywhere; no-gatekeepers holds with defaults in place.
- (4)/(5) revocation echo is intentional (human's safety vs agent's addressability).
- (6) middle paragraph meets the disloyal-AI-agent worry: duty + enforced boundaries ("where loyalty can't be verified, boundaries can be enforced").
- Operator commitments excluded; attenuation derivable from (4), chained warrants = roadmap; no "a web where…" preamble.

**Framing memo — swapping the broker (keep in mind, not in the text):**
Replacing the broker is not unilateral for any single party. Either the RP chooses a different broker (real cost: users won't have it set up, unfamiliar implementation), or the user's browser natively implements navigator.id.* (fine — the user's choice), but if that browser's broker issues fallback certificates the RP still has to trust that fallback. Our implementations hard-code browserid.me as default because (7) demands some default. Hence (7) names per-party swap paths (issuer↔domain, verifier↔site, native browser↔user) and never claims "anyone can swap the broker" flatly.

**Parked (low importance per Dan, revisit only if the doc gets a next life, e.g. publication):**
- Diagnosis beat (borrowed passwords / no boundaries / no kill switch) joining "Why now"
- Contrast-pairs coda (human authority over agent autonomy; legible over unlinkable; open federation over curated trust; revocation over rotation; working defaults over pure decentralization)
- The word "censorship resistance" appears nowhere; substance lives in (2)+(3)

## Principle 8 added (2026-08-26, shipped 1157050)

"Ease of use is not an afterthought." — Dan's headline. Body says both halves: delight matters in its own right AND ease is load-bearing (path of least resistance = the threat model; the shortcut wins when the right way is harder). Concrete bars: sign-in easier than a password, adding to a site takes five minutes, agent identity easier than handing over yours. Closer: "A design that is correct but burdensome is not correct yet."

Reorder: ease slots at 6, loyalty ("Anything that acts between you and the world…") moves to 8 as the deliberate closer. All other numbers unchanged, so the (see 2)/(see 7) cross-references survived untouched. P5's "honesty cheaper than masquerade" now reads as the agent-specific instance of 6.

All three copies synced (guardrails green); /about "in one breath" gained the ease clause and says "full eight".

## Summary of Changes

The manifesto is done and published. Final state: docs/principles.md (source of truth) = "Why now" (3 paragraphs: the platforms filled the identity gap; open attempts incl. our own Persona lineage lost; agents forcibly reopen the question) + eight principles, each a bold sentence with a short plain explanation:

1. Your identity is an email-shaped name.
2. No gatekeepers.
3. Every identity answers to its owner — and no one else.
4. All authority is borrowed.
5. One protocol for humans and machines.
6. Ease of use is not an afterthought.
7. No one has to choose between open and working.
8. Anything that acts between you and the world owes its loyalty to you. (deliberate closer)

Published at https://www.browserid.me/principles (html + md mirror), drift-guarded by a cargo byte-sync test and a test.sh html-containment check (bean fip9). Reached from the footer sitewide and from /about's "Read the eight principles →" link; /about is in the top nav and carries the one-breath paraphrase. README links the doc up top.

Open items resolved by decision: no diagnosis beat added to "Why now"; contrast-pairs coda omitted. Candidates preserved in this bean's earlier notes if ever revisited.
