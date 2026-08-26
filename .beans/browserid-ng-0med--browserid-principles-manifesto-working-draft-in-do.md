---
# browserid-ng-0med
title: BrowserID principles manifesto (working draft in docs/principles.md)
status: in-progress
type: task
priority: normal
created_at: 2026-08-26T15:43:15Z
updated_at: 2026-08-26T17:37:54Z
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
- [ ] Decide whether a diagnosis beat (borrowed passwords / no boundaries / no kill switch) joins the opening story
- [ ] Decide on contrast-pairs coda
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
