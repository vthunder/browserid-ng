---
# browserid-ng-0med
title: BrowserID principles manifesto (working draft in docs/principles.md)
status: in-progress
type: task
created_at: 2026-08-26T15:43:15Z
updated_at: 2026-08-26T15:43:15Z
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
- [ ] Workshop bold lines for principles 2 and 3 (current candidates read AI-punchy)
- [ ] Decide whether a diagnosis beat (borrowed passwords / no boundaries / no kill switch) joins the opening story
- [ ] Decide on contrast-pairs coda
- [ ] Tighten below-the-fold texts; cut anything that repeats a sibling principle
- [ ] Final pass for "will" language leaking into principles (dreams belong in the opening, promises in the principles)
