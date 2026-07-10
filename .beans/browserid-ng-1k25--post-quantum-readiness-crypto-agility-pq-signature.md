---
# browserid-ng-1k25
title: 'Post-quantum readiness: crypto agility + PQ signatures (browserid-ng + SBO on-chain)'
status: draft
type: task
priority: low
created_at: 2026-07-10T11:52:49Z
updated_at: 2026-07-10T12:42:02Z
---

Research/readiness track (not near-term). What it would take to make browserid-ng — and its on-chain (SBO) usage — post-quantum safe. File-for-later; needs more thought.

## Framing
browserid-ng is SIGNATURE-ONLY (assertions/certs are signed, never encrypted). So we need PQ SIGNATURES, not PQ KEMs — we dodge the hardest, most urgent TLS-style key-exchange problem. Ed25519 (ECDLP) is the vulnerable primitive everywhere. SHA-256 is only Grover-weakened (fine; SHA-384 for margin). TLS transport (DoT for the DNSSEC fetch, HTTPS endpoints) is a separate ecosystem layer already migrating (hybrid X25519+ML-KEM).

## Vulnerable components (all Ed25519)
IdP identity key in `_browserid` DNS + broker key; certificates and (planned) host certs (JWT EdDSA); assertions; the agent provisioning delegation chain; SBO on-chain object/attestor/checkpoint signatures.

## Changes, in order
1. **Crypto agility (enabling change; do regardless).** Today it's monomorphic Ed25519. Add algorithm-tagged keys/sigs + verify dispatch. Formats are half-ready: `_browserid` already has `public-key-algorithm=`; JWTs have `alg`; SBO `ed25519:<hex>` hardcodes alg -> needs `<alg>:<bytes>` (ripples into Controller rooting + SBO wire-format spec). Code: browserid-core keys.rs/certificate.rs/assertion.rs call ed25519-dalek directly.
2. **Algorithms (NIST 2024):** ML-DSA (Dilithium, FIPS 204) general default (~1.3KB key / ~2.4KB sig); SLH-DSA (SPHINCS+, FIPS 205) hash-based, most conservative, reserve for rarely-signed long-lived roots + checkpoints; Falcon (FN-DSA) smallest sigs where size-critical (DNS, on-chain), but hazardous signing.
3. **Hybrid during transition:** dual-sign Ed25519 + PQ so safe if either holds.
4. **Prioritize by lifetime/value:** IdP identity keys (in DNS), roots, on-chain identities first; short-TTL assertions can trail.

## The ceiling: the DNSSEC trust root
browserid-ng is only as PQ-safe as the DNSSEC chain that authenticates `_browserid` (and RFC 9102 offline proofs). If DNSSEC is quantum-broken, forge the record -> fake IdP key -> PQ certs underneath don't save you. PQ-DNSSEC is unsolved (PQ sigs vs DNS packet-size limits; SLH-DSA far too big, ML-DSA borderline) and is an IANA-root/TLD ecosystem problem, not ours. Fallback (secondary PQ trust root / transparency log) reintroduces the centralization we avoided by choosing DNSSEC. This is the binding constraint.

## On-chain / offline case: RETROACTIVE forgery risk (the important nuance)
Unlike ephemeral website auth (a forged expired assertion is useless), the ledger stores signatures that anchor history verified INDEFINITELY. So "harvest now, forge later" DOES apply to signatures here — as retroactively spoofing historical chain state / bootstrap proofs:
- A future quantum attacker holds every on-chain Ed25519 pubkey (public) and can forge sigs matching them. They could build a plausible ALTERNATE FORK from an early point (all sigs forged) and fool a fresh fast-syncing node.
- The defense is NOT the per-object signature; it's the immutability/ordering anchor: hash-linking (SHA-256, PQ-OK) + the checkpoint/attestation web-of-trust that pins the canonical root at each height. BUT those checkpoint/attestation signatures are Ed25519 today — so the bootstrap trust anchor (evaluate_trust / threshold backers, the attestor work this session) is itself quantum-forgeable. That is the concrete "spoof historical state" vector.

### Mitigation (collapses the retroactive risk)
1. **Make the checkpoint + attestation layer PQ-safe** (hash-based SLH-DSA is a natural fit — checkpoints are infrequent, so big/slow sigs are fine, and hash-based needs no lattice assumption). This is the single most important on-chain PQ change: it's what a new node uses to trust ALL of history.
2. **Ensure DA-layer inclusion/ordering is PQ-safe** (hash commitments, not signature-only) — relates to sbo-7bl8 (DA inclusion trusted from RPC, no reorg).
3. **Pre-quantum anchoring:** commit current chain state into a durable, widely-witnessed PQ-safe (hash-based) commitment NOW, so pre-quantum history has an immutable hash anchor a future attacker can't rewrite. Once history is pinned by a PQ-safe hash commitment, quantum-broken sigs INSIDE it can't rewrite it — they can only forge NEW data, which ordering rejects.
4. Per-object sigs -> PQ matters most for NEW writes going forward and for PURE-offline attribution (cert + detached DNSSEC proof with no chain anchor). Note: on-chain attribution is evaluated at inclusion time and the RESULT is baked into state, so a re-verifier trusts the state/checkpoint chain, not a re-verification of the old signature -> reduces again to checkpoint-layer PQ safety.

### SBO extras
- Wire-format alg agility; signature BLOAT (64B Ed25519 -> ~2.4KB ML-DSA, ~40x) is a real ledger storage/bandwidth cost -> argues Falcon on-chain or sig aggregation.
- Proving system: SNARKs (Groth16, pairing-based) are quantum-broken; STARKs are hash-based/PQ-safe. Existing zkVM beans -> proof-system choice is part of the PQ story.
- Related review beans: sbo-y5ek (pinned KSK decorative), sbo-7bl8 (DA trust/no-reorg).

## Highest-leverage first step
Build the crypto-agility layer (browserid-core + SBO wire format). It's a prerequisite for everything, de-risks the eventual algorithm flip, and is useful independent of PQ.

## Execution note
Cross-cuts browserid-ng (identity crypto) and sbo (ledger + checkpoint/attestation + wire). Likely spins an sbo-side bean for the on-chain execution when picked up.


## Base-layer (Avail DA) dependency — a second external ceiling

Beyond DNSSEC, SBO's on-chain integrity ultimately rests on the base DA/consensus layer (Avail). The checkpoint/attestation + hash-anchoring defenses above pin history at the SBO layer, but they sit ON TOP of Avail's block ordering and finality. If Avail's consensus crypto (validator signatures, finality gadget, networking key exchange) is quantum-vulnerable, a future quantum attacker could forge/reorg base-layer history — an alternate Avail history that SBO nodes would follow. So for on-chain history to be truly non-forgeable going FORWARD, we are bound by Avail switching to quantum-safe consensus (PQ validator sigs + finality). Like DNSSEC, this is external and not ours to fix.

Nuances:
- Pre-quantum HASH anchoring (on-chain mitigation #3) still protects history committed BEFORE the quantum era even if Avail hasn't migrated — a widely-witnessed hash commitment is base-layer-independent. But NEW post-quantum-era history needs a PQ-safe base layer.
- SBO's own checkpoint/attestation PQ migration reduces trust in the base layer for STATE integrity, but liveness / ordering / censorship-resistance still depend on Avail consensus.
- Action: track Avail's PQ roadmap; SBO forward on-chain integrity is gated on it.

## External ceilings (neither is ours to fix; both bound the on-chain PQ story)
1. DNSSEC — trust root for identity keys + offline attribution proofs.
2. Avail DA consensus — base-layer history integrity / ordering / finality.
Our layer (crypto agility, PQ certs, PQ checkpoints/attestations, hash anchoring) is necessary but not sufficient without these two.
