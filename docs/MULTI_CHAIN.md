# Multi-chain Chiral — refining the design beyond one pair

> Forward-looking design note (not built). How Chiral generalizes from Cardano⇄CKB to N chains, what a
> chain must bring to participate, and the honest limits. Builds directly on the SEC-D6 reorg work
> (`spike/ckb-to-cardano/circuit/D6_REORG.md`), whose K + cap turn out to be the per-chain *finality
> normalization* primitive multi-chain needs.

## 0. The invariant that makes it possible
Chiral is not a bridge between two chains; it is a **binding rule** (chain-agnostic) plus **oracles**
(per-direction). Every chain plays the same game:

> an asset is a **single-use seal on one chain** + a **shadow on the others**; you may act on a shadow
> only by proving the seal moved, **final to depth K**, with the amount inside the **commitment**.

The binding (seal + shadow + commitment + single-use) is identical everywhere. **Only the oracle changes** —
how chain X proves an event to chain Y. So "multi-chain" = grow a *registry of oracles + finality
profiles*, not a rewrite.

## 1. Refinement 1 — normalize the oracle, or drown in O(N²)
Naively each ordered pair X→Y needs a bespoke verifier on Y that understands X's consensus → O(N²)
verifiers. Kill it with a **canonical proof ABI**: every oracle emits the same shape

```
(chain_id, seal, source_root, commitment, K)
```

and every follower runs *one* generic verifier parameterized by the source's verifying key. Adding a chain
= **one prover** (its consensus → the canonical proof) + reuse the existing verifier instantiation →
**O(N)**. We are already most of the way there: the Groth16 leg's public inputs are
`(window_root, seal, commitment, tip, K)` — that *is* the ABI; it needs only an explicit `chain_id` and to
be declared the universal interface (so a proof for X→Y can never be replayed on X→Z — domain separation).

## 2. Refinement 2 — roles are asymmetric; wire a directed graph, not a clique
A chain has **four independent capabilities**; which *roles* it can play depends on which it has. Don't ask
"can X bridge to Y," ask "what can X *be*."

| Capability | Enables role | Examples |
|---|---|---|
| **Provable finality** (cheap to attest to outsiders) | **source / anchor** | PoW+work (BTC, CKB), stake cert (Cardano/Mithril), BFT quorum (Cosmos), validity proof (rollups) |
| **Single-use object** | holds **seals** | UTXO/cell native (BTC, CKB, Cardano); account chains **emulate** via a nullifier contract (Ethereum) |
| **Verifier surface** (run another chain's finality check on-chain, within budget) | **follower** | CKB-VM (arbitrary RISC-V), Plutus (BLS12-381 builtins). Bitcoin ≈ none |
| **Commitment slot** | stashes the binding | datum / cell data / witness / calldata / OP_RETURN |

Topology that falls out (a directed graph of "X can follow Y" edges, not a mesh):
- **Bitcoin** — strong finality, no verifier → **anchor-only sink** (everyone follows it; it follows no one). This is exactly RGB++'s ceiling.
- **Cardano** — PoS finality + Plutus, but *tiny* budget → follower that verifies **SNARK-compressed** proofs of the source.
- **CKB** — big verifier budget → can verify **natively**; cheap PoW → large **K** when it is the *source*.
- **Ethereum** — great verifier, **emulated** single-use (nullifier set), gadget finality.

## 3. The requirements checklist a chain must meet
Needs **all four** capabilities for the roles it wants. To be a **source** specifically, the SEC-D6 work
adds two:

5. **A declared finality profile `(finality_type, K, reorg_cost)`** — the direct generalization of the
   `min_confirmations` policy shipped in D6, from "CKB's K" to a **per-source-chain table of (K, cap)**.
   Weak-finality sources (cheap PoW) get large K + a value cap sized to their reorg cost; strong-finality
   sources (BFT / stake / validity-proof) get K≈1, no cap. **The D6 reorg defense is not CKB-specific
   plumbing — it is the finality-normalization layer every source plugs into.** The governance policy cell
   (`chiral_policy` / `PolicyState`) generalizes to a **per-source-chain finality registry**.
6. **Chain-id + direction domain separation** in the commitment/nullifier (no cross-edge replay).

## 4. The genuinely hard problem — path conservation (A→B→C)
Single-use must hold across the **whole path**, not per-edge: "spent once, minted once, live on exactly one
chain at a time," even under a reorg on *any* hop. Two honest options:

- **Re-root toward the strongest anchor** (the RGB++ move, formalized in D6 §1 as "security follows the
  seal"): keep the authoritative seal on the strongest-finality chain in the path; everyone else is a
  recoverable follower. A reorg on a follower only scrambles representation, never ownership → re-derive.
  This makes path-conservation tractable.
- **Composed finality is multiplicative — an unavoidable cost.** If value genuinely re-anchors at each hop,
  reorg exposure **compounds**: a path is only as safe as its weakest link, so the safe-value bound for a
  route is `min over the path of (cost to reorg that hop to depth K)`. This is the honest limit to put in
  front of an auditor: *multi-hop value is capped by the weakest chain's finality on the route.* You don't
  hand-wave it; you cap it (the D6 aggregate cap, evaluated per path).

## 5. Built vs. needed
**Already in place** (Cardano⇄CKB reference impl): the binding construction; two working oracles
(Mithril→CKB, Groth16-of-CKB-consensus→Cardano); single-use seal + nullifier; the light-client checkpoint
pattern; and — newly — **per-chain K + aggregate cap** with a governance policy cell (the
finality-normalization primitive). **Multi-chain adds:** (1) declare the canonical proof ABI + `chain_id`;
(2) turn the policy cell into a **per-source-chain finality registry**; (3) **one new prover + verifier per
chain** (the only genuinely new engineering — each consensus is its own circuit/verifier); (4) re-rooting +
per-path cap logic for hops.

## 6. Bottom line
The multi-chain refinement is mostly **generalizing primitives D6 already introduced** (finality K, value
cap, governance registry, the seal-follows-the-strong-chain rule) — not inventing new ones. The one piece
that's genuinely new work is the **prover-per-chain**, and the one piece that's a genuine *limit* to state
honestly is **multiplicative finality on multi-hop paths**. That a major new requirement (multi-chain)
turns out to reuse the reorg primitives is the strongest signal the D6 work was the right next step.
