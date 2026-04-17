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

---

# Part II — Grounded evaluation (5 candidate chains)

Pressure-test of the requirements against real chains (parallel per-chain assessment + synthesis). Three
constraints surfaced here that the conceptual half (Parts 0–6) missed: **K needs a unit**, the **BN254 vs
BLS12-381 curve split** is a real wiring constraint, and **path conservation must be baked into the ABI**.

## 7. Capability matrix

| Chain | Finality type | K (as source) | Single-use | Follows? | Verifies via | Fit |
|---|---|---|---|---|---|---|
| **Bitcoin** | PoW cumulative-work (probabilistic) | tiered by value: ~6 small / 36–100+ mid / hundreds high | **native UTXO** (cleanest seal) | **no** | cannot (no pairing, no `OP_CAT`) | **good-source, one-way** (anchor/source/sink) |
| **Ethereum L1** | PoS Casper-FFG **finalized checkpoint** | **2 epochs** (~12.8 min), *not* block-depth | emulated nullifier | yes | **native** (BN254 + BLS12-381 precompiles) | strong, both roles |
| **Solana** | BFT (Tower → Alpenglow cert) | 32 slots (~12.8 s) now → **1 cert** post-Alpenglow (~Q3'26) | emulated nullifier (PDA) | yes | **SNARK-compressed** (BN254 syscalls, 1.4M CU) | strong, both roles |
| **Cosmos/CometBFT (Osmosis)** | BFT-quorum (instant, accountable) | **K=1** (commit is final), buffer 2–3 | emulated nullifier (CosmWasm) | yes | **native** (ed25519/secp256k1/**BLS12-381**; *no BN254*) | strong both, **low cap** |
| **ZK-rollup (Starknet/zkSync)** | validity-proof, **inherited from Ethereum** | ACCEPTED_ON_L1 + ETH-finalized (~3 h) | emulated nullifier | yes | native (Garaga / EIP-197) | strong follower, **transitive source** |

Driving asymmetries: only **Bitcoin** has a native seal and only Bitcoin **cannot follow**. ETH/Osmosis/
rollup verify **natively**; Solana and CKB/Plutus-class followers need **SNARK-compressed** proofs. The
rollup has **no independent finality** — its source-oracle is transitively an Ethereum oracle.

## 8. Canonical proof ABI (makes onboarding O(1), not O(N²))
Every source-oracle emits the **same** public-input vector + envelope; a follower verifies any source with
one verifier shape parameterized by `chain_id`. The fixed field order **is** the interface.

```
ChiralSealProof.publicInputs = [
  chain_id,      # uint64  source-chain domain separator (binds proof to ONE source)
  window_root,   # bytes32 root of the source finality window (PoW header-chain | finalized-checkpoint |
                 #         cert-set | AppHash | L1-verified-batch root)
  seal,          # bytes32 canonical seal id. native: H(txid||vout); emulated: nullifier key
  commitment,    # bytes32 = H(amount || target_chain_id || origin_chain_id || min_finality || shadow || salt)
  tip,           # bytes32 source head the K-depth is measured against
  K,             # uint32  confirmation depth/threshold ACTUALLY satisfied by this proof
  finality_tag   # uint8   0=PROBABILISTIC_DEPTH 1=PoS_FINALIZED 2=BFT_CERT 3=BFT_COMMIT 4=L1_SETTLED
]
```

Follower rules (constant across chains): `chain_id` ∈ registry; `commitment.target_chain_id ==` self;
`K_proven >= registry.K[chain_id]` AND `finality_tag == registry.finality_type[chain_id]`;
`running_value[origin] + amount <= registry.cap[origin]`; `seal` unspent in the local shadow nullifier set,
marked spent atomically. **Envelope** (relayer-interchangeable): `{curve∈{BN254,BLS12_381}, scheme∈{GROTH16,
PLONK}, vk_id, public_inputs, proof}`. Native-verifier followers MAY skip the SNARK and check the raw
finality artifact, but still populate the same vector so policy is identical.

## 9. Finality registry (generalizes the D6 policy cell)
One governance-set row per source chain, on each follower:

```
FinalityPolicy = {
  chain_id, finality_type∈{POW_CUMULATIVE,POS_FINALIZED,BFT_CERT,BFT_COMMIT,VALIDITY_L1},
  K, K_unit∈{BLOCKS,SLOTS,EPOCHS,CERTS,COMMITS},   # 6 BTC blocks ≠ 2 ETH epochs ≠ 1 BFT cert
  cap, cap_denom∈{USD,NATIVE},                      # sized to reorg cost (re-mine / slashable stake)
  vk_id, curve, validator_set_ref, enabled         # validator_set_ref tracks PoS/BFT set rotation; enabled = kill switch
}
```

Seed values: BTC `POW_CUMULATIVE / tiered BLOCKS / cap tiered by K`; ETH `POS_FINALIZED / 2 EPOCHS / ~⅓ of
~34M staked ETH`; SOL `BFT_CERT / 32 SLOTS→1 CERT / ~⅓ slashable SOL`; Osmosis `BFT_COMMIT / 1 COMMIT(+2–3) /
~⅓ staked OSMO — **pin LOW, track drift**`; rollup `VALIDITY_L1 / ETH-finalized / sized to the ~0-cost
pre-finalization window`. The explicit `K_unit` + `finality_type` are what make this generalize — D6's bare
`K` silently meant different things per chain.

## 10. Onboarding checklist (build vs. reuse — the O(1) boundary)
**Always NEW per chain:** the source finality-proof generator (header-chain / finalized-checkpoint+sigs /
quorum cert / L1-settlement), the inclusion proof of `seal+commitment` against `window_root`, the SNARK
circuit *iff* a thin follower consumes it (target the follower's curve), and validator/stake-set tracking.
**REUSED after the first 2 chains:** the entire follower policy layer (§8 rules), the envelope decoder, the
registry schema, the shadow nullifier + aggregate-cap accumulator, and the governance path. Always:
domain-separate by `(chain_id, target_chain_id)` and test the **non-finalizing/halt** path — a follower must
treat "not final" as "not safe" *forever*, never time out into acceptance.

## 11. Recommended add-order
1. **Bitcoin (one-way).** Strongest finality + only native seal, least novel crypto (SPV header-chain
   oracle, SNARK'd for thin followers). Do **not** attempt Bitcoin-as-follower (no script for it).
2. **Ethereum (both roles).** Native verifier makes the canonical ABI pay off — build the follower policy
   layer here, reuse everywhere. Follower first (easy); source = SNARK the FFG validator set.
3. **Osmosis.** Fastest finality (K=1), but **pin the cap low** + a bespoke BLS12-381 batch-ed25519 source
   circuit. Generalizes to high-cap Cosmos chains.
4. **Solana.** Follower now; flip source `K=32 SLOTS → 1 CERT` via a registry update once Alpenglow ships.
5. **ZK-rollup (last).** Excellent follower; source is transitively an Ethereum oracle (~3 h) → depends on #2.

## 12. The cross-cutting risk — multiplicative finality / path conservation
**Laundering attack:** a seal that is only *Osmosis-final* (shallow, low cap) is shadowed to Ethereum, then
a third chain treats it as *Ethereum-final and Ethereum-capped* — upgrading weak finality into strong-looking
and breaching the aggregate cap. **Baked into the ABI (§8):** `commitment` carries the **origin** `chain_id`
and the **min finality reached so far** (not just the predecessor); the cap is enforced against the
**origin** source and `running_value` is conserved end-to-end (never reset per hop); re-shadowing can
**never upgrade** `finality_tag`/cap — a shadow is only ever **as strong as its weakest link**. The rollup
(inherited finality) and Osmosis (low cap) are where this bites first.
