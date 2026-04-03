# Forward-leg circuit sizing — measured (S1)

Hard R1CS constraint counts for the CKB-consensus leap circuit (`prover/src/bin/leap_prove.rs`),
synthesized with `ark-relations` `ConstraintSystem::num_constraints()`. Reproduce:

```
cd prover
COUNT_ONLY=1 cargo run --release --bin leap_prove                 # demo (2-merge MMR)
COUNT_ONLY=1 MMR_DEPTH=25 cargo run --release --bin leap_prove    # production-depth MMR
```

## Measured

| MMR membership path depth | constraints | next power of two (proving/SRS domain) |
|---|---|---|
| 2 (demo, 4-leaf toy chain) | 1,285,757 | 2²¹ |
| 16 | 3,462,183 | 2²² |
| **25 (≈ production, ~21.3 M-block chain)** | **4,861,314** | **2²³** |
| 30 | 5,638,609 | 2²³ |
| 34 | 6,260,445 | 2²³ |

- **Per-MMR-merge cost ≈ 155,459 constraints** (linear; `(6,260,445 − 1,285,757)/32`). Each merge is a
  `ckbhash` (blake2b-256) of ~240 bytes ≈ ~77 K constraints/blake2b-block.
- **MMR membership dominates**: at production depth it is ~75–80 % of the whole circuit. R1 (Eaglesong
  PoW + compact-target), R3 (tx-CBMT), R4 (seal/commitment) together are the remaining ~1.3 M.

## Conclusions

1. **The production forward-leg circuit is ~4.9–6.3 M constraints → a 2²³ proving domain** — *not* the
   "~2.7 M" the docs state, and far above the `leap_prove` demo's 1.29 M (the demo only proves a
   2-merge MMR; production proves membership against a ~25-deep real CKB header-MMR).
2. **Setup implication (S1 → D-2).** No public BLS12-381 universal SRS exists at 2²³ (Ethereum's KZG
   ceremony is 2¹²–2¹⁵; the largest public BLS12-381 PoT is ~2²¹ — 4× too small). So **both** Groth16
   and PLONK need a **custom 2²³ BLS12-381 universal Powers-of-Tau** regardless. PLONK's headline
   advantage ("ride a 95k-participant public ceremony") therefore **does not apply at this size**; its
   real remaining benefit is *reusability across circuit revisions* (no per-circuit Phase-2), which is
   still worth having. Net: PLONK stays the direction, but the setup is a custom ceremony either way.
3. **The bigger lever is circuit reduction, not the setup choice.** Because the per-leap circuit is
   MMR-dominated, the highest-impact production move is to **stop carrying the full MMR membership in
   the per-leap proof** and push that work into the *amortized* checkpoint-advance
   (`AdvanceCKBCert`, already incremental) and/or a recursion step (`spike/pq-recursion`). A per-leap
   circuit that proves membership against a *recent, small* checkpoint (or a recursively-folded one)
   could drop ~4–5×, back toward 2²⁰–2²¹ — which in turn shrinks the SRS tier *and* the prover RAM/time.
   This is worth more than Groth16-vs-PLONK and should be decided before the circuit freeze.

## S2 (D2-A per-outpoint membership) — affordable within the 2²³ budget
D2-A adds the full spend-tx bytes as witness, one blake2b over the tx (~3–5 blocks ≈ ~0.3–0.4 M
constraints), and a molecule parse + outpoint compare (cheap byte-selects). That is ≈ +0.4–0.5 M on a
~4.9–6.3 M circuit — it does **not** change the 2²³ tier (ceiling 8.4 M; production depth ≤ ~46 stays
in 2²³). So **per-outpoint membership is essentially free relative to the MMR cost and should be
adopted** as the rigorous seal model — *especially* if the circuit is restructured per conclusion 3,
since the MMR work moves out and leaves ample 2²³ headroom.

> On-chain verify cost is unaffected by any of this: a Groth16 proof is constant-size, so the measured
> ~22.7 % of a Cardano tx budget stands regardless of circuit size. What grows with size is the
> trusted-setup degree and the prover's key size / RAM / time — i.e. an ops and ceremony concern, not
> an on-chain one.
