# CKB-consensus circuit — spec + cost (the off-chain prover for the CKB→Cardano leg)

> Branch `dev`. The on-chain half is proven cheap (a Groth16 verify ≈ 22.7% of a Cardano tx; see
> `../../RESULTS.txt`). This is the **prover** side: the zk statement attesting a CKB seal-spend, the
> consensus relations (validated on a **real Pudge block**), the sub-circuit inventory + constraint
> estimate, and the proving-system choice. Host reference: `ckb_consensus/` (run it — it recomputes a
> real header's hash + Eaglesong PoW from scratch).

## 1. The statement the SNARK proves

Public inputs (the three field elements the Cardano `cardano_bound.ak` validator binds):
`(ckb_checkpoint_root, seal, commitment)` — each a 32-byte value hashed into one BLS-scalar field element.

Private witness: a CKB header `H` (+ its MMR proof to the checkpoint), the spending tx `T` (+ its CBMT
proof to `H.transactions_root`), and the witness bytes of `T` carrying the commitment.

Relations (all **validated on real data** or standard):
- **R1 — PoW.** `H` has valid proof-of-work: `ckbhash(eaglesong(ckbhash(RawHeader(H)) ‖ nonce_le16))`,
  read **big-endian**, `≤ target_from_compact(H.compact_target)`. ✅ validated on block 21,340,780.
- **R2 — confirmation.** `H` is in the checkpointed header MMR (root = `ckb_checkpoint_root`), i.e. it
  has enough cumulative work behind it (FlyClient-style; the CKB header `extension` commits the chain
  MMR root). An MMR membership path of Blake2b merges.
- **R3 — inclusion.** `T`'s hash is under `H.transactions_root` via CKB's CBMT (Complete Binary Merkle
  Tree, merge = `ckbhash(l ‖ r)`); `transactions_root = ckbhash(raw_tx_root ‖ witnesses_root)`.
- **R4 — binding.** `T` **spends the seal cell** (`seal` ∈ `T.inputs`) and a witness/output of `T`
  carries `commitment` (covered by `T`'s hash, hence by R3). Mirror of the CKB BoundAsset §2.4.

If the proof verifies on Cardano, the bound UTxO transitions/finalizes — Cardano has verified CKB.

## 2. Consensus relations — validated on a real block (`ckb_consensus/`)

Block 21,340,780 (testnet.ckb.dev), recomputed from scratch with CKB's own reference crates:
- **Header hash** = `ckbhash(RawHeader_192 ‖ nonce_le16)` = `3dc9a017…` ✓ (so the molecule struct
  serialization + `ckbhash` = Blake2b-256 personalized `"ckb-default-hash"` are exact).
- **PoW** = `ckbhash(eaglesong(pow_hash ‖ nonce_le16))` = `00000004b0de…` ≤ target `00000083f14…` ✓.

`ckbhash` = Blake2b-256/`"ckb-default-hash"`. `target_from_compact` = the Bitcoin-style compact form.

## 3b. MEASURED constraint counts (gadgets built + tested — `prover/`)

The Eaglesong and Blake2b-256 gadgets are **built in `ark-r1cs-std` and differential-tested against
the native CKB references** (byte-for-byte, in-circuit). Real R1CS constraint counts (BLS12-381 Fr):

| primitive | measured constraints |
|---|---|
| Eaglesong permutation (1×) | ~232 K |
| **Eaglesong PoW** (48-byte message, 2 sponge blocks) | **464,192** |
| Blake2b-256 / `ckbhash` (per 128-byte block / compression) | **~48,820** |
| Blake2b-256 of 192 B (RawHeader, 2 blocks) | 103,040 |

Refined **full-circuit total** with measured costs (vs the ~9–12 M earlier *over*-estimate):
- R1 PoW = Eaglesong(48 B) 464 K + ckbhash(RawHeader 192 B) 103 K + ckbhash(eaglesong_out 32 B) 49 K ≈ **616 K**
- R2 header-MMR ≈ 25 merges × 49 K ≈ **1.22 M** · R3 tx-CBMT ≈ 15 merges × 49 K ≈ **0.73 M** · R4 ≈ **0.15 M**
- **≈ 2.7 M constraints per leap** (naive R1CS, no lookups) ⇒ Groth16 proving in **~tens of seconds**,
  modest RAM. Comfortably prover-tractable; lookups would cut it further but aren't needed for feasibility.

## 3. Sub-circuit inventory + constraint estimate (original estimate; superseded by 3b)

Eaglesong (from the reference): **43 rounds**, 512-bit state (16×u32); per round = a GF(2) bit-matrix
(~128 u32 XORs) + a rotation layer (16×2 rotations [free] + XORs) + injection (16 u32 modular **adds**,
the nonlinearity). So Eaglesong is XOR/rotate-heavy with ~16 modular-adds/round — *binary-friendly*.

| Component | count per leap | naive R1CS constraints | with 8-bit XOR/add lookups (PLONK/Halo2) |
|---|---|---|---|
| Eaglesong permutation | 1 | ~250 K | ~25–50 K |
| `ckbhash` (Blake2b-256) | ~4 (pow_hash 192 B, pow_output, + R4) | ~200 K each → ~0.8 M | ~20 K each → ~80 K |
| header-MMR path (R2) | ~25 Blake2b merges | ~5 M | ~0.5 M |
| tx CBMT path (R3) | ~15 Blake2b merges | ~3 M | ~0.3 M |
| seal/commitment binding (R4) | a few hashes + compares | ~0.2 M | ~30 K |
| **total** | | **~9–12 M constraints** | **~1 M constraints** |

The cost is dominated by the **Merkle/Blake2b** work, not Eaglesong; both are non-arithmetic-friendly
hashes, so **lookup-based** systems win big. (No constraint here exceeds standard zk-hash practice —
SHA-256/Blake2 circuits are routine.)

## 4. Proving system + cost + verdict

- **On-chain constraint:** the verifier must be **pairing-based over BLS12-381** (Cardano's builtins) —
  so **Groth16** (measured: ~22.7% of a tx) or a **Plonk/KZG** verifier on BLS12-381. Groth16 needs a
  **circuit-specific trusted setup**; a universal-SRS Plonk avoids per-circuit ceremony at a modestly
  higher on-chain cost (still within budget given our 77% headroom).
- **Proving:** ~1–12 M constraints ⇒ **seconds (lookup-based) to a few minutes (naive Groth16)** on a
  server, a few GB RAM. Borne by the **permissionless relayer/prover**, amortized via the checkpoint
  (one `AdvanceCKBCert` per batch, like our Mithril AdvanceCert). **Liveness only — cannot forge.**
- **Recursion option:** a fast STARK (Plonky2/binary-field) for the consensus circuit, wrapped in a
  small Groth16-over-BLS12-381 for the on-chain verify — best proving time, constant on-chain cost.

**Verdict: feasible, prover-bound.** The hard on-chain question is already answered (the SNARK verify
fits Cardano). The circuit is a substantial but *standard* zk-hash engineering effort (Eaglesong +
Blake2b + Merkle), with no exotic constraint. Nothing here changes the feasibility — it sizes the build.

## 5. Build plan for the full circuit
1. Pick the stack: **Halo2/KZG-BLS12-381** or **Plonky2 → Groth16-BLS12-381 wrap** (best proving time).
2. Gadgets: Blake2b-256 (reused for `ckbhash`, MMR, CBMT) → Eaglesong (port the validated reference) →
   compact-target compare → MMR-membership → CBMT-membership → the R4 seal/commitment binding.
3. Wire public inputs `(checkpoint_root, seal, commitment)` to match `cardano_bound.ak`'s `inputs_bind`.
4. `AdvanceCKBCert`: a Cardano checkpoint UTxO advanced by a proof of CKB header-MMR growth (amortizes R2).
5. End-to-end on testnets, mirroring the live preview↔Pudge runs of the Cardano-anchored leg.
