# CKB → Cardano: the mirror leg

> The *other* direction — a **CKB-anchored** isomorphic binding where Cardano follows CKB.
>
> **Status (2026-06): BUILT AND PROVEN END-TO-END (this is no longer just a design note).** The
> on-chain half (a Groth16 verifier in Plutus) and the off-chain half (a full CKB-consensus circuit
> + prover + relayer) both exist; a real Groth16 proof of CKB consensus was **accepted on-chain by
> Cardano** (verify tx `f99c3461`, cpu 2.73B) and the full lock→verify→mint→burn→unlock round trip
> ran live (`spike/ckb-to-cardano/LEAP.md`). The original design/cost analysis is preserved below;
> §5b records the achieved status. The Cardano-anchored leg (Mithril oracle) is the other one we
> built and ran live (see `BINDING_SPEC`, `LEAP_FLOWS`, `deployed/`).

## 0. The key idea: both legs are the SAME binding; only the ORACLE differs

Isomorphic binding is symmetric *as a construction*: ownership = a **single-use seal** on the anchor
chain; state = a **cell/UTxO** on the other chain; the other chain only transitions if it can prove,
via an **oracle**, that the seal moved in the authorized way. RGB++ does this with Bitcoin as anchor;
we did it with Cardano as anchor. The *only* thing that's direction-specific is the oracle —
`cardano_tx_is_certified(tx)` on the CKB side. So:

| | anchor (ownership = seal) | follower (state = cell) | oracle the follower runs |
|---|---|---|---|
| **Cardano-anchored (BUILT)** | Cardano UTxO under binding lock | CKB bound cell | **Mithril** stake-BLS cert + MKMapProof, in CKB-VM |
| **CKB-anchored (this note)** | CKB cell (single-use by construction) | Cardano UTxO under a Plutus binding lock | **a CKB consensus proof**, in Plutus |

> So "one side isomorphic binding and the other?" → **the other is also isomorphic binding.** You
> don't change the binding; you swap the Mithril oracle for a **CKB-light-client / ZK oracle**.

## 1. Why this direction is the hard one

Cardano had a gift: **Mithril** — a succinct, signature-based attestation of settled Cardano history
that's cheap to verify (aggregate BLS + a Merkle proof) inside CKB-VM's ~3.5e9-cycle budget.

CKB has **no Mithril**. Its light-client story is consensus-native: **Eaglesong PoW** + a **header
MMR** (each CKB header commits to an MMR of all prior headers) + FlyClient-style sampling for
cumulative-work. To let Cardano follow CKB, Cardano must verify *that* — and Plutus's per-script
budget (~10M CPU / ~14M mem units) is **two-to-three orders of magnitude smaller** than CKB-VM's.
That budget gap, not any conceptual asymmetry, is why we anchored on Cardano first.

## 2. What the CKB→Cardano oracle must prove

`ckb_cell_is_confirmed(seal_spend)` — established on Cardano, it must attest:
1. **PoW validity:** a CKB header `H` has a valid Eaglesong solution meeting target.
2. **Cumulative work / depth:** `H` sits under enough confirmed work (FlyClient sampling against the
   header MMR root, or a fixed confirmation depth) — the analogue of Mithril's "settled/immutable".
3. **Inclusion:** the CKB **seal cell** was *spent* in a tx included in `H` (CKB cell/tx Merkle proof
   into the header), and that spend **committed** `blake2b/keccak(next_Cardano_state)` (the symmetric
   commitment — placed in a CKB witness/cell-data covered by the tx hash).

Same five invariants as BINDING_SPEC §5, mirror-imaged. The hard part is items 1–2 *in Plutus*.

## 3. Two implementation paths

### (a) Native light client in Plutus — likely infeasible today
Implement Eaglesong in PlutusTx + verify the header-MMR proof + sample for cumulative work. Plutus
has builtins for sha256/blake2b/keccak but **not Eaglesong**, so the PoW hash is hand-rolled
PlutusTx — expensive, and you need it for every sampled header. Verifying even a handful of Eaglesong
evaluations + MMR paths blows the script budget. Verdict: research-grade, not practical now.

### (b) ZK proof of CKB consensus, verified on Cardano — the realistic path  ✅ KEYSTONE MEASURED
A **succinct proof** (Groth16 / PLONK) attests off-chain that items 1–3 hold; Cardano verifies a
**single constant-size SNARK** on-chain. Cardano gained **BLS12-381 builtins** (G1/G2 add + scalar
mul, `millerLoop` + `finalVerify`, hash-to-curve) in the Chang/Plomin era. A Groth16 verify is
4 Miller loops + a final_verify + a small public-input MSM.

**Built + measured** (`spike/ckb-to-cardano/`): a real arkworks Groth16 proof over BLS12-381 (3 public
inputs), re-encoded to CIP-0381 compressed points, verified by a Groth16 verifier **in Aiken**:

| | measured | Cardano per-tx limit | % |
|---|---|---|---|
| CPU steps | 2,266,909,180 | 10,000,000,000 | **22.7%** |
| Mem | 37,379 | 14,000,000 | **0.27%** |

It **fits with ~77% CPU headroom** for the binding logic, and rejects a tampered public input. So the
on-chain half of this leg is **de-risked** — exactly as Mithril-in-CKB-VM (~5% of a block) de-risked
the other leg. The `cardano_bound.ak` validator wires this verify into the CKB-anchored binding lock.
The remaining work is the **prover** (the consensus circuit, §3 item 1–3), proven off-chain.
- **Circuit (off-chain, the heavy part):** Eaglesong PoW check(s) + header-MMR membership + the
  cell/tx inclusion proof + the commitment binding. Proven once per CKB checkpoint advance (amortized,
  like our AdvanceCert) and/or per leap. This is a real zk-light-client circuit (cf. zkBridge /
  Telepathy-style proofs of consensus). **Scoped + the consensus relations validated on a real Pudge
  block** in `spike/ckb-to-cardano/circuit/` (`SPEC.md` + `ckb_consensus/`): PoW =
  `ckbhash(eaglesong(pow_hash‖nonce)) ≤ target` and the header hash both recompute from scratch.
  Estimate: ~1–12 M constraints (Merkle/Blake2b-dominated, not Eaglesong) ⇒ seconds–minutes proving;
  feasible, prover-bound.
- **On-chain (cheap):** the Plutus binding lock requires a valid SNARK whose public inputs are
  `(ckb_header_root_checkpoint, seal_outpoint, commitment)`; it verifies the proof and that the
  commitment binds the new Cardano state. Mirror of our CKB `BoundAsset`.

## 4. The construction (mirror of what we built)

```
CKB (anchor):     a SEAL cell (unique, single-use — CKB cells are consumed once). Spending it = the
                  move; the spend tx carries commitment = H(next Cardano state) in a witness.
Cardano (follower): a bound UTxO at a Plutus binding lock. It transitions only on a SNARK proving the
                  CKB seal was spent in a confirmed CKB block with that commitment.
checkpoint:       a Cardano-side "CKB light-client checkpoint" UTxO holding the latest proven CKB
                  header-MMR root, advanced by a periodic AdvanceCKBCert proof (amortized).
relayer:          permissionless; watches CKB seal spends, generates the SNARK, submits to Cardano.
                  Liveness only — cannot forge (Plutus re-verifies the proof).
```

Leap-in/transfer/leap-out are the exact mirror of LEAP_FLOWS, with Cardano and CKB swapped.

## 5. Trust, latency, cost

- **Trust:** CKB PoW honest-majority + the SNARK's soundness (a trusted setup for Groth16, or a
  transparent PLONK). No committee — symmetric to the Mithril-honest-stake assumption we use today.
- **Latency:** the proven CKB checkpoint trails the CKB tip by the confirmation depth + proving time
  — settlement-style, same shape as our Mithril gap.
- **Cost:** on-chain = one Groth16 verify per leap (within Plutus budget); off-chain = SNARK proving
  (seconds–minutes, the real expense, borne by the relayer/prover and amortized via the checkpoint).

## 5b. Status — the leg is de-risked AND proven end-to-end (`spike/ckb-to-cardano/`)
- ✅ On-chain Groth16 verifier in Aiken — **measured ~22.7% of a Cardano tx** (`groth16/`).
- ✅ CKB-anchored binding lock `cardano_bound.ak` (compiles).
- ✅ Consensus relations validated on a **real Pudge block** (`circuit/ckb_consensus/`).
- ✅ Proving stack chosen: **arkworks Groth16 / BLS12-381 + ark-r1cs-std** (proof drops straight into
  the Aiken verifier).
- ✅ **Gadgets built + differential-tested vs native, in-circuit**: Eaglesong (PoW 464,192 constraints),
  Blake2b-256/ckbhash (~48,820/block), Merkle membership (CBMT/MMR), target-≤ compare.
- ✅ **COMPLETE circuit statement, END-TO-END**: the assembled leap circuit on **real block 21,341,101**
  with **all four relations** — R1 PoW (in-circuit compact-target decode) + R2 ChainRootMMR
  (HeaderDigest) membership tying the proven header to the checkpoint + R3 the tx bound to the header's
  `transactions_root` via a **real CBMT path** + R4 commitment — produces a real Groth16 proof
  **accepted on-chain by the Aiken verifier** (`circuit/prover/leap_prove.rs`, `groth16/lib/g16/leap_test.ak`).
  Every gadget differential-tested vs native CKB on real data; ~tens-of-seconds proving.

- ✅ **AdvanceCKBCert — the checkpoint is TRUSTLESS** (`groth16/validators/advance_ckbcert.ak` +
  `circuit/prover/advance_prove.rs`). The checkpoint UTxO `{chain_root, total_difficulty}` is advanced
  only by a Groth16 proof that a new header extends the chain with **valid PoW + a verified difficulty**
  (`difficulty_verify`: `diff == ⌊(2²⁵⁶-1)/target⌋`, multiply-compare; tampering rejected) added to the
  cumulative work; the validator enforces **new_total > old_total** (Nakamoto heaviest-chain). Proven on
  **real header 21,341,102 extending tip 21,341,101** (parent link verified), accepted on-chain (~24% of a tx).

- ✅ **PROVEN MMR-append** (`mmr_gadget::merge_digest` + `advance_prove.rs`): the advance circuit now
  **computes `new_root` in-circuit** (full-carry merges of the old peaks + the appended leaf), with each
  merge summing `total_difficulty` via `add256` — so the new root *and* its embedded cumulative work are
  proven, not witnessed. Proven on **real header 21,341,104 appended to the MMR over 21,341,101–103**,
  accepted on-chain. The last in-circuit gap is closed.

The in-circuit statement (R1–R4) **and** the trustless checkpoint advance (PoW + difficulty + MMR-append)
are **complete and on-chain-verified, with nothing assumed about the new root**. The remainder is
**ops, not feasibility**: a variable-carry append (general `leaf_count` via witnessed carry bits) +
batching N headers per advance + the trusted-setup ceremony (or a universal-SRS Plonk verifier). See
`circuit/prover/RESULTS.txt`.

- ✅ **GENESIS PIN — the checkpoint lineage is anchored to ONE canonical CKB genesis** (mirror of the
  reverse-leg §I.1 pin). `advance_ckbcert.ak` enforced heaviest-chain but not a genesis; an attacker could
  seed a parallel checkpoint with a fake genesis. Closed with a one-shot **thread token**
  (`validators/ckbcert_thread.ak`): mintable at most once (consumes a unique outpoint) and only onto an
  output at the checkpoint script carrying the **pinned** `Checkpoint` datum. `advance_ckbcert.ak` now
  requires that token on both the spent and the continuing checkpoint, so every advance is tied to the
  single pinned lineage. Adversarial battery `lib/g16/ckbcert_test.ak` **18/18** (fake-genesis / wrong-addr /
  non-unique / double-mint / lighter-reorg all rejected); both validators compile to UPLC. Relayer wiring +
  redeploy is the integration step. See `docs/TESTNET_LOG.md §K`; `docs/PLONK_SETUP_REMOVAL.md` scopes the
  trusted-setup removal.

## 6. The endgame: symmetric, both ZK

Today: Cardano-anchored leg uses **Mithril** (honest-stake oracle). The trust-minimized endgame for
*our* leg is to swap Mithril for a **ZK-of-Praos** proof behind the same `cardano_tx_is_certified`
interface. Do that **and** build this CKB→Cardano ZK leg, and you get a **fully bidirectional,
anchor-agnostic, committee-free bridge**: each chain verifies the other by a single SNARK, the binding
construction unchanged on both sides. Same isomorphic binding, two oracles, both succinct.

## 7. Build order — COMPLETED
All five steps were executed (`spike/ckb-to-cardano/`):
1. ✅ CKB seal-cell + Cardano binding lock (`cardano_bound.ak`) + commitment placement.
2. ✅ Groth16 verifier in Aiken over the BLS12-381 builtins (`groth16/lib/g16/verifier.ak`),
   measured ~22.7% of a tx; tampered inputs rejected.
3. ✅ Consensus circuit (Eaglesong + Blake2b + header-MMR + CBMT inclusion + compact-target),
   arkworks Groth16/BLS12-381, every gadget differential-tested vs native CKB.
4. ✅ `AdvanceCKBCert` trustless checkpoint (difficulty-verify + variable-carry MMR-append +
   N-batching) + a live prover/relayer.
5. ✅ End-to-end on testnets — lock→verify→mint→burn→unlock, explorer-visible (`LEAP.md`).

What remains is shared with the whole project: audit + mainnet + a universal-SRS (Plonk) verifier
to retire the Groth16 trusted setup. See `CHIRAL_READINESS.md`.
