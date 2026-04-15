# Post-quantum bridge — product roadmap (both paths, phased)

Goal: a deployable post-quantum CKB-side verifier **now**, growing into a fully trustless post-quantum
light-client **later**, with no rework in between. The two paths are not an either/or — they **share the same
verifier** (`spike/pq-fri-verify`); they differ only in *what statement* it is asked to check. So we ship the
cheap statement first and swap in the heavy one when its prover and (optionally) recursion are ready.

This doc is the sequencing plan. Status of the underlying crypto is in `PQ_STATUS.md`; soundness in
`SECURITY.md`; integration in `INTEGRATION.md`; recursion in `pq-recursion/RECURSION.md`; the Cardano-side
verdict in `PLUTUS_PQ_COST.md`.

## The shared core (done — Phase 0)

A hash-only (post-quantum) FRI/STARK verifier that runs **in CKB-VM**, **integrated as the checkpoint
acceptance rule**, **statement-bound**, **production-scale (n=2²², 333 M cyc, fits 4 MB)**. Both product paths
plug their statement into this. Built, measured, adversarially tested. *Not yet: audited, deployed.*

## Path B — committee / certificate (ship first)

The bridge already authenticates the counterparty chain with a stake certificate (Mithril BLS today). Make
that certificate **post-quantum** and verify it with the Phase-0 verifier.

- **Statement checked on-chain:** "a quorum of the counterparty's validators attested checkpoint X" — a
  hash-based certificate (e.g. a STARK over a hash-based multisig, or a hash-based aggregate signature).
- **Cost:** light — the verifier at ~50–170 M cycles (≈1.5–5 % of a block). **No SP1, no recursion.**
- **Trust model:** committee honest-majority (same as the current bridge) — *not* trustless, but a strict
  upgrade: removes the BLS/pairing dependency, which is the only post-quantum-relevant change here.
- **What it needs to ship:** (1) choose the PQ certificate scheme; (2) wire the validator set / quorum rule
  into the checkpoint script (the `checkpoint_consensus` logic already does heaviest-chain + epoch + binding);
  (3) **audit**; (4) **testnet → mainnet** deployment (genesis one-shot, thread-token lifecycle, fees).
- **Timeline driver:** audit + deployment. No research, no special hardware.

## Path A — trustless light-client (the end state)

Replace the committee with a **proof of the counterparty's actual consensus** (PoW chain / heaviest-work),
so no trusted validator set is needed.

- **Statement checked on-chain:** "a valid consensus chain links the old checkpoint to the new one with this
  cumulative work" — proven by a zkVM (SP1, `spike/sp1-ckb`) + the difficulty AIR (`consensus.rs`).
- **What it needs:** 
  1. **Faithful consensus circuit** — *done*: real **Eaglesong** PoW, CKB **compact-target** difficulty,
     **U256** work, and a real **MMR `chain_root`** are implemented; a real-Eaglesong proof was generated +
     verified (`sp1-ckb`, 16 blocks, 109 s / 11.9 GB), and its public outputs are wired into the checkpoint
     advance (`sp1-ckb` → `checkpoint`).
  2. **Production proving** — the SP1 compressed prover needs a **≥32–64 GB** box (OOM'd at 15 GB here);
     Eaglesong is ~60 K cyc/block, so this box now core-proves ~16–24 blocks.
  3. **On-chain verification** — either:
     - **A1 (works now, no recursion):** verify the SP1 proof natively at **~2.3 G cycles (~65 % of a block)**
       — functional but heavy / low-throughput. Good enough if checkpoints advance infrequently.
     - **A2 (optimized):** **recursion** — compress to a ~300 M outer verify (~7–8×). See below.
- **Trust model:** trustless (only the hash + the source chain's PoW).

## Recursion (Phase A2 — cost optimization, not a gate)

Designed, primitive measured (`pq-recursion/RECURSION.md`: Poseidon2-Goldilocks at 18,420 cyc/perm). Turns
Path-A's 2.3 G native verify into a constant-size ~300 M outer-STARK verify. **Needed only if** Path A is
chosen *and* its ~65 %-of-a-block cost is too high. Remaining build: a general AIR framework +
Poseidon2/FRI-verifier-as-constraints (an `sp1-recursion`-class effort). No research risk; substantial
engineering.

## Sequencing — how to get both without rework

```
Phase 0  [DONE]      shared PQ verifier in CKB-VM, checkpoint-integrated, measured
Phase 1  Path B      PQ certificate scheme + validator/quorum wiring   ─┐ ship a PQ bridge
         (ship)      audit → testnet → mainnet                          │ on the committee model
Phase 2  Path A core faithful Eaglesong/MMR circuit; SP1 prover on a    │
         (trustless) ≥32–64 GB box; verify natively (A1, ~2.3 G)        │ swap the *statement*;
                     → bridge becomes trustless, same verifier/script   │ verifier & script reused
Phase 3  Path A2     build the recursion AIR → ~300 M verify (~8×)      ─┘ optimize cost when needed
```

Because the checkpoint script gates on a *statement-bound proof*, moving from Path B → A → A2 swaps **what is
proven**, not the verifier or the on-chain machinery. No phase invalidates an earlier one.

## What "both paths shipped" still does NOT give you (unchanged, honest)

Even with Path A2 live, the **bridge is not end-to-end quantum-resistant**, because security also roots in
links no bridge can change:

- **The Cardano leg's verifier** can't host a hash-**STARK** in Plutus (~2–14× over the tx budget,
  `PLUTUS_PQ_COST.md`) — the *trustless* Cardano leg needs **PQ-friendly Plutus builtins** or tx-chaining.
  **But under Path B (certificate model) the Cardano leg CAN be post-quantum:** a hash-based **signature**
  (WOTS+/XMSS) verifies in a Plutus tx — measured ~28 % cpu / ~66 % mem (`PQ_CARDANO.md`). Swapping Mithril's
  BLS for a hash-based cert makes **both legs post-quantum under the committee model** (large multi-signer
  quorums still need signature aggregation or tx-splitting).
- **The anchor signatures** — Cardano Ed25519/KES + Mithril BLS, CKB secp256k1 — are classical. End-to-end PQ
  needs **Cardano and CKB themselves to adopt PQ signatures**.

These are protocol-level, above the bridge. The roadmap above makes **the CKB-side verifier and the
bridge's checkpoint logic** post-quantum, on both trust models; closing the chains' own crypto is a
dependency on the L1s, to be tracked but not owned here.

## Recommended order

1. **Now:** Phase 1 (Path B) — fastest path to a *shipped* PQ-relevant upgrade; the heavy lift is audit +
   deployment, both required for any path anyway.
2. **In parallel:** Phase 2 prerequisites that aren't blocked — the **faithful consensus circuit** (codeable
   now) and provisioning a **≥32–64 GB prover**.
3. **When Path A is live and cost matters:** Phase 3 recursion.
