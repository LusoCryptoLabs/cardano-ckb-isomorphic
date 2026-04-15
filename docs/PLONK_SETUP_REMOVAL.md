# Retiring the Groth16 trusted setup on the forward (CKB→Cardano) leg

> Scope + feasibility for the "trustless upgrade" half of the forward-leg roadmap. The genesis-pin half is
> done (`TESTNET_LOG.md §K`); this is the remaining, **multi-session** piece. Written to be honest about
> what is and isn't feasible on Plutus so we don't build the wrong thing.

## 1. The trust we want to remove

The forward leg verifies a **Groth16** proof of CKB consensus on Cardano (`groth16/lib/g16/verifier.ak`,
~22.7% of a tx). Groth16 needs a **circuit-specific trusted setup**: a structured reference string (SRS)
whose "toxic waste" (the secret τ, α, β…) must be destroyed. **Whoever knows the toxic waste for our
circuit can forge a proof for it** — i.e. mint bridged assets against a CKB lock that never happened. That
is the single trust assumption on this leg beyond CKB PoW honest-majority.

Current mitigation (already in-repo, not removal): `circuit/prover/src/bin/ceremony.rs` +
`lib/g16/ceremony_test.ak` — a **multi-party computation** (MPC) ceremony, phase-1 from a universal
Powers-of-Tau, circuit-specific phase-2 by independent parties. This reduces trust to **"≥1 of N
participants was honest and discarded their share."** Standard (Zcash/Filecoin/Semaphore use it), but it is
a liveness/coordination burden per circuit change, and "≥1 honest" is still an assumption.

## 2. What is NOT feasible: a STARK / FRI verifier on Plutus

A transparent (zero-setup) STARK verifier on-chain would remove all setup. **It does not fit Cardano's
budget.** FRI verification is thousands of hash evaluations (blake2b/keccak) + Merkle-path checks per query,
over many rounds; even a modest STARK is ≫ the ~10 B CPU / 14 M mem per-tx limit (the Groth16 verify, four
Miller loops + a final pairing, already uses ~2.3 B). Plutus has **no** cheap FRI-friendly primitive and no
native field arithmetic for the prime fields STARKs use. STARK belongs **off-chain** as a *recursion* layer
(`circuit/SPEC.md` §recursion: a fast Plonky2/binary-field STARK for the consensus circuit, **wrapped** in a
final pairing-based SNARK that Cardano verifies). That improves *proving time*, not *on-chain trust*.

## 3. The feasible path: a universal-SRS PLONK/KZG verifier over BLS12-381

PLONK (or Marlin/HyperPlonk) with **KZG** commitments over BLS12-381:
- **Verifier = a handful of pairings + G1/G2 MSMs** — the *same* class of operations the Groth16 verifier
  already does with Cardano's BLS12-381 builtins, so it is **in budget** (estimate below).
- **Universal + updatable SRS:** one Powers-of-Tau ceremony serves **all circuits up to a degree bound**,
  and is reusable from existing public ceremonies (Aztec Ignition, the Perpetual Powers of Tau, Ethereum's
  KZG ceremony). So we **drop the per-circuit phase-2** entirely — no new toxic waste when the consensus
  circuit changes; trust collapses to a *single, public, audited, already-performed* universal ceremony.

This is the honest meaning of "trustless upgrade" on Cardano today: **per-circuit setup → a public universal
SRS we don't run ourselves.** Fully transparent (no SRS at all) is not on-chain-affordable here.

## 4. Work breakdown (multi-session)

| # | item | size | notes |
|---|---|---|---|
| 1 | **PLONK verifier in Aiken** over BLS12-381 builtins | L | poly-commitment opening checks, permutation/quotient identity, Fiat–Shamir transcript (blake2b). Mirror `verifier.ak`'s pairing style. |
| 2 | **Budget-prove it fits** (`aiken check` exec units) | S | gate: must stay < a tx, like the 22.7% Groth16 number. KZG verify is a few pairings + MSM — expected to fit; **must be measured, not assumed.** |
| 3 | **PLONK prover for the consensus circuit** (the ~1.2 M-constraint R1→R4 + advance circuit) | L | port the arkworks gadgets to a Plonkish backend (halo2-KZG / `plonky3`-KZG / `gnark`-KZG-BLS12-381). Keep the differential tests vs native CKB. |
| 4 | **SRS sourcing + transcript domain separation** | M | pick a public PoT, document the powers used, fix the Fiat–Shamir transcript so a proof for circuit A can't be replayed for B. |
| 5 | **Swap-in:** new `vk` param + redeploy `cardano_bound` / `advance_ckbcert` / `zk_chiral_mint` | M | the binding/pin logic is unchanged — only the proof system behind `verify(...)` changes. |

Interfaces that **don't** change: the binding construction, the genesis pin (§K), the public-input layout
`(checkpoint_root, seal, commitment)` / `(old_root, old_diff, new_root, new_diff)`. Only `verify` and the
prover are replaced — the rest of the leg is proof-system-agnostic.

## 5. Recommendation / order

1. **Now (done):** genesis pin (§K) — removes a concrete soundness gap independent of the proof system.
2. **Next prove-out (1 session):** item #1+#2 — a minimal PLONK/KZG verifier in Aiken with a hand-made
   proof, **measured** against the tx budget. This is the keystone that de-risks the whole upgrade exactly
   as the Groth16 measurement de-risked the leg originally. If it fits, the rest is prover engineering.
3. **Then:** items #3–#5 — the circuit port + SRS + swap-in.
4. **Interim trust statement (today):** the leg runs on Groth16 with the in-repo MPC ceremony, so the live
   trust is "≥1 honest ceremony participant + CKB PoW honest-majority." The PLONK upgrade reduces the first
   clause to "a public universal SRS." Document this plainly in `CHIRAL_READINESS.md` until the swap lands.

## 6. Why this is the right altitude

The on-chain cost asymmetry (Plutus ≪ CKB-VM) is *the* constraint of this leg. It forced Groth16 (cheapest
verifier) first; it equally rules out STARK-on-chain. A universal-SRS KZG SNARK is the only known point that
is **both** affordable on Plutus **and** free of per-circuit toxic waste. So the roadmap's "universal-SRS
Plonk verifier" line (`CKB_TO_CARDANO.md §5/§7`, `circuit/SPEC.md`) is the correct target, and "STARK
verifier to drop the trusted setup" is only achievable off-chain as a recursion wrapper — which doesn't
change the on-chain trust and so isn't the lever here.
