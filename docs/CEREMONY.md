# Trusted setup — how to actually run it

How the production setup gets done, for the chosen path (universal-SRS PLONK) and the Groth16 fallback.
Tied to `PRODUCTION_PLAN.md` D-2 and the circuit sizing (`spike/ckb-to-cardano/circuit/CIRCUIT_SIZING.md`,
`RESTRUCTURE.md`). **The whole point of a ceremony: the secret "toxic waste" is unrecoverable unless
*every* contributor colludes — so ≥1 honest contributor who destroys their entropy ⇒ secure.**

## The size that drives everything
- Forward-leg circuit: **~2²³ today**, **~2²¹ after the windowed-membership restructure** (signed off).
- So target an SRS of degree **2²¹** (≈ 2.1 M). This is the single biggest lever: 2²¹ is 4× smaller than
  2²³ and is the largest tier where an existing public BLS12-381 SRS plausibly exists to *reuse*.

## Chosen path — universal-SRS PLONK (run ONCE, reuse forever)
PLONK needs only a **universal SRS** (a Powers-of-Tau / Phase-1). There is **no per-circuit Phase-2**, and
circuit revisions need **no re-ceremony** (as long as degree ≤ the SRS). Two steps:

**Step 1 — try to REUSE an existing public BLS12-381 Powers-of-Tau (no ceremony to run).**
- Requirement: a published BLS12-381 PoT of degree ≥ 2²¹ with a credible transcript and many independent
  contributors. Candidates to vet: existing BLS12-381 PoT efforts (the Ethereum KZG ceremony is
  BLS12-381 but only 2¹²–2¹⁵ — too small; a ~2²¹ BLS12-381 PoT has been reported — **validate its
  provenance, contributor count, and that the powers are in the form PLONK/KZG needs**).
- If a credible 2²¹ BLS12-381 SRS exists → adopt it, publish the hash we pin, done. **No ceremony to run.**

**Step 2 — if none qualifies, run our own universal PoT (one-time, then reusable).**
- Tooling (BLS12-381, arkworks-native to match this repo's stack):
  - **Jellyfish** (Espresso) — a BLS12-381 KZG-PLONK with universal SRS + ceremony tooling; verifier maps
    cleanly onto Cardano's BLS12-381 builtins. Primary candidate for the verifier *and* the SRS format.
  - **arkworks** `ark-poly-commit` KZG / the repo's existing `ceremony.rs` contribution+PoK machinery,
    adapted from per-circuit delta to the Phase-1 tau powers.
  - (snarkjs is the most battle-tested ceremony tool but is BN254-centric; not ideal for BLS12-381.)
- Run it: a coordinator publishes initial params; each contributor, **on a fresh/airgapped machine**,
  draws entropy from the OS CSPRNG, applies their contribution, emits a **publicly-verifiable** update +
  a **PoK of the secret** (the `ceremony.rs` Schnorr/Fiat-Shamir pattern — rogue-resistant), then
  **destroys the secret**. The more independent contributors the stronger (open it to the public — a PoT
  is monotone: one honest party suffices). Coordinator verifies the whole chain and publishes the
  transcript + final SRS.

## Fallback — Groth16 per-circuit Phase-2 (only if PLONK busts the Plutus budget, see S1)
Groth16 needs **both**: (1) the same universal Phase-1 PoT above, **and** (2) a **circuit-specific
Phase-2** that must be **re-run on every circuit change**. The Phase-2 machinery already exists in
`spike/ckb-to-cardano/circuit/prover/src/bin/ceremony.rs` (verifiable delta re-randomization + Schnorr PoK
+ rogue rejection), demonstrated single-process on a toy circuit — productionizing it = run the *same*
`contribute()`/`verify_contribution()` over the **frozen** `leap_prove`/`advance` proving keys, with ≥3
independent contributors on separate offline machines, publishing each verifiable contribution. Tooling
alt: snarkjs `zkey contribute` (if porting the circuit to its format).

## Operational checklist (either path)
1. **Freeze the circuit first** (restructure + D2-A + D5), so the SRS/keys bind a final statement.
2. Decide reuse-vs-run for Phase-1 (vet candidate BLS12-381 SRS at 2²¹).
3. Recruit contributors: ≥3 *independent* people/orgs minimum; for a universal PoT, open it widely.
   Each uses a fresh machine, fresh OS entropy, destroys the secret, signs + publishes their attestation.
4. Every contribution is publicly verifiable (no secrets revealed) — publish the full transcript so anyone
   can re-verify the chain and confirm their own contribution is included.
5. Pin the final SRS/vk hash on-chain (the verifier already takes the vk as a compile-time param — B1).
6. (Groth16 only) re-run Phase-2 on any later circuit change. (PLONK: no action unless degree grows.)

## Bottom line
Adopt PLONK + the restructure → the setup becomes a **single universal 2²¹ BLS12-381 PoT**, ideally a
*reused* public one (zero ceremony to run) and otherwise a one-time open ceremony that never needs
repeating. That is the most trust-minimized, lowest-coordination path, and the restructure is what makes
2²¹ — and therefore reuse — feasible.
