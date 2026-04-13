# PLONK-in-Plutus budget — spike verdict (S1 / D-2)

Does a transparent-setup **PLONK/KZG** verifier fit a Cardano tx budget, so the forward leg can use a
*universal, reusable* SRS (CEREMONY.md) instead of a per-circuit Groth16 ceremony? Per-tx budget (Plutus
v3 mainnet): **cpu 10e9 steps, mem 14e6**.

## Measured anchor (this repo's Groth16 verifier, via `aiken check` ExUnits)
The on-chain Groth16 verify (`lib/g16/verifier.ak` = 4 Miller loops + 1 final_verify + an `(n+1)`-term
G1 MSM, over BLS12-381 builtins):

| public inputs | cpu-steps | % of budget | mem |
|---|---|---|---|
| 1 (ceremony key proof) | 2,005,861,618 | 20.1% | 36,357 |
| 3 (leap / finalize / relayer) | **2,271,870,552** | **22.7%** | 54,041 |
| 4 (advance) | 2,404,861,717 | 24.0% | 62,883 |

From the deltas: **~133 M cpu per public input** (one G1 scalar-mul + add + uncompress) and a **~1.87 G
pairing base** (4 ML + final_verify + the fixed point uncompressions). So in Plutus the *pairing* part
dominates and the MSM is ~133 M/term.

## PLONK/KZG verify — op count vs Groth16
A standard single-proof PLONK/KZG verifier (gnark/Aztec style):
- **Pairing:** the batched KZG opening is **2 Miller loops + 1 final_verify** (vs Groth16's 4 ML + 1 fv) —
  *cheaper* on the pairing side by ~2 Miller loops.
- **G1 MSM:** compute the linearization/folded commitment and the batch — ~**12–18 G1 scalar-muls** + adds
  over the wire/permutation/quotient/selector commitments (vs Groth16's ~3). This is the cost driver.
- **Fiat–Shamir:** ~5–6 transcript hashes (blake2b) — negligible (~few M).
- **Field arithmetic:** vanishing poly, L₁, public-input poly, quotient consistency — small in Plutus.

## Estimate
Anchoring on the measured numbers (pairing base ~1.87 G for 4 ML+fv ⇒ ~0.4 G per Miller loop; ~100–130 M
per G1 mul incl. its uncompress):
- PLONK pairing (2 ML + fv): drop ~2 ML from the base ⇒ ~**1.1 G**.
- PLONK MSM (~15 G1 mul + ~15 commitment uncompresses): ~**1.5–2.0 G**.
- hashing + field: ~**0.1 G**.
- **Total ≈ 2.7–3.2 G cpu ≈ 27–32 % of the tx budget** (mem stays tiny, ≪ 1 %).

## Verdict — FEASIBLE (confirms D-2)
A PLONK/KZG verifier is **~1.2–1.5× Groth16's 22.7 %**, landing around **~30 %** of a Cardano tx — well
within budget, leaving ~70 % for binding logic. So **PLONK-in-Plutus is viable**, and the universal-SRS
path (reuse/run one 2²¹ BLS12-381 Powers-of-Tau, no per-circuit ceremony — CEREMONY.md) is the right D-2
choice. Caveat: this is a grounded estimate from the measured Groth16 primitives + PLONK's known op count,
**not** a full implementation; building the actual `plonk_verifier.ak` and measuring it is the confirming
follow-up (the op count above is the spec to implement). The fallback if it overruns remains Groth16 + a
per-circuit Phase-2 ceremony.

## Gotcha for whoever builds `plonk_verifier.ak`
`aiken` v1.1.21 **silently ICEs (exits 1 with no diagnostic)** on a recursive function that threads an
opaque BLS type (`MillerLoopResult`, and apparently `G1Element` under an `if`-counter recursion) as an
accumulator. Single-shot / list-recursion (`verifier.ak::msm`) is fine. Micro-benchmark the pairing ops
with **fixed, unrolled** expressions, not counter-recursion, or the whole `aiken check` aborts without an
error message.
