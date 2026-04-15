# Keystone: a hash-only (post-quantum) FRI verifier fits CKB-VM's budget

The PQ analogue of "Groth16 fits Plutus at 22.7%". It establishes — from **measured CKB-VM primitives**, not
hand-waving — that a FRI/STARK verifier (hash-based, no pairings, no trusted setup ⇒ post-quantum
*verification*) runs in CKB-VM at a cost **on the same order as the BLS `cert-verify` it would replace**, and
at a small fraction of a CKB block. Plutus, by contrast, cannot host one (§4). See `docs/PQ_STRATEGY.md`.

## Measured primitives (ckb-debugger 0.119.0, `--mode full`, `riscv64imac`)

| workload | iters N | total cycles | per-op (− baseline) |
|---|---|---|---|
| `baseline` (empty loop) | 100,000 | 1,400,664 | ~14 /iter |
| `hash` — blake2b(64B→32B) | 100,000 | 585,403,421 | **~5,840 cycles / Merkle-node hash** |
| `fmul` — Goldilocks multiply | 1,000,000 | 482,845,101 | **~469 cycles / mul** (loose: uses generic `u128 %`; the fast Goldilocks reduction is ~20–30 cycles) |

Reproduce: `./build.sh` then `ckb-debugger --bin bin/bench_<feat>.bin --mode full` for `feat ∈ {baseline,hash,fmul}`.

Comparison baseline — the **current** reverse-leg verifier (BLS pairings + hashes, *not* PQ):
`cv_standalone` on a real Mithril cert = **164,611,181 cycles (157.0M)**.

## Cost model — a full FRI verify, from the measured primitives

Parameters for a STARK over the CKB-consensus circuit (~1.23 M constraints ⇒ trace ≈ 2²¹, LDE domain ≈ 2²³):
- `D = 23` (log₂ LDE domain), fold-by-2 ⇒ `R ≈ 22` FRI rounds.
- Merkle-node hashes per query ≈ FRI-layer cumulative depth `D(D+1)/2 ≈ 276` + batched trace/quotient
  openings `≈ 2·D = 46` ⇒ **≈ 322 blake2b / query**.
- Queries `Q` for ~100-bit soundness: `Q ≈ ⌈λ / log₂(blowup)⌉`. blowup 4 ⇒ `Q ≈ 50`; a conservative `Q = 80`.
- Field work: constraint-eval + folding ≈ a few hundred muls/query.

| | hashes | hash cycles (×5,840) | field cycles (opt → upper) | **total FRI verify** |
|---|---|---|---|---|
| Q = 50 | 16,100 | 94.0 M | 0.8 M → 12 M | **~95 – 106 M** |
| Q = 80 | 25,760 | 150.4 M | 1.2 M → 19 M | **~152 – 170 M** |

(+ a negligible Fiat–Shamir transcript: a few hundred hashes ≈ 1–2 M.)

## Verdict

- **Fits CKB-VM with large headroom.** ~95–170 M cycles is **~3–5 % of a ~3.5 × 10⁹-cycle CKB block**, and is
  **on the same order as — to slightly cheaper than — the BLS `cert-verify` it replaces (164.6 M).** So
  swapping the in-VM pairing verifier for a hash-only FRI verifier is roughly **cost-neutral** while making
  the *verification* post-quantum (no pairings, no trusted setup).
- **Conservative.** blake2b is CKB's native hash; blake3/blake2s Merkle, the fast Goldilocks reduction, and
  fold-by-4 (halving `R`) each cut the number further. SP1's *native* Poseidon2 trees would be **more**
  expensive in plain RISC-V, so a CKB-VM-targeted FRI should use a blake-family Merkle (Plonky3/Stwo both
  support this) — which is exactly what these numbers model.
- **Plutus cannot host this (§4 of PQ_STRATEGY).** A FRI verify needs 10⁴–10⁵ hashes + field emulation;
  against Cardano's ~10¹⁰-CPU-unit per-tx budget (one Groth16 verify already consumes 22.7 % of it), that is
  multiples of a full tx — so the on-chain PQ verifier belongs in CKB-VM, and Cardano's on-chain check stays
  the documented non-PQ "last mile."

## What this de-risks

The PQ-meaningful target (`PQ_STRATEGY §3`): a transparent **FRI** proof of CKB consensus removes the
forward leg's trusted setup **and** makes its off-chain soundness post-quantum in one move. This keystone
shows the *verifier* side is affordable wherever it can run in budget (CKB-VM today; Cardano only via the
pairing last-mile). Next: an SP1 guest = the CKB-consensus circuit, proven as a FRI STARK on a ≥32 GB / network
prover (the box here is 15 GB), then a CKB-VM-side blake-Merkle FRI verifier built to these measured costs.
