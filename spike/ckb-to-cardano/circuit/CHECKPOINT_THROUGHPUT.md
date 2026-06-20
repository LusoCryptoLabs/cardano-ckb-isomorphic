# Checkpoint throughput — why returns re-anchor, and the real fixes

**Measured (2026-06-19):** `advance_live` (the deployed single-block windowed advance) is **1,389,535 constraints
per header** — already filling the 2^21 proving tier. The cost is dominated by the in-SNARK Eaglesong PoW +
blake2b and is irreducible per block. Each advance proof is ~6 min (426 MB pk load + prove). CKB produces a block
every ~8 s.

So a **trustless always-current checkpoint is bottlenecked by per-block PoW proving**, and **batch advance does
not fix it**: Groth16 proving is ~linear in constraints and the proving key grows with circuit size, so proving
N headers in one proof ≈ N separate proofs (it saves on-chain tx overhead, not proving throughput). N=2 already
exceeds the 2^21 tier. To keep pace you'd need a ~45× proving speedup — batching can't provide it.

This is why returns **re-anchor** (re-genesis at `burn + K_MIN`): genesis trusts a fresh anchor (no per-block PoW
proof), so it is fast but mints a **new checkpoint NFT** each time → the escrow + ref scripts (which bake the NFT)
churn → no stable escrow.

A design note that DOESN'T help throughput but DOES de-risk the on-chain side: a batch-window-advance circuit that
emits `advance_live`'s **same 7 public inputs** `(old_root, old_total, new_root, new_total, old_wroot, new_wroot,
new_tip)` would be verified by the EXISTING `advance_ckbcert.ak` with just a re-baked vk — no new validator, no
leap-proof rewiring. So if a cheaper-per-block proof ever exists, wiring it on-chain is trivial.

## Three real fixes (ranked by practicality)

### 1. Warm/resident prover — SHIPPED + VALIDATED (the actual dominant cost)
Timing a live return: re-anchor was ~2–3 min; the dominant cost was the burn proof **reloading its 480 MB
`leap_bound_windowed_pk.bin` every time**. Measured: the reload is **~391 s (~6.5 min)** and the actual prove is
**only ~8.3 s** — so the cold ~6.7-min prove step is almost entirely key-reload. `leap_bound_windowed.rs` now has a
`CHIRAL_SERVE=<unix socket>` resident mode (cold one-shot path untouched, `catch_unwind`-hardened): load the pk
**once**, serve many proofs at ~8.3 s each. Validated live — the warm redeemer's vk == the on-chain ceremony vk
(same key that produced release `2030617040`). Client `relayer/warm_prove.py`; `xada_burn_orchestrate.mjs` proves
warm-first with cold fallback. Each return's prove step drops from ~6.7 min to ~8.3 s once the service is warm.
This is the highest-leverage win and is done.

### 2. Stable escrow via a checkpoint REGISTRY — near-term build (recommended next)
Keep fast re-genesis, but decouple the escrow from a single NFT: the `ada_escrow` validator trusts a **registry of
valid checkpoint NFTs** (a rolling set; each re-genesis adds its checkpoint) instead of one baked `checkpoint_nft`.
The escrow + ref scripts then stay STABLE across re-anchors (deploy once, fund as a pool) — eliminating per-return
escrow-lock + ref-script deploy (~3–4 min). Trust is unchanged from today (each registry checkpoint is anchored at
a real CKB height exactly as the current per-return genesis is). Cost: a validator change (escrow binds
`nft ∈ registry` not `nft == const`) + a small genesis-pinned checkpoint registry singleton + its admission rule.
No new cryptography. This is the practical road to "fast, stable returns."

### 3. Recursion / folding (Nova / PCD) — the research endgame for true continuous tracking
A folding scheme (Nova/SuperNova, e.g. via `arecibo`) makes per-block work a cheap **fold** of the PoW step circuit
(~2 MSMs over the step, ~seconds) instead of a full ~6-min Groth16 per block. The accumulator is compressed to one
Groth16 proof periodically for on-chain verification (the existing `advance_ckbcert` shape can verify the wrapper).
This is the only approach that lets a daemon keep the checkpoint at the chain tip trustlessly. Effort: port the
advance step (Eaglesong PoW + window update) to a Nova step function + a Groth16 wrapper; multi-week, arkworks lacks
mature Nova so it pulls in a folding crate. High value, research-grade.

(A FlyClient/superlight sampled-header circuit makes the on-chain VERIFIER succinct but does not reduce the PROVER's
per-block cost for continuous tracking, so it is not the throughput fix here.)

## Recommendation
Ship #1 (done) + build #2 next (stable returns without new crypto). Treat #3 as the long-horizon path to a truly
always-current trustless checkpoint. See memory `checkpoint-advance-throughput` for the measured numbers.
