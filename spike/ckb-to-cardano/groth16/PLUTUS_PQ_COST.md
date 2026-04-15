# Can the Cardano leg be post-quantum too? — measured: not within a Plutus tx budget

The CKB side got a working post-quantum (hash-only FRI/STARK) verifier because CKB-VM is a general RISC-V
machine where a blake2b costs ~6,600 cycles against a ~3.5×10⁹-cycle block. The symmetric question for "both
legs quantum-resistant" is whether the **Cardano** side — Plutus — can run the same hash-based verifier. This
measures it the same way: micro-benchmark the primitives, combine with the verifier's op counts.

Plutus is fundamentally different: **no general-purpose VM** (it's an interpreted lambda calculus with builtin
functions and an ExBudget cost model), and **no native FRI/Merkle/Goldilocks acceleration** — only BLS12-381
pairings are builtins, which is exactly why Groth16 fits Plutus (~22.7% of budget) but a hash-STARK is a very
different story.

## Measured (`lib/pqcost.ak`, `aiken check`, Plutus v3, stdlib v2.2.1)

Per-op cost isolated as (ExUnits at 2N − at N)/N over chained iterations:

| primitive | cpu-steps / op | mem units / op |
|---|---|---|
| blake2b-256 of a 64-byte Merkle node | **964,127** | **2,916** |
| Goldilocks field multiply (`a*b mod p`) | **950,909** | **3,107** |

Per-transaction budget (Plutus v3 mainnet `maxTxExUnits`): **cpu 10,000,000,000 ; mem 14,000,000.**

A single blake2b node-hash is ~964 K cpu-steps — **~51× costlier, relative to budget, than the same hash in
CKB-VM** (Plutus 9.6×10⁻⁵ of budget/hash vs CKB-VM 1.9×10⁻⁶). And **memory is the harder cap**: at 2,916 mem
units/hash, **only ~4,800 blake2b hashes fit in one transaction** (field muls: ~4,500). Note field arithmetic
is as expensive as hashing here — Plutus has no native 64-bit field, so each Goldilocks mul is a big-integer
multiply + reduce.

## Verdict: a hash-based verifier does NOT fit one Plutus tx

Using the op counts measured for the CKB-VM verifier:

| verifier | blake2b | field-mul | cpu vs budget | mem vs budget |
|---|---|---|---|---|
| demo FRI (40 q, n=2¹³) — *not even secure* | ~7,200 | ~2,000 | 0.9× | **1.9×** |
| secure quartic (100 q, n=2¹³) | ~18,000 | ~5,000 | 2.2× | **4.9×** |
| production (n=2²², 100 q) | ~50,000 | ~15,000 | 6.2× | **13.7×** |

**Even the smallest, weakest FRI verifier exceeds the per-tx memory budget by ~1.9×; a quantum-secure one by
~5×; production by ~14×.** It does not fit — the binding constraint is the 14 M memory cap (~4,800 hashes/tx).

## Why the asymmetry, and what it means for "both legs"

- **CKB-VM** is a real CPU: a hash is a tight native loop, a Goldilocks mul is one 64-bit multiply + a cheap
  reduction. A hash-based verifier is ~1–10% of a block. ✅ (demonstrated, `spike/pq-fri-verify`).
- **Plutus** has no such machine: every hash/field-op is an interpreted builtin with a large ExBudget, and the
  one thing it *does* accelerate is BLS12-381 pairings — i.e. precisely the **non-post-quantum** primitive.
  So Cardano is, today, structurally biased toward the classical (Groth16/BLS) verifier and **cannot host the
  hash-based PQ verifier within a transaction.**

So **both legs are not — and cannot today be — symmetrically post-quantum by the same approach.** Closing the
Cardano side needs one of:
1. **Protocol-level builtins** on Cardano for a STARK-friendly hash or FRI step (the analogue of the BLS
   builtins that made Groth16 viable) — a ledger/Plutus change, not something a script can do.
2. **Splitting verification across a chain of transactions** (incremental/streamed verification with state in
   reference cells) — fits the per-tx cap by using many txs, at the cost of latency and a more complex,
   liveness-sensitive protocol.
3. A different PQ construction whose Cardano-side check is cheap (e.g. only a few hashes), pushing the heavy
   verification elsewhere — research-level.
4. Cardano adopting **native PQ signatures**, which also addresses the deeper Ed25519/KES anchor problem.

## Honest bottom line

The CKB leg's on-chain verifier is post-quantum and demonstrated. The **Cardano leg cannot be made
post-quantum by porting the same hash-STARK verifier into Plutus** — measured to overflow the per-tx budget by
~2–14×, memory-bound. That is the concrete, quantified blocker to "both legs quantum-resistant," and it is a
Cardano-protocol matter (PQ-friendly builtins or PQ signatures), above the bridge layer. (This is a primitive
+ op-count estimate; an actual end-to-end Plutus FRI verifier would refine the op counts, but the
order-of-magnitude memory overflow — and thus the verdict — does not depend on that refinement.)
