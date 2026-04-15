# A real post-quantum FRI + STARK verifier, running in CKB-VM

Turns the `spike/pq-fri-ckbvm` cost *model* into a **measured, working** verifier. Two real proofs
(host-generated) are verified **inside CKB-VM** with hash-only + Goldilocks arithmetic — **no pairings, no
trusted setup ⇒ a post-quantum verifier**: a FRI low-degree test, and a full **STARK** that proves an actual
computation is correct. Valid proofs accepted, tampered/invalid proofs rejected.

## What it is

- `core/` — `fri-core`, a `no_std` crate shared by prover and verifier: Goldilocks field (p = 2⁶⁴−2³²+1),
  blake2b Merkle, Fiat–Shamir transcript, an O(n log n) NTT, FRI **prove/verify**, and a minimal **STARK**
  (`stark_prove`/`stark_verify`) layered on the FRI engine. The FRI verifier is **inversion-free** (fold
  consistency checked by cross-multiplication `2x·v_next == x(e₀+e₁) + β(e₀−e₁)`); the primitives are exactly
  those measured in `pq-fri-ckbvm`.
- `host/` — `prove` (FRI: a random degree-<n/2 polynomial is low-degree) and `stark` (a real computation
  `a(i+1)=a(i)²+c`); each writes fixtures and runs an adversarial battery through the shared verifier.
- `ckbvm/` — two `no_std` CKB-VM binaries (`fri_verify`, `stark_verify`): embed a proof, verify it, exit
  `0`/`20`/`2`.

The FRI low-degree-test sections below are the foundation; the **STARK** section ("From LDT to a real STARK")
is the headline — a post-quantum verifier of an actual computation, in CKB-VM, at the same cost class.

## Measured (ckb-debugger 0.119.0, `--mode full`, riscv64imac)

Instance: `log_n = 13` (domain n = 8192), `n_folds = 9`, `NUM_QUERIES = 40`, final poly degree < 8.

| input | result | cycles |
|---|---|---|
| **valid proof** | **accept (exit 0)** | **49,109,669 (46.8 M)** |
| tampered (final poly perturbed) | reject (exit 20) | 1,915,911 (1.8 M) — fails fast |

**This validates the keystone model.** Per query: 9 layers × 2 authentication paths, depths 13…5 ⇒ ≈ 81×2 =
162 node-hashes + 18 leaf-hashes; ×40 queries ≈ **7,200 blake2b**. At the measured ~5,840 cyc/hash that is
~42 M — and the measured total is 46.8 M (the ~5 M remainder is the field arithmetic: ωˡᵒ powers, the fold
checks, Horner). The cost model holds on a real run.

## Adversarial battery (host, shared verifier) — 7/7

| case | what it forges | result |
|---|---|---|
| F0 | valid proof | **accept** |
| F1 | a query leaf value | reject |
| F2 | a Merkle path node | reject |
| F3 | a layer root | reject |
| F4 | the final low-degree polynomial | reject |
| **F5** | a **high-degree** codeword (not in the rate-½ RS code) | **reject** (LDT soundness) |
| F6 | a swapped fold pair | reject |

F5 is the important one: it shows the verifier rejects a *genuinely high-degree* witness, i.e. it is a real
low-degree test, not just a Merkle/transcript integrity check. The in-VM build confirms one rejection too
(`--features bad` → exit 20).

## The prover runs here, at production domain size

"Can the prover run on this box?" — **yes, measured.** The prover (NTT + blake2b Merkle + FRI) is now
O(n log n) via a radix-2 Goldilocks NTT (`fri-core::ntt`; the field's 2-adicity is 32, so it is exact to
2³²). `host/src/bin/bench.rs` proves a random degree-<n/2 polynomial is low-degree at increasing domain
sizes on this **15 GB / 4-core** box (single-threaded):

| log₂ n | domain | prove time | peak RSS | proof | verifies |
|---|---|---|---|---|---|
| 13 (demo) | 8 K | 11 ms | 3.5 MB | 215 KB | ✅ |
| 20 | 1 M | 2.1 s | 154 MB | 526 KB | ✅ |
| 22 | 4 M | 8.8 s | 609 MB | 637 KB | ✅ |
| **23 (production LDE)** | **8.4 M** | **15.8 s** | **1.19 GB** | **697 KB** | ✅ |

2²³ is the LDE domain of the ~1.23 M-constraint CKB-consensus circuit (trace ≈ 2²¹, blowup ×4). The FRI
prover proves at that size in **~16 s and 1.2 GB — ~12× RAM headroom** on this box, single-threaded (≈4×
faster is on the table with rayon across the 4 cores). The earlier "needs ≥32 GB" caveat was specifically
the **SP1 Groth16 *wrap*** — the non-PQ outer SNARK we explicitly *don't* want; the post-quantum **core
STARK** prover, of which FRI is the heavy half, is light and fits here comfortably.

`cargo prove` (SP1 v4) and the `succinct` toolchain are installed, and the crate registry is reachable from
this environment, so a genuine SP1 core-STARK proof of the *real CKB-consensus program* (vs. this hand-rolled
STARK) is the buildable next step — see "Scope / honesty" at the end.

## Scaling to the production circuit (cost on CKB)

The CKB-consensus circuit is ~1.23 M constraints ⇒ trace ≈ 2²¹, LDE domain ≈ 2²³ (D = 23), and ~100-bit
soundness wants Q ≈ 80. With this verifier's (unoptimized) **two-paths-per-layer** opening:
~Q·(Σ layer depths)·2 ≈ 80 · 261 · 2 ≈ 42 k node-hashes ⇒ **~240 M cycles ≈ ~7 % of a ~3.5×10⁹-cycle CKB
block.** The standard **sibling-pairing** layout (commit `(v_i, v_{i+half})` as one leaf ⇒ one path per
layer) halves it to **~120 M cycles (~3–4 %)** — matching the `pq-fri-ckbvm` keystone number. Either way it
**fits CKB-VM with large headroom**, and is on the same order as the BLS `cert-verify` (164.6 M) it would
replace — **roughly cost-neutral, but post-quantum** (`docs/PQ_STRATEGY.md`).

## Reproduce

```
./build.sh                                              # regenerates fixtures + builds all 4 riscv64 verifiers
# FRI low-degree test:
ckb-debugger --bin bin/fri_verify.bin       --mode full # valid    -> Run result: 0,  ~46.8M cycles
ckb-debugger --bin bin/fri_verify_bad.bin   --mode full # tamper   -> Run result: 20
# full STARK (verifies a real computation):
ckb-debugger --bin bin/stark_verify.bin     --mode full # valid    -> Run result: 0,  ~46.5M cycles
ckb-debugger --bin bin/stark_verify_bad.bin --mode full # invalid  -> Run result: 20
```

## From LDT to a real STARK — verifying an actual computation in CKB-VM

The FRI test above proves a *codeword* is low-degree. The next file up the stack turns it into a real
**STARK** that proves an actual *computation* is correct, and runs that verifier in CKB-VM too.

**Statement (public):** from `a(0)=3`, the recurrence `a(i+1) = a(i)² + 5` over Goldilocks reaches `out`
after `nt = 1024` steps. The prover interpolates the execution trace into `f` over the trace group `H=⟨g⟩`,
low-degree-extends it onto the disjoint coset domain `D = 7·⟨ω⟩` (`N = 2048`, blowup 2), and proves three
constraint quotients are polynomials by showing their random linear combination — the **composition
polynomial CP** — is low-degree (via the same FRI engine):

| constraint | quotient that must be a polynomial |
|---|---|
| boundary (seed) | `(f(x) − a0) / (x − 1)` |
| boundary (result) | `(f(x) − out) / (x − g^{nt−1})` |
| transition | `(f(g·x) − f(x)² − c) / ((x^{nt}−1)/(x − g^{nt−1}))` |

The CKB-VM verifier runs the FRI low-degree test on CP **and**, at each FRI query point, re-derives CP from
the opened trace values and checks it equals the FRI-committed CP value — binding the trace to CP. (Stark101
style: the composition relation is checked directly at the query points, not via a DEEP out-of-domain point.)

**Measured (ckb-debugger, `--mode full`):**

| input | result | cycles |
|---|---|---|
| **valid computation** (constraints hold) | **accept (exit 0)** | **48,753,378 (46.5 M)** |
| invalid computation (recurrence broken at step 6) | reject (exit 20) | 2,924,257 (2.8 M) — FRI fails fast |

**The headline:** a full STARK verifier — checking an actual computation's AIR constraints, not just a
low-degree codeword — costs **46.5 M cycles, the same class as the pure LDT (46.8 M).** The constraint layer
adds field arithmetic (~240 Goldilocks inversions across the 40 queries) but **no new cost class**: the
Merkle hashing still dominates, confirming the earlier prediction. So "verify an actual computation,
post-quantum, on CKB" is ≈1.3 % of a block at this size.

**STARK adversarial battery (host, shared verifier) — 7/7:** valid accepted; tampered trace opening, wrong
claimed output, tampered trace root, tampered composition poly, **an invalid computation that breaks the
recurrence (S5 — the real STARK-soundness case)**, and a swapped trace/shift opening all rejected. The
in-VM `bad` build (`stark_verify_bad.bin`) confirms the invalid-computation rejection inside CKB-VM.

## Scope / honesty

This is a faithful but **minimal** STARK: one trace column, a degree-2 transition, three constraints,
rate-½ FRI. It is the real pipeline (trace LDE → constraint quotients → composition → FRI → query-point
checks), not the CKB-consensus AIR — authoring that ~1.23 M-constraint circuit is the separate large piece.
What this spike establishes is now strong and measured: **a hash-only, setup-free, post-quantum verifier
that checks an actual computation runs in CKB-VM in budget (46.5 M cycles), and the prover that produces
such proofs runs on a commodity 15 GB box at the production domain size (16 s / 1.2 GB at 2²³).** The one
remaining heavyweight is a production zkVM prover (e.g. SP1) of the *real* CKB-consensus program; the SP1
toolchain and crate registry are reachable here, so that is a scoped follow-up rather than a blocker.
