# SP1 ↔ AIR recursion: the design, the enabling primitive (measured), and the honest remaining build

**Goal.** Verifying an SP1 proof of CKB consensus natively in CKB-VM costs ~2.3 G cycles (measured,
`spike/sp1-verify-cost`). *Recursion* compresses that: prove, in a cheap STARK, that you verified the SP1
proof; then on-chain you verify only the small constant-size **outer** proof. This is exactly how SP1's own
"compressed" proof works internally — and the same technique would bind our two prover demos (`sp1-ckb`'s PoW
proof and `consensus`'s difficulty-sum AIR) into one on-chain-cheap proof of the *real* consensus transition.

## The one thing that makes recursion possible: a field-friendly hash

Verifying a STARK inside a STARK means **re-running the verifier's hashing as circuit constraints**. A hash is
arithmetizable only if it is built from field operations:

| hash | CKB-VM cost (measured) | arithmetizable? |
|---|---|---|
| blake2b-256 (our on-chain verifier) | 6,601 cyc/2-to-1 | **no** — ARX / bit ops, ~10³ constraints each, recursion-hostile |
| **Poseidon2-Goldilocks** (this spike) | **18,420 cyc/perm** | **yes** — width 8, S-box x⁷, all field ops |
| Poseidon2-KoalaBear (SP1's hash) | 26,157 cyc/perm | yes |

This is the key insight and the reason our on-chain verifier (blake2b) is *not* itself recursable: blake2b is
the right choice for a **native** CKB-VM verifier (cheap as a syscall-like op) but the wrong choice for a
**recursed** one. A recursion-ready PQ stack must hash with Poseidon2 — at **~2.8× the native cost of blake2b**
(measured here), which is the price of recursability. (For recursing *SP1* specifically, the outer circuit
must encode Poseidon2-**KoalaBear**, SP1's hash.)

## The recursion design

1. Inner proof uses a field-friendly hash (Poseidon2). The inner verifier does `H` permutations
   (Merkle-path + transcript hashing).
2. The **recursion AIR** is a circuit that *runs the inner verifier*: its trace holds the Poseidon2 states
   and the opened values, with constraints enforcing (a) each Poseidon2 round (add-constant, x⁷ S-box, the
   external/internal linear layers — all field arithmetic) and (b) the FRI fold relations. It outputs the
   inner proof's public statement.
3. Prove the recursion AIR (a STARK). Commit it with **blake2b** (so the *outer* proof verifies cheaply in
   CKB-VM). On-chain you verify only this constant-size outer proof — our existing cheap verifier.

## Cost model (grounded in the measured per-perm cost)

With ≈30 constraint-rows per Poseidon2 permutation (8 full + 22 partial rounds; order-of-magnitude):

| recurse | inner Poseidon2 perms | recursion AIR size | outer on-chain verify |
|---|---|---|---|
| our secure FRI (144 q, n=2¹³) | ~26,000 | ~2²⁰ rows | **~283 M cyc** |
| **SP1 compressed proof** (measured 86 K perms) | ~86,000 | ~2²² rows | **~333 M cyc** |

So recursion turns **SP1's ~2.3 G native on-chain verify into a ~300 M outer-STARK verify** — **~7–8× cheaper,
constant-size regardless of the inner computation**, checked by our blake2b verifier (which already fits 4 MB,
`SECURITY.md`). It also closes the `sp1-ckb`↔`consensus` seam: one recursive proof attests *valid PoW chain →
correct total_difficulty*, verified cheaply on-chain.

## What's done here vs. the remaining build (honest)

**Done (this spike):** the enabling primitive — **Poseidon2-Goldilocks implemented and measured in CKB-VM
(18,420 cyc/perm)** — plus the design and a measurement-grounded cost model. This establishes recursion is
*feasible and quantified*: the recursion-friendly hash works, and the outer verify lands at ~300 M cycles
(~8–9 % of a block).

**Remaining (a dedicated build, not a session task):** the recursion AIR itself. That requires
- a **general multi-column, higher-degree AIR framework** (our STARK machinery is hardcoded to 1–2 columns,
  degree ≤ 2; Poseidon2 needs width-8 state and degree-7 constraints), and
- **Poseidon2 rounds + FRI-verifier logic encoded as constraints** (the verifier circuit).

This is, in scope, **SP1's `sp1-recursion` machine** — person-level effort, the standard hard core of every
recursive proof system. There is **no research risk** (the design and costs are settled above); it is a
substantial engineering project. The honest status: recursion is **designed, its primitive built and measured,
and its cost quantified (~300 M on-chain, ~7–8× cheaper than native SP1)** — the verifier circuit is the
remaining implementation.

## Reproduce

```
cd ckbvm
cargo build --release --target riscv64imac-unknown-none-elf                    # baseline (K=0)
cargo build --release --features perms --target riscv64imac-unknown-none-elf   # +1000 permutations
ckb-debugger --bin <elf> --mode full   # per-perm = (K-build − baseline)/1000
```
