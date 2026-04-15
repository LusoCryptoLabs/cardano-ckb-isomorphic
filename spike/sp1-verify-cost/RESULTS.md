# Can an SP1 proof be verified on-chain in CKB-VM? — the cost keystone

The remaining integration question for the post-quantum forward leg: `spike/sp1-ckb/` showed a production SP1
prover generates a real STARK proof of CKB consensus on this box; `spike/pq-fri-verify/` showed a hash-only
STARK *verifier* runs in CKB-VM at ~47 M cycles. To verify an **SP1** proof on-chain (post-quantum, i.e. the
compressed STARK, not the non-PQ Groth16 wrap) you need SP1's verifier in CKB-VM — and SP1 is over a
*different* field+hash (KoalaBear + Poseidon2) than our verifier (Goldilocks + blake2b). Porting SP1's whole
recursion verifier is a multi-week build, but the answer hinges on one measurable quantity: **the CKB-VM cost
of SP1's hash primitive, Poseidon2 over KoalaBear**, because hashing dominates a STARK verify (as the
`pq-fri-ckbvm` keystone established). So we measure that directly.

## Measured in CKB-VM (ckb-debugger 0.119.0, `--mode full`, riscv64imac)

Method: run K operations, subtract a K=0 baseline (636 cycles) to isolate cost/op. The Poseidon2 is a
faithful port of SP1 v6's actual permutation — KoalaBear in **Montgomery form** with SP1's `MONTY_MU` and
`monty_reduce`, the external MDS-light layer (`circ(2·M4, M4, …)`), the width-16 internal diffusion (real
monty shift table), 8 full + 20 partial rounds, S-box x³. Only the round-constant *values* are placeholders
(they don't affect cycle count). blake2b is measured in the same harness for an apples-to-apples ratio.

| primitive (1000×) | total cycles | **per op** | |
|---|---|---|---|
| **Poseidon2-KoalaBear** (SP1's hash) | 26,157,813 | **26,157 cyc** | width 16, 28 rounds, x³ |
| blake2b 2-to-1 compress (our hash) | 6,601,326 | **6,601 cyc** | the Merkle compress in `pq-fri-verify` |

**SP1's hash primitive costs ≈ 4.0× a blake2b compress in CKB-VM.** (The blake2b figure also confirms the
`pq-fri-ckbvm` model's ~5.8 K/hash estimate from the other direction.)

## The permutation count — now measured, not modeled

The earlier version of this note *modeled* the Poseidon2 count at ~10⁴–3×10⁴. We then pinned it by
**instrumenting SP1's actual permutation** (`spike/sp1-ckb/vendor/p3-poseidon2`, a copy of the real crate with
an atomic counter in `permute_mut`, wired in via `[patch.crates-io]`) and counting the permutations a real
SP1 **core-proof verify** performs on this box (the counter is reset immediately before `client.verify`):

| program proven | Poseidon2 perms in verify | × 26,157 cyc | share of a ~3.5×10⁹-cycle block |
|---|---|---|---|
| CKB chain, 1 block | **86,291** | **2.257 G** | **~64 %** |
| CKB chain, 256 blocks (1.5 M cycles) | **86,844** | 2.272 G | ~65 % |

The count is **essentially constant** (+0.6 % from 1→256 blocks): both programs fit in one SP1 shard, so the
verify cost is fixed by the per-shard chip/commitment structure (the marginal growth is slightly deeper
Merkle paths for the taller trace). So **the measured count (~86 K) is ~3–8× higher than the earlier model**
— the model under-counted the per-shard commitment openings and challenger sponge calls.

**Compressed (on-chain) proof — bounded, not directly measured.** On-chain you'd verify the constant-size
*compressed* (recursion) proof, not the core proof. Producing one needs the recursion prover, which **OOM-kills
at >15 GB on this box** (confirmed: `--compressed` peaks ~13 GB then SIGKILL), so it couldn't be measured here.
But its verify is a single recursion-STARK verify of the *same kind and order* as a core-shard verify (94
queries, Poseidon2 Merkle over a ~2²⁰ AIR), i.e. also ~10⁴–10⁵ permutations → **~0.3–2.6 G CKB-VM cycles**.

## Conclusion

| post-quantum on-chain verifier | CKB-VM cycles | share of a block |
|---|---|---|
| **our Goldilocks+blake2b STARK** (`pq-fri-verify`, measured) | **47 M** | ~1.3 % |
| native **SP1** verify (measured core; compressed same order) | **~2.3 G** (~0.3–2.6 G) | ~30–75 % |

Verifying an SP1 proof natively in CKB-VM is **technically possible but expensive — roughly a *whole CKB
block*, ~30–50× our own verifier.** Two compounding reasons: Poseidon2-KoalaBear is ~4× a blake2b per call,
and an SP1 shard verify does ~86 K hashes (94 queries × many committed matrices) vs our 40-query verifier's
~7 K. So the post-quantum on-chain path the bridge should take is the **in-house Goldilocks+blake2b STARK**
(`pq-fri-verify`); **SP1 is for proving** (off-chain, where its tooling and speed win), with its output
re-proven into the lighter on-chain system if one end-to-end pipeline is wanted.

Both inputs are now hard-measured: the per-permutation cost (26,157 cyc) and the per-verify permutation count
(86,291). The only un-measured piece is the *compressed* proof's exact count (needs a >15 GB box to produce
one), bounded above to the same order as the core-shard verify.

## Reproduce

```
cd ckbvm
cargo build --release --target riscv64imac-unknown-none-elf                    # baseline (K=0)
cargo build --release --features perms --target riscv64imac-unknown-none-elf   # +1000 Poseidon2
cargo build --release --features blake --target riscv64imac-unknown-none-elf   # +1000 blake2b
ckb-debugger --bin <elf> --mode full   # read 'All cycles'; per-op = (K-build - baseline)/1000
```

(`target/` is git-ignored; the three measured ELFs are in `bin/`.)
