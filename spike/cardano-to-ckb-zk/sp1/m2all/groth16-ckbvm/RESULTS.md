# Verifying the SP1 Groth16 wrap of the composed Mithril STARK *inside CKB-VM*

This closes the last ⏳ of the optional v2 "succinct reverse leg" (`../README.md`): the SP1 STARK
that composes all four Mithril relations (M1 signed-message · M2 BLS-STM aggregate · M3 tx-inclusion
· M4 cert-hash) was wrapped into a constant-size **BN254 Groth16** proof, and that proof is verified
**on-chain in CKB-VM** here, on the real preview certificate `7356eaa1`.

## What runs

1. **The wrap** (`SP1_WRAP=groth16` on `../m2all`): produced + verified off-chain on a 64 GB box
   (gnark, BN254, `nbConstraints=15,972,262`, prove ~14 s). Outputs, baked in here via
   `include_bytes!`:
   - `proof.bin` — 356 bytes = 4-byte vkey-hash prefix + 32 exit-code + 32 vk-root + 32 proof-nonce + 256-byte gnark proof
   - `pubvals.bin` — 210 bytes of SP1 public values
   - `groth16_vk.bin` — 492-byte SP1 v6 Groth16 verifying key
   - SP1 program vkey hash `0x008a8215ff859b6c741815c584dc8247b4a8c3fd3aa856fa75876fbea02763e8`
2. **The on-chain verify** (`src/main.rs`): a `ckb-std` no-std RISC-V program that reconstructs the
   five Groth16 public inputs `[vkey_hash, sha256(pubvals)&top3=0, exit_code, vk_root, proof_nonce]`
   and runs the BN254 pairing check. The verify logic is vendored from SP1's `sp1-verifier` Groth16
   path (`verify_gnark_proof`), so it accepts proofs from the SP1 SDK `.groth16()` prover unchanged.
   Only `bn` (pure-Rust `substrate-bn-succinct-rs`) + `sha2` are pulled in — *not* the heavy
   recursion crates that `Groth16Verifier::verify` needs for the `VK_ROOT_BYTES` equality.

## Measured (ckb-debugger 1.1.1, script-version 2, riscv64imac)

| run | result | cycles |
|---|---|---|
| **positive** (real proof) | `Run result: 0` — **verified** | **3,810,585,066** (3634 M) |
| **negative** (one tampered public-values byte) | `Run result: 1` — **rejected** | 3,805,390,256 |

The verifier accepts the genuine proof and rejects a tamper, so the pairing check is real, not
vacuous.

## The finding: BN254-Groth16-in-CKB-VM is **not** the cheap path

The verify costs **~3.81 G cycles ≈ 109 % of a 3.5 G-cycle CKB block.** CKB-VM has **no BN254
pairing precompile**, so the four-pairing Groth16 check runs as pure-software field arithmetic and
is expensive. Put in context:

| on-chain reverse-leg verify | CKB-VM cycles | share of a block |
|---|---|---|
| **direct Mithril cert verify** (what's LIVE) | ~146 M | ~4 % |
| in-house Goldilocks+blake2b STARK verify (`spike/pq-fri-verify`) | ~47 M | ~1.3 % |
| native SP1 STARK verify (`spike/sp1-verify-cost`, est.) | ~2.3 G | ~65 % |
| **this: SP1 Groth16 (BN254) wrap verify** | **~3.81 G** | **~109 %** |

So the Groth16 wrap is ~26× the direct Mithril verify and over one block — it is the *wrong* route
for cheap on-chain verification on CKB, and (being pairing-based) it is also not post-quantum. It is
valuable as an **end-to-end demonstration** that an SP1-produced succinct proof of the Mithril
statement can be checked in CKB-VM at all; the cheap and/or post-quantum on-chain path remains the
**direct Mithril verify** (live) or the **in-house FRI verifier** (`spike/pq-fri-verify`,
hash-only, ~47 M cycles). SP1 stays an *off-chain* prover. This matches the conclusion of
`spike/sp1-verify-cost`.

## Build / run notes (reproduce)

```
# build for CKB-VM (single-threaded: lower atomics to plain RMW, see src/atomics.rs)
cargo build --release   # .cargo/config.toml sets target + -C target-feature=-a,+forced-atomics
ELF=target/riscv64imac-unknown-none-elf/release/g16_ckbvm
ckb-debugger --max-cycles 100000000000 --bin "$ELF"   # Run result: 0 ; All cycles: 3,810,585,066
```

Gotchas handled: `ckb-std` needs `riscv64-unknown-elf-gcc`; CKB-VM has no A-extension so `bn`'s
`spin`/`lazy_static` atomics are lowered via `-a,+forced-atomics` with `__sync_*` polyfills
(`src/atomics.rs`, sound on one hart); LTO is off to avoid a target-feature/bitcode mismatch with
`ckb-std`'s prebuilt objects.
