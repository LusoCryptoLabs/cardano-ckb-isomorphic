# SP1 zkVM setup for M2 (proving the Mithril STM verification)

## Status — ALL FOUR Mithril relations PROVEN in SP1 on real preview data; composed in one STARK
- ✅ SP1 toolchain installed (manually — see install_toolchain.sh). `rustc 1.94.0-dev`, target
  `riscv32im-succinct-zkvm-elf`; `cargo prove build` works. Core STARK prove+verify works on this 15 GB box.
- ✅ **M1** signed_message = Sha256(ordered protocol-message parts) — proven (sp1/m2, and composed below).
- ✅ **M2** BLS-STM aggregate (BLS12-381 pairing, the hard crypto core) — proven (sp1/m2bls; SP1 bls12_381
  precompile cut 57M→~3.3M cycles; needs swap to clear the v6 prover RAM floor).
- ✅ **M3** tx-inclusion: real burn 6608c4c8.. under the certified tx-set root via the two-level Blake2s256
  MKMapProof — proven (sp1/m3), constants decoded from `mithril_verify/proof.example.json` (cert 7356eaa1).
- ✅ **M4** cert_hash recomputed from primitives == the real cert hash — proven (composed below).
- ✅ **ALL FOUR COMPOSED** in ONE SP1 STARK on cert 7356eaa1 (`sp1/m2all`): **M2_ALL_PROVED true**,
  cycles=3,931,058, 15 GB RAM + 17 GB swap. M3's CERT_ROOT is bound to the `cardano_transactions_merkle_root`
  part that M1 hashes and M2 signs — so one proof attests the whole reverse-leg statement.
- ✅ **Groth16 wrap PRODUCED + VERIFIED IN CKB-VM** (`SP1_WRAP=groth16`): on a 64 GB box the wrap runs
  natively (gnark, BN254, nbConstraints=15.97M, prove ~14 s) → a 356-byte proof (`m2all/groth16-ckbvm/`).
  That proof **verifies on-chain in CKB-VM**: accepts the real proof (Run result 0, **3,810,585,066
  cycles ≈ 109 % of a 3.5 G block**), rejects a tampered byte (Run result 1). **Finding:** CKB-VM has no
  BN254 pairing precompile, so the Groth16 wrap is *not* the cheap on-chain route (~26× the direct ~146 M
  Mithril verify, and not post-quantum). Keep the direct Mithril verify on-chain; the succinct/PQ on-chain
  path is the in-house Goldilocks+blake2b FRI verifier (`spike/pq-fri-verify`, ~47 M cycles); SP1 stays an
  off-chain prover. See `m2all/groth16-ckbvm/RESULTS.md`.

## Directory map
| dir | proves | result |
|---|---|---|
| `m2` | M1 signed_message (Sha256) | M2_M1_PROVED |
| `m2bls` | M2 BLS12-381 aggregate (the crypto core) | M2_BLS_PROVED |
| `m2full` | M1 + M2 + M4 composed | M2_FULL_PROVED |
| `m3` | M3 tx-inclusion (two-level Blake2s MMR) | M3_PROVED |
| `m2all` | **M1 + M2 + M3 + M4 — all four, one STARK** | **M2_ALL_PROVED** (+ `SP1_WRAP=groth16` path) |

Full details, cycle counts, the exact Mithril recipe, and the Groth16-wrap resource measurement: **M2_SCOPE.md**.

## Environment gotchas (documented so this reproduces)
1. `cargo prove install-toolchain` FAILS here with "error sending request": its bundled-reqwest TLS does
   not trust the sandbox egress-proxy CA (curl/cargo use the system CA and work). Also needs an authed
   GitHub call (unauth 60/hr too low on the shared IP). Fix: `install_toolchain.sh` downloads the asset
   with curl + $GITHUB_TOKEN and links it manually.
2. The `succinct-1.94.0-64bit` x86_64-linux asset ships `bin/rustc` + `lib` but NOT `cargo`; symlink the
   host cargo into the toolchain (the script does this).
3. `sp1-sdk` needs `protoc` (`apt-get install -y protobuf-compiler`).
