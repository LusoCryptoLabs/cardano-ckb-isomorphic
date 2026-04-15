# Reproducing the SP1 Mithril-verification proofs

Exact, tested commands for the proofs under `sp1/`. Paths assume the repo at
`/home/user/cardano-ckb-isomorphic` (adjust `CERT`/`PROOF` paths in the hosts if you relocate it).

## 0. Prerequisites
- **SP1 toolchain** (`succinct` rustc + `riscv32im-succinct-zkvm-elf`): `bash sp1/install_toolchain.sh`
  (works around cargo-prove's reqwest/egress-proxy TLS bug; needs `$GITHUB_TOKEN` for the authed asset
  download). Then `export PATH="$HOME/.sp1/bin:$PATH"`.
- `apt-get install -y protobuf-compiler` (sp1-sdk needs `protoc`).
- Real Mithril data is committed: `mithril_verify/cert.example.json` (preview cert 7356eaa1) and
  `mithril_verify/proof.example.json` (the MKMapProof for burn tx 6608c4c8 under that cert). No network needed.

## 1. The proofs (Core STARK — prove + verify)
Each is `cargo run --release` in the `script/` dir; the guest is auto-built by `build.rs`.

| dir | command (in `sp1/<dir>/script`) | success line | cycles |
|---|---|---|---|
| `m2`    | `cargo run --release` | `M2_M1_PROVED true`   | ~62.8K |
| `m2bls` | `cargo run --release` | `M2_BLS_PROVED true`  | ~3.29M |
| `m3`    | `cargo run --release` | `M3_PROVED true`      | ~85.2K |
| `m2full`| `cargo run --release` | `M2_FULL_PROVED true` | ~3.85M |
| `m2all` | `cargo run --release` | `M2_ALL_PROVED true`  | 3,931,058 |

`m2all` is the headline: M1 + M2 + M3 + M4 in ONE STARK. It first prints
`EXECUTE cycles=3931058 M1_ok=true M4_certhash_ok=true bls_ok=true m3_ok=true`, then proves+verifies.

## 2. Resource recipe (this 15 GB-RAM box)
The BLS-heavy proves (`m2bls`, `m2full`, `m2all`, ~3–4M cycles) exceed the SP1 v6 prover's RAM floor on
15 GB. Add swap so RAM+swap ≈ 32 GB, and keep disk free for the final link:
```sh
fallocate -l 17G /swapbig && chmod 600 /swapbig && mkswap /swapbig && swapon /swapbig
```
Tip: build first (`cargo build --release`, disk-heavy link), THEN grow swap, THEN run — the link needs disk,
the prove needs RAM. The small proofs (`m2`, `m3`) prove fine on 15 GB with no swap.

## 3. Groth16 wrap (STARK→SNARK BN254, for cheap on-chain CKB-VM verify)
`m2all/script` supports `SP1_WRAP=groth16`: produces a constant-size BN254 Groth16 proof (writes
`/tmp/m2all_groth16.bin` + `/tmp/m2all_pubvals.bin`, prints `M2_ALL_GROTH16 true vk=… proof_hex=…`).

Gnark circuit artifacts (~8 GB, version pinned in `sp1-prover`'s `SP1_CIRCUIT_VERSION`, here `v6.1.0`):
```sh
DIR=~/.sp1/circuits/groth16/v6.1.0; mkdir -p $DIR
curl -s -o $DIR/artifacts.tar.gz https://sp1-circuits.s3-us-east-2.amazonaws.com/v6.1.0-groth16.tar.gz
( cd $DIR && tar xzf artifacts.tar.gz && rm artifacts.tar.gz )   # -> groth16_pk.bin (5.5G) + groth16_circuit.bin (2.3G)
```
Run (single-worker keeps the recursion RAM peak down; arity MUST stay default):
```sh
SP1_WRAP=groth16 \
SP1_WORKER_NUM_CORE_WORKERS=1 SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=1 \
SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=1 SP1_WORKER_NUM_DEFERRED_WORKERS=1 \
cargo run --release
```

### Resource reality (MEASURED here — read before trying on a small box)
- The SP1 recursion+wrap phase (before gnark) needs **~33 GB effective** memory. With 18 GB swap (artifacts
  NOT yet on disk) it clears the wrap; with ≤16 GB swap it OOMs (~36 GB total-vm).
- gnark then needs the **8 GB artifacts on disk** + memory. On this ~38 GB-disk box, 18 GB swap and 8 GB
  artifacts cannot co-reside, and they're needed at different times in one process → the wrap is gated here.
- **Do NOT set** `SP1_WORKER_MAX_REDUCE_ARITY`/`MAX_COMPOSE_ARITY` below the default 4 — only those
  reduce-shapes are precomputed; arity 2 panics in `sp1-prover` `shapes.rs`.
- **Recommended**: a **≥32 GB-RAM** machine (no swap juggling; artifacts fit easily) runs the command above
  end-to-end, or use the **SP1 network prover** (`SP1_PROVER=network` + key) to offload proving entirely.

## 4. Consuming the proof on CKB
The committed public values are, in order: `signed_message(hex) || cert_hash || avk_root || hm || bls_ok || m3_ok`.
A CKB-VM bn254 Groth16 verifier checks the proof against the VK hash (printed as `vk=…`, = public input #0),
then enforces the seal/commitment binding (see `REVERSE_LEG.md`). NB: the LIVE reverse leg already verifies
the full M1..M4 directly in CKB-VM — this SP1 path is the optional succinct/post-quantum optimization.
