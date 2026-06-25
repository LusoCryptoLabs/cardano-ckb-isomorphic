# Spike - the build

> Status (2026-06): what began as the Phase-1 feasibility gate (below) grew into the full
> build. Each subdirectory is a proven experiment with its own `RESULTS.txt`; together they are the
> live bridge, both directions. Map:
>
> - Cardano→CKB (Mithril-in-CKB-VM): `mithril-verify/` (cert verify, acceptance green),
> `light-client-cell/` (`AdvanceCert`/`TxSetCert`, live), `cross-chain/` (tx-membership oracle),
> `bound-asset/` + `phase1/` (the `BoundAsset` verifier), `phase2/` (SNARK-lottery target),
> `phase3/` (relayer + leap-out finalize), `phase4/` (hardening/difftest).
> - CKB→Cardano (Groth16-in-Plutus): `ckb-to-cardano/` (consensus circuit + Aiken verifier +
> live round trip).
> - Optional v2: `cardano-to-ckb-zk/` (SP1 STARK-Mithril, all four relations composed).
> - Ops primitives: `burn-gated-unlock/`, `relay-escrow/`, `relayer-daemon/`.
> - Feasibility origin: `ckb-vm-bls-bench/`, `mithril-real-point/` (the Phase-1 measurements).
>
> See `../docs/CHIRAL_STATUS.md` and `../docs/LIVE_STATUS.md` for the live tx record.

## Origin - Cardano light-client feasibility on CKB (Phase 1)

This held the evidence for the gate in `docs/FEASIBILITY.md`.

Verdict: GO (latency is the design caveat, not a blocker) - since proven live. See
`docs/FEASIBILITY.md`.

- `ckb-vm-bls-bench/bls_bench.rs` - the CKB script binary used to measure BLS12-381 pairing
  and G1-addition cycle costs on the CKB VM. Run inside a CKB script workspace via
  `ckb-testtool` (see `docs/FEASIBILITY.md` §Reproduce). It must not be committed to the
  sibling `cardano-ckb-bridge` repo (the frozen baseline) - it lived there only transiently
  to borrow the proven cross-compilation toolchain.
- `ckb-vm-bls-bench/RESULTS.txt` - the raw measured numbers + live mainnet Mithril params.
