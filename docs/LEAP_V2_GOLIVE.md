# Leap v2 — LIVE on testnet (Pudge ⇄ preview)

The RGB++-style ownership-toggle leap is **deployed and proven end-to-end on both testnets.** The genesis —
a CkbOwned cell created on CKB by proving a Mithril-certified Cardano seal mint, validated by the live
`bound_asset_v2` against the M2 44-byte checkpoint — **succeeded on Pudge** (tx `0x408d9c28…`).

## Live deployment

**CKB — Pudge:**
| Component | code / tx | constant |
|---|---|---|
| cv_deploy_v2 (M2 44-byte checkpoint verifier) | code `0x75b288f3`, deploy `0xa42e3942` | `CHIRAL_LCKP_TH 0xa055798e` |
| AVK epoch checkpoint advance 1323→1324 | `0x2519ee3c` | (also un-stuck live v1) |
| 44-byte `LCKP‖root‖height` checkpoint | published `0xe5e61bdc` (re-published each leap) | type hash = CHIRAL_LCKP_TH |
| burn_nullifier_registry | code `0x2b96f094`, genesis singleton `0x4e159851` | `CHIRAL_REG_TH 0xdc18fd56` |
| bound_asset_v2 | code `0xb33fc200`, **`V2_BOUND_CODE_HASH 0x4cc7ae86`** | LCKP+REG baked |
| **GENESIS CkbOwned cell** | **`0x408d9c28…`** | seal=08000078, state="bound-asset:demo:v1" |

**Cardano — preview:** v2 `binding_lock` `addr_test1wprutk2vjvuzgwlsvf956we9ssxqlyfl9jdeywrlv6tsyccz32l5e`,
seal policy `ec8d2c74…`, seal mint `08000078…` (Mithril-certified).

## What deploying caught that VM-testing never would have
1. **CKB-VM rejects RISC-V atomics** (opcode 0x2F → `InvalidInstruction`). The burn-gated-unlock binaries must be
   built `RUSTFLAGS="-C target-feature=-a,+forced-atomics"` + carry the `__sync_*` polyfill, then stripped.
2. **`hex32` didn't strip the `0x` prefix** — baking `CHIRAL_LCKP_TH=0x…` produced a byte-shifted hash
   (`[0, a0, 55, …]`). Fixed to strip `0x`/`0X`.
3. **`checkpoint_root` OOM'd on the 1 MiB secp256k1_data cell.** A lock dep_group expands into its referenced
   cells; `load_cell_data` on every cellDep loaded the 1 MiB secp table → heap abort → script error `-1`. Fixed
   to check the cheap 32-byte type hash FIRST and only load data for a trusted checkpoint. **This only manifests
   with a real secp-locked funding input — the in-VM tests used always-success funding, so it stayed hidden until
   the live tx.** Reproduced + fixed via `ckb-debugger --tx-file` on the dumped tx; regression-guarded by
   `v2vmtest/tests/genesis_real.rs` (faithful real-witness repro) + `mmr_diag.rs`.

The AVK was also a stale epoch (1323 vs 1324); advancing it un-stuck the live v1 lineage too.

## Status: end-to-end genesis proven; the leap TOGGLE is next
The genesis proves the hard part — the M2 checkpoint + Mithril cert + MMR proof + `bound_asset_v2` all validate
a real certified Cardano event on CKB. Remaining to exercise the full toggle:
- **S4 leap-to-cardano** (CkbOwned → CardanoBound): mint `seal_prime` one-shot on Cardano, consume the CkbOwned
  cell, recreate as CardanoBound. Cardano side ≈ `mint_seal_ours.py` (state-only datum); CKB side via the S4
  branch.
- **S5 leap-to-ckb** (CardanoBound → CkbOwned): the dangerous direction — owner-signed `LeapToCkb` seal-spend on
  Cardano (RC datum), then the CKB S5 leap binding the recipient + inserting the nullifier. Needs the pycardano
  `LeapToCkb` driver (`relayer/cardano_leap_v2.mjs` is the lib-agnostic plan; template = `transfer_seal_ours.py`).

Each leap step is one more certify-then-prove cycle (Mithril snapshot latency = the finality guarantee).

## On-chain orchestration (relayer/onchain/)
deploy_cv_deploy_v2 · advance_1324 (+ adversarial/advance_check_1324.py) · refresh_checkpoint_v2 (44-byte
publisher) · deploy_regcode · deploy_bound · reclaim (fund consolidation) · boundasset_v2 (genesis builder, with
`--dump` → ckb-debugger ReprMockTransaction). State: `deployed.json` / `chain_state.json` / `checkpoint_v2.json`
/ `v2_registry.json`. Keys: `~/.chiral/{pudge,preview}_relayer.key`.
