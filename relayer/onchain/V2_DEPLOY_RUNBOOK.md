# v2 leap deploy — DONE (Pudge + preview)

The v2 ownership-toggle leap is deployed and the end-to-end **genesis succeeded on Pudge** (tx `0x408d9c28…`).
Full status + hashes: `docs/LEAP_V2_GOLIVE.md`. This file is the operator log + how to re-run.

## Deployed (final)
- cv_deploy_v2 code `0xa42e3942`:0 · `CHIRAL_LCKP_TH 0xa055798e911a4f7ed074d5e1ee6273683e9a446c70d3e22adab680d70eea5b74`
- AVK checkpoint advanced 1323→1324 (`0x2519ee3c`); 44-byte checkpoint published via `refresh_checkpoint_v2.mjs`
- registry code `0x2b96f094`:0 + genesis singleton `0x4e159851`:0 · `CHIRAL_REG_TH 0xdc18fd562bca1834536c926ce8c9d94f608318c3a79a43959c0c46a84265a24e`
- bound_asset_v2 code `0xb33fc200`:0 · `V2_BOUND_CODE_HASH 0x4cc7ae86c48944f145dbe3c0f6bd44dda7be623c382e4b31c98feef97c1020b7`
- Cardano v2 binding_lock `addr_test1wprutk2vjvuzgwlsvf956we9ssxqlyfl9jdeywrlv6tsyccz32l5e`, seal mint `08000078…`
- State files: `deployed.json` (cv_*), `chain_state.json` (AVK 1324), `checkpoint_v2.json` (latest 44-byte ckpt),
  `v2_registry.json` (registryCode/registryGenesis/boundCode + CHIRAL_REG_TH).

## Build (production — REQUIRED flags)
The burn-gated-unlock binaries MUST be built atomic-free + stripped or the on-chain CKB-VM rejects them:
```
RUSTFLAGS="-C target-feature=-a,+forced-atomics" CHIRAL_LCKP_TH=0x.. CHIRAL_REG_TH=0x.. \
  cargo build --release --bin bound_asset_v2 --target riscv64imac-unknown-none-elf
riscv64-unknown-elf-strip -o <bin>.stripped <bin>      # ~139k -> ~64k; needed for capacity + symbol hygiene
```
`hex32` strips a `0x`/`0X` prefix, so the env may include it. (Earlier deploy baked a shifted hash because it
didn't — see GOLIVE bug #2.)

## Re-run
- Republish checkpoint: `node refresh_checkpoint_v2.mjs`
- Genesis: `node boundasset_v2.mjs genesis` (refreshes ckpt + aligns proof + creates the CkbOwned cell)
- Debug a failing tx: `node boundasset_v2.mjs genesis --dump` → `genesis_dump.json`, then
  `ckb-debugger --tx-file genesis_dump.json --script-group-type type --cell-type output --cell-index 0`
  (build the verifier with `-C debug-assertions=on` to get `ckb_std::debug!` output; `--bin` overrides the script).
- Fund consolidation (orphaned cells from failed deploys): `node reclaim.mjs --live`.

## Next: the leap TOGGLE (S4/S5) — see GOLIVE §"the leap TOGGLE is next"
S4 leap-to-cardano (mint seal_prime + CKB S4) then S5 leap-to-ckb (Cardano LeapToCkb seal-spend + CKB S5). The
S5 Cardano driver still needs writing (pycardano, from `cardano_leap_v2.mjs`'s plan / `transfer_seal_ours.py`).
