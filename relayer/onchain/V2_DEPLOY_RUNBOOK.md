# v2 leap go-live runbook (Pudge + preview)

Status: **staged, blocked on testnet capacity.** All code is built, verified, and committed; the constants
below are computed and fixed. Resume = fund the relayer, then run the stages in order.

## Fund first
- Pudge relayer address: `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqtn540xxh57xvqf3xxla9rjnrvqecsurgcdvfumt`
- Spendable now ≈ 21,244 CKB. Need ≈ 244k (code cells) + ~25k headroom ≈ **270k**. Add **~250k+**
  (one 300k Pudge faucet claim covers it). The rest of the balance is locked in the live v1 deploy — do NOT reclaim it.

## Fixed constants (already computed)
- cv_deploy_v2 (M2 44-byte) codeHash = `0x75b288f3774bfe553fc72895f940578214e2111208f5a85fb5c5dbf5e9017bf9`
- **CHIRAL_LCKP_TH** = `0xa055798e911a4f7ed074d5e1ee6273683e9a446c70d3e22adab680d70eea5b74`
  (= `Script{codeHash: 0x75b288f3…, hashType: "data1", args: "0x"}.hash()`)
- registry binary codeHash = `0x8b3c821b7a332dd424e00ae2204c4f07950b05ed64fd6987f661755fbd3f5177`
- empty SMT root = `0x5b7ed70cdcbaae36e29a122fb0b7d2414f4ca62a2103d76850e3f8ad1eed663c`

## Prerequisite: AVK epoch advance
On-chain AVK checkpoint is **epoch 1323**; Mithril is now **1324**. Before any checkpoint can be published
against a current cert, the AVK must be advanced 1323→1324 (the `cv_advance` / advance-cert flow). Verify the
checkpoint pipeline by attempting a refresh first; advance if it rejects on epoch.

## Stages
1. **cv_deploy_v2** (the M2 44-byte checkpoint verifier):
   `cd relayer/onchain && node deploy_cv_deploy_v2.mjs --live`  → records `cv_deploy_v2` in deployed.json.
2. **44-byte checkpoint**: upgrade `refresh_checkpoint.mjs` (or a v2 copy) to write
   `"LCKP" ‖ root(32) ‖ latest_block_number(8 LE)` (44 B) typed by `cv_deploy_v2`, extracting
   `latest_block_number` from the cert's `message_parts`. Publish → the leap's CHIRAL_LCKP_TH checkpoint.
3. **registry singleton + bound code** (relayer JS needs ccc; junction `node_modules` → `chiral-study/relayer/node_modules`):
   `cd spike/dex-integration/relayer && CKB_DEPLOYER_KEY=<pudge key> node deploy_v2.mjs --live --stage registry`
   → prints `CHIRAL_REG_TH`.
4. **rebuild + deploy bound**:
   `CHIRAL_LCKP_TH=0xa055798e… CHIRAL_REG_TH=<from step 3> cargo build --release --bin bound_asset_v2 \`
   `  --target riscv64imac-unknown-none-elf --manifest-path ../../burn-gated-unlock/Cargo.toml`
   then `CHIRAL_LCKP_TH=0xa055798e… CKB_DEPLOYER_KEY=<pudge key> node deploy_v2.mjs --live --stage bound`
   → prints `V2_BOUND_CODE_HASH`.
5. **Cardano binding_lock v2** on preview (preview key at `~/.chiral/preview_relayer.key`): deploy the v2
   `binding_lock` (with `LeapToCkb`), then drive `cardano_leap_v2.mjs` through a Cardano lib.
6. **End-to-end**: genesis → leap-to-CKB → CKB transfer → leap-to-Cardano → finalize, explorer-visible.

The v2 scripts are immutable/disjoint from v1 (new code hashes), so this lineage can coexist with the live v1
once funded — no teardown required.
