# STM-pin redeploy: staged + ready (run at audit / mainnet time)

The on-chain CKB Mithril verifier fix (`SEC_STM_QUORUM_PIN.md`) is **in source, validated, and staged**. This
doc is the turnkey package so the live redeploy is push-button when it is actually needed. It is deliberately
**NOT executed yet**: the live stack is testnet with no value at risk, the source fix already closes the hole for
anyone who reads/builds the code, and the security doc orders this redeploy **after** a professional audit (the
audit validates `PINNED_GENESIS` and the fix against the actual binary). Executing it now costs ~270k CKB and
tears down the working demo for zero testnet benefit. So: stage now, deploy with/after the audit.

## What it fixes (one line)

The deployed verifiers read the STM quorum `k`/`total` from the witness; a single compromised Mithril SPO key
could forge a `k=1` cert and pass verification. The pinned binary rejects `ct.k != STM_K`, bounds lottery
indices to `STM_M`, and anchors `total`. Preview params pinned: `STM_K=1944`, `STM_M=16948`. Validated:
adversarial suite 28/28 (Battery D = 5 STM-pin cases), real epoch-1324 cert ACCEPTS, four forged variants
REJECT (`SEC_STM_QUORUM_PIN.md`).

## Build the pinned binaries (reproducible)

```
cd spike/light-client-cell/cert-verify
# deploy/checkpoint mode (default features)
cargo build --release --target riscv64imac-unknown-none-elf
riscv64-unknown-elf-strip -o /tmp/cv_deploy_pinned.bin target/riscv64imac-unknown-none-elf/release/cert_verify
# advance mode
cargo build --release --target riscv64imac-unknown-none-elf --features advance
riscv64-unknown-elf-strip -o /tmp/cv_advance_pinned.bin target/riscv64imac-unknown-none-elf/release/cert_verify
```

codeHash = blake2b-256 personalized `ckb-default-hash` of the stripped binary. Built 2026-06-12 (WSL ChiralSP1,
cargo 1.96, riscv64-unknown-elf-strip):

| cell | NEW code hash (pinned) | size | replaces (live) |
|---|---|---|---|
| `cv_deploy_v2` | `0x7db9b5ca06e0fd4df9713feb2e33f1b7936856abbf0bee9a68dfc8be9a965d5e` | 104,808 B | `0x75b288f3774bfe553fc72895f940578214e2111208f5a85fb5c5dbf5e9017bf9` |
| `cv_advance` | `0x6e361ce4bf234caaa31187ec399eed4cc59d8065b7a3a9978a901b0c034c8039` | 105,672 B | `0xe877a8028eac379e962a596671d1cd918aceddfa4c4cd78163168ba3b533ac55` |

(The exact code hash is strip/toolchain-dependent; recompute from the freshly built binary at deploy time and
bake THAT value. New code hashes -> new type hashes -> the downstream re-bakes below.)

## Funding plan (no need to spend the live verifiers)

Relayer `0x7a971a3b…` (`node relayer/onchain/fund_assess.mjs` to refresh): ~891k CKB total, but only ~19.5k is
plain-spendable; the rest is locked in 88 code cells. The two new `cv_*` cells need ~211k CKB. Fund by reclaiming
(spending) cells that are NOT part of the live Cardano-CKB stack:

| reclaim (outpoint :0) | frees | what it is |
|---|---|---|
| `0xc68edab9…` + `0x8350102e…` | ~145k CKB | orphaned Cosmos `catom_mint_owner` code (archived leg, see `archive/cosmos-multichain`) |
| `0x0b08f773…` | ~22k CKB | orphaned Cosmos `xosmo_burn_receipt` code |
| `0x5ffd669a…` | ~104k CKB | superseded old `cv_deploy` (non-v2), not referenced by the live toggle |
| plain cell | ~19.5k CKB | — |

That is ~290k CKB without touching the live `cv_advance` `0x422b1db1…`, `cv_deploy_v2` `0xa42e3942…`, or
`bound_asset_v2` `0xf135e9ef…`. Reclaim via `reclaim_targeted.mjs`-style spends (cell_deps + completeFeeBy, never
a blind scan past the 10MB RPC cap). Verify each reclaim target is not a live cell dep before spending.

## Runbook (the destructive cascade, in order)

1. **Build + hash** the pinned `cv_deploy_v2` and `cv_advance` (above); set `deploy_cv_deploy_v2.mjs::EXPECT` to
   the new `cv_deploy_v2` code hash.
2. **Reclaim** the orphaned/superseded cells (funding plan) into plain capacity.
3. **Deploy** the new `cv_advance` then `cv_deploy_v2` code cells (~105k CKB each).
4. **Re-genesis the AVK chain** from `PINNED_GENESIS` under the NEW `cv_advance`, then advance epoch-by-epoch
   1319 -> 1324. Each advance is a live CKB-VM tx (~165M cycles) needing a real Mithril cert witness transcoded
   from the live aggregator (`relayer/relay.py` + `transcode.py` + `produce_witness.py`). Mithril aggregator must
   be reachable.
5. **Re-bake + redeploy `bound_asset_v2`** with the NEW LCKP type hash (derived from the new `cv_deploy_v2`
   checkpoint type), then re-bake the new `bound_asset_v2` hash into the seal genesis.
6. **Re-genesis the seal + the bound cell**, then re-establish the live toggle state
   (`leap_orchestrator.mjs`).
7. Update `relayer/onchain/deployed.json`, `BRIDGE_STATUS.md` §1/§2, and `SECURITY_FIXES.md` (mark #3 live).

## Pre-conditions to satisfy first (the audit ordering)

Per `SEC_STM_QUORUM_PIN.md` and `BRIDGE_STATUS.md` §C, before this goes live a professional cryptographic audit
should (1) confirm + bound the fix, (2) run the actual binary against adversarial witnesses, (3) verify
`PINNED_GENESIS` against Mithril's genesis certificate, (4) confirm the BLS hash-to-curve domain separation and
the mainnet STM params (`CHIRAL_STM_K`/`CHIRAL_STM_M` differ on mainnet). Deploying ahead of that risks redoing
the whole cascade. This is a mainnet gate; on testnet there is no value at risk.
