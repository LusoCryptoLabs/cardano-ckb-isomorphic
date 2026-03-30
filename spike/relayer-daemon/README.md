# Permissionless relayer daemon (skeleton)

`relayer.mjs` — ANYONE can run this; it holds no special authority. It watches CKB (Pudge) for relay-escrow
deposits and, when the bridge event is proven (the AUTHENTICATED tx-set checkpoint exists), relays them by
submitting the proof-gated completion tx, keeping the escrow as its fee. The validators are proof-gated (no
admin keys), so a relayer cannot forge — only fail to relay, and the depositor self-relays/refunds.

    RELAYER_KEY=/path/to/pudge.key node relayer.mjs --once            # one pass
    RELAYER_KEY=/path/to/pudge.key node relayer.mjs --interval=15000  # loop
    # run from a dir with @ckb-ccc/core installed (npm i @ckb-ccc/core)

## DEMONSTRATED LIVE on Pudge
One `--once` pass discovered **4 escrow deposits and relayed all of them** permissionlessly — relay txs
`0xdf319755`, `0x2785ba5c`, `0xda9950ef`, `0x707c2704` (committed) — each collecting the escrow as its
reward, with no special authority. Anyone running it does the same; multiple relayers race for the fee.

The on-chain mechanics it drives are all proven live (docs/TESTNET_LOG.md §C–§F): escrow relay `0x6e9a291e`,
timeout refund `0x78cf1071`, authenticated checkpoint `0xe4e1b0c6`, burn-gated unlock `0xe6ea066a`.



## Two-chain watch (added)
The daemon now also WATCHES the Cardano side: each pass it fetches the latest Mithril CardanoTransactions
certificate from the live preview aggregator and confirms the certified tx-set root + that it's signed.
Demonstrated pass:
- `[cardano] latest Mithril cert: root 14ae311460b07b7a.. epoch 1321 block 4359104 signed=true`
- then relayed the CKB deposit `0x76161e94` -> `0xc42668ae` (205 CKB reward).
So one process observes the live certified state on Cardano AND relays on CKB. (Production then ADVANCES the
on-chain light-client checkpoint to each new cert via AdvanceCert/TxSetCert — which requires parameterizing
those verifiers to take the cert via witness instead of the current fixture; that's the next step.)

## What production extends (this is a skeleton)
- Watch BOTH chains (CKB headers + the Mithril aggregator), not just one escrow lock.
- Build the Groth16 proof (CKB→Cardano) and advance the light-client checkpoint by verifying the Mithril
  cert (Cardano→CKB) — instead of assuming the authenticated checkpoint is already on-chain.
- Handle Mithril certification latency, reorgs, retries, fee markets, and run its own CKB indexer/node
  (the public `findCellsByLock` indexer is slow/rate-limited).
- Monitoring/alerting; multiple independent relayers race for the fee (permissionless by construction).
