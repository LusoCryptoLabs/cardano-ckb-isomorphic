# Chiral — LIVE end-to-end (our keys), Cardano preview ⇄ CKB Pudge

A complete, real Cardano→CKB isomorphic-binding round-trip, driven by the relayer under our own funded
keys, against an authenticated Mithril light client we built from genesis with **live** data. Every CKB
step re-verifies real Mithril-certified Cardano data in CKB-VM. Keyless off-chain (Koios + public Mithril
aggregator); the only secrets are our two testnet keys in `~/.chiral/`.

## Keys (outside the repo, gitignored)
- CKB Pudge:      `~/.chiral/pudge_relayer.key`   addr `ckt1qzda0cr0…dvfumt`  (funded ~300k CKB)
- Cardano preview `~/.chiral/preview_relayer.key`  addr `addr_test1vqklgnr…0y8mvq` (funded 10k tADA)

## Authenticated light client (CKB Pudge, our key)
Built genesis(epoch 1319) → advance ×4 → epoch-1323 AVK checkpoint, each verifying a real Mithril cert in-VM.
- cv_advance code:  `0xe877a802…`  deploy tx `0x422b1db1…`   (type-hash `0x59efd99d` = ADV_TYPEHASH)
- cv_deploy code:   `0xdfc0aad0…`  deploy tx `0x5ffd669a…`   (checkpoint type-hash `0x855231b3`)
- epoch-1323 AVK checkpoint cell: `0x0848f94e…`
- authenticated tx-set checkpoint: refreshed per leap (re-published at the current Mithril root each step)

## BoundAsset verifier (our instance, CKB Pudge)
Rebuilt from `spike/phase1/bound_asset_unified.rs` with `LCKP_TYPE_HASH` = our checkpoint type `0x855231b3`,
`lock_addr` widened to the full 29-byte address, and built `-C target-feature=-a,+forced-atomics` with
`__sync_*` polyfills (CKB-VM has no A-extension). type args = `seal_policy(28) ‖ lock_addr(29)`.
- code: `0xca24efc3…`  deploy tx `0xbd1b2c4d…`

## Cardano instance (preview, our key) — fresh seal
- seal policy (one-shot): `1e7efe1770e7f800455fe902301252602e5a4d4945092e9960f6f19c`
- binding_lock: `addr_test1wru9eafd2wkjpwhwrvth3dmuq5n564839yeww5cljmwwyzq3c55x5`
- owner vkh: `2df44c71a4312463ba31315c5aa7725b6ad44cd544a055a3dde915a6`

## The live round-trip (all on-chain, confirmed)
| step | Cardano (preview) | CKB (Pudge) | in-VM check |
|---|---|---|---|
| mint seal | `c07d8620…` | — | — |
| GENESIS (bind) | (certified) | `0xc559fbcc…` | seal-mint ∈ checkpoint root + seal@lock + commitment |
| transfer seal | `301a4f2d…` | — | — |
| TRANSITION | (certified) | `0x45d5f442…` | transfer ∈ root + old seal consumed + new commitment |
| unbind seal | `0d703ac1…` | — | — |
| FINALIZE (leap-out) | (certified) | `0x03ac82a2…` | unbind ∈ root + seal consumed + NOT recreated → bound cell destroyed |

## Run it (the relayer drives everything)
```
# Cardano side (mint / transfer / unbind a seal) — keyless via Koios + native aiken
cd cardano/binding
CHIRAL_PREVIEW_KEY=~/.chiral/preview_relayer.key AIKEN=~/.aiken/bin/aiken python3 mint_seal_ours.py
#   ... transfer_seal_ours.py / unbind_seal_ours.py for the next legs

# CKB side (genesis / transition / finalize) — refreshes checkpoint, builds proof, sends tx
cd relayer
RELAYER_KEY=~/.chiral/pudge_relayer.key node onchain/boundasset.mjs genesis    <cardano_txid> [state]
RELAYER_KEY=~/.chiral/pudge_relayer.key node onchain/boundasset.mjs transition <cardano_txid> [state]
RELAYER_KEY=~/.chiral/pudge_relayer.key node onchain/boundasset.mjs finalize   <cardano_txid>

# Or via the HTTP service a front-end calls:
RELAYER_KEY=~/.chiral/pudge_relayer.key python service.py            # :8787
#   GET  /api/config                        -> live instances above
#   POST /api/cardano-to-ckb/submit {mode, tx, state}  -> drives the BoundAsset tx, returns {ckb_tx}
```

## Notes / remaining (mainnet gates, not testnet blockers)
- Wait between each Cardano event and its CKB step for Mithril certification (30–90 min on preview).
- The checkpoint is refreshed per leap (re-published at the current root); the AVK is valid for epoch 1323.
- Mainnet still requires: independent audit, a real trusted setup/ceremony for the CKB→Cardano (Groth16)
  leg, and a hosted monitored relayer daemon. This is a testnet prototype.
