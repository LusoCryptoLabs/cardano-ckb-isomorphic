# Live deployment status (Cardano preview ⇄ CKB Pudge)

> The live path for a real isomorphic-binding leap. Updated as steps land.

## ✅ Step 1 — Leap-in: seal minted on Cardano preview (DONE, on-chain)

The binding lock + seal NFT were parameter-applied and a **real seal** was minted on preview
(`cardano/binding/deploy_seal.py`):

| | |
|---|---|
| seal policy | `8855af1be1fd48ee096b72e91bee858db51b9ab75e866540c8647674` |
| seal name | `SEAL` |
| binding_lock addr | `addr_test1wqwthgsg3cjfsr255gamvh0z683r8gekejk9ka0mqxkdyuqtyp3vw` |
| owner vkh | `4cf25d6a752890b5…` (coordinator) |
| S0 (genesis state) | `bound-asset:demo:v1` |
| commitment | `cad8d630…` = `blake2b256(S0)` |
| **seal mint tx** | **`83dd51d2f3ae6c6529a2f6feda2d85d1a27efa5bfafc6a34c6c595d203f25e15`** (block 4,355,257) |

Confirmed on-chain: the seal NFT sits at the binding lock with its inline `SealDatum`. This is the
genesis of a bound asset: ownership = this seal UTxO; the commitment binds it to CKB state `S0`.
(`deployed/preview/seal-instance.json`.)

## ✅ Step 2 — Mithril certification (DONE)

Seal-mint tx `83dd51d2…` is Mithril-certified: cert `c8a6986f…`, certified tx-set root
`30a3465e…`. (Host-verified with mithril-common.)

At capture time the seal tx (block 4,355,257) was **just above** the Mithril certified tip
(4,355,249) — `non_certified`. It certifies once Mithril aggregates past that block (the
certification-latency gap we measured). No action; the relayer waits.

## ✅ Step 3 — Bound cell minted on CKB Pudge (DONE — CARDANO→CKB CLOSED LIVE)

The `genesis_mint` type script (embedding the real MKMapProof for `83dd51d2…`) was deployed on
Pudge (`0xd2a650ec…`) and a **bound cell was minted** (`0xab2f93a7…`, committed). The type script
**ran on the live node** and verified, in-script: the Mithril MKMapProof that the seal-mint tx is in
the certified tx-set root `30a3465e…`, AND that the seal `SealDatum` commitment binds `S0`. A real
Mithril-certified Cardano event drove a real CKB bound-cell creation. (deployed/pudge/.)

## ✅ Step 4 — PRODUCTION MODEL LIVE: unified verifier + witness proof + real transition (DONE)

Phase 1's keystone now ran **live on Pudge**: **one** deployed `BoundAsset` verifier
(`bound_asset_unified.rs`), the per-transfer proof in the **witness**, the certified tx-set root in
a **light-client checkpoint cell** (cellDep, `"LCKP"||root`). Scripts in `deploy/pudge/`;
hashes in `deployed/pudge/unified-instance.json`.

| | tx | what the live node verified in-script |
|---|---|---|
| unified verifier deploy | `0xf8644bd3…` (code_hash `0x42f74fbc…`, 47,248 B) | — deployed once, shared by every bound cell (reclaimed the demo code cell `0x9eb56c3b` to fund it) |
| **genesis** (bind) | `0x0318d35f…` (block 21,339,914) | MKMapProof: seal-mint `83dd51d2` ∈ certified root `30a3465e` (from the checkpoint cell) ∧ `commitment == blake2b256(S0)`; 1,136-B proof in witness `input_type` |
| **transition** (consume old → new) | `0x94d0620f…` (block 21,339,956) | **consumed the genesis bound cell** ∧ MKMapProof: transfer `a98b6636` ∈ root `5acd33ab` ∧ the certified transfer **consumed the OLD seal** (`83dd51d2:0`) ∧ `commitment(new SealDatum) == blake2b256(S1)`; 1,173-B proof in witness |

State advanced `bound-asset:demo:v1` → `bound-asset:demo:v2 owner=bob`; seal advanced `83dd51d2` →
`a98b6636`; the genesis cell is **spent**. This is the real per-transfer model — **not** create-only,
**not** a fresh 45 KB code cell per step — verified on the live node against real Mithril data.
**Phase 1 is complete.**

### legacy (the earlier embedded-proof demo — superseded by the unified model above):

Once the seal-mint tx is certified: fetch the Mithril cert + the MKMapProof for tx `83dd51d2…`,
and mint the bound cell on Pudge with the genesis `BoundAsset` rule, which runs the **wired check**
(`spike/bound-asset/bound_asset_leap.rs`, proven in CKB-VM): `cardano_tx_is_certified(seal-mint tx)`
∧ it creates the seal at `binding_lock` ∧ commitment binds `S0`. → the bound cell is live.

## ✅ Step 5 — Transfer + leap-out (DONE — see the sections below)

> The transfer and leap-out described here as "then" were completed. Transfer: spend the seal on
> preview (`Transfer`, new commitment) → cert → CKB transition `0x94d0620f` (consumed the genesis
> cell). Leap-out: `Unbind` `6c729ea6` on preview → CKB finalize `0x795f4bb9`. Details in the
> "leap-out FINALIZE : NOW CLOSED LIVE" section below.

## Note (historical)
Steps 3–5 needed the relayer + witness/molecule plumbing + waiting out the certification latency,
but no new in-script cryptography — the verifier, the wired leap, the Conway parse, and the Cardano
lock were all built and tested. That integration is done; the full lifecycle ran live (below).


## Step 4 — leap-out : VERIFIED, final spend stranded by ephemeral key (not a crypto gap)
The Cardano leap-out is DONE on-chain: seal Unbind `6c729ea6..` confirmed (preview block 4,355,361),
the seal NFT released to a plain address. The CKB leap-out FINALIZE is PROVEN in CKB-VM — 205,581 cycles
on the REAL certified Unbind (MKMapProof: Unbind ∈ cert root `0bc33aa8..` ∧ old seal `83dd51d2` consumed
∧ seal NOT recreated at binding_lock ⇒ bound cell may be destroyed). Finalize verifier deployed
(`0x97ca700d`), bound cell staged & LIVE under it (`0xc40d4a39:0`, 206.8 CKB).
THE ONLY UNSUBMITTED TX is the finalize spend, and it is blocked by OPS, not crypto:
1) at deploy time it was ~0.02 CKB dust-short, and
2) the staged bound cell's lock is the deploy's **gas key** (secp256k1 args `0x7bbf9723..`), held in
   `deploy/pudge/testnet-pq-common.mjs` which was **never committed** — so it was lost when that
   ephemeral container was reclaimed. The cell is now unspendable by us.
Lesson: commit/escrow deploy keys. To DEMO the final spend live: redeploy a fresh instance with a
committed key (a funded Pudge key exists) and run the lifecycle end-to-end (re-runs the JS tooling +
Mithril cert latency). The protocol, the in-VM finalize verification, and every other on-chain step are
complete; this is a key-custody artifact of the sandbox, and M2/STARK is NOT involved.

## Step 4 — leap-out FINALIZE : NOW CLOSED LIVE on Pudge (the stranded spend is done)
The previously-stranded finalize spend was completed on-chain with a fresh, faucet-funded key, reusing the
already-deployed finalize verifier (`0x97ca700d`) as a cellDep and recreating the light-client checkpoint
cells from the committed proof data (p1t_hex/p1f_hex). All three txs committed on Pudge:
- checkpoint cells (transfer root 5acd33ab @:0, unbind root 0bc33aa8 @:1): `0x8d637bd3…`
- bound cell genesis (seal a98b6636 v2, under the finalize verifier): `0x8de55d8b…` — verifier accepted the
  certified-transfer bind proof in-script.
- **LEAP-OUT FINALIZE**: `0x795f4bb90847ed1cd3be19c6fa2dbdf34ed00595a1ed395042687c50bbc88d7c` (block
  21,358,183). The verifier ran on the live node and accepted the destroy-proof against the REAL certified
  Unbind `6c729ea6`; it **consumed the bound cell** (`0x8de55d8b:0`, now dead) and produced **only plain
  cells** (no type script) — the asset is **unbound**. Independently re-confirmed via RPC.
=> The Cardano→CKB binding leg's leap-out is now demonstrated end-to-end on-chain (genesis bind →
transition → leap-out finalize), key-custody issue resolved for the demo. (Original stranded cell
`0xc40d4a39:0` remains unspendable — its ephemeral key is still lost — but it is no longer the blocker.)
