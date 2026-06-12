# Cosmos to CKB isomorphic binding: the keystone

This spike proves the hard, novel half of an isomorphic binding between a Cosmos chain and CKB: **CKB-VM
verifying a Tendermint commit**. It is the exact analog of the Mithril certificate verifier that makes the
CKB to Cardano bridge work, each chain verifies the other's consensus on-chain, no trusted relayer for safety.

This is NOT an HTLC swap. It is the real bridge mechanism: on-chain mutual verification, which is what lets one
asset be represented and moved across chains rather than swapped.

## What CKB verifies

A Tendermint block is final when more than 2/3 of the validator set's voting power signs it. Each validator
signs a canonical vote with ed25519. So the CKB-VM script (`tendermint_verify.rs`) does, for one block:

1. Reconstruct each precommit's canonical vote bytes:
   `VoteSignBytes = MarshalDelimited(CanonicalVote{type=precommit, height, round, block_id, timestamp, chain_id})`.
2. ed25519-verify each signature against that validator's pubkey.
3. Sum the voting power of the valid signatures and require `3 * signed > 2 * total`.

The one encoding subtlety, pinned off-chain against real data first, is that `round = 0` is omitted (proto3
zero-omission) and each precommit carries its own timestamp.

## What was proven

- **Encoding nailed off-chain** (`verify_offchain.mjs`): against a real cosmoshub-4 commit (height 31539885,
  180 validators), all 178 committed precommits ed25519-verify and sum to 100% of committed power, well over
  2/3. With `round` included instead of omitted, 0 verify, that is how the rule was found.
- **Verified in CKB-VM** (`tendermint_verify.rs`, built in WSL; `build_witness_mock.mjs` packs the same real
  data into the witness): the genuine commit gives `Run result: 0` at **343.8M cycles**, comfortably under
  CKB's ~3.5B block limit. A tampered block hash gives `Run result: 20` (every signature over the real hash
  now fails, so power falls below 2/3). Fail-closed.

So verifying a 180-validator Tendermint commit in CKB-VM costs ~344M cycles. Affordable, and it scales roughly
linearly with the number of signatures checked (you can stop once 2/3 is reached).

- **Full "tx in a final block" verifier** (`tendermint_inclusion.rs`, `build_inclusion_mock.mjs`): extends the
  keystone to the complete chain in one CKB-VM script. It (1) reconstructs `block_hash` as the Merkle root of
  the 14 header leaves and parses `data_hash` from leaf[6], so `data_hash` is BOUND not trusted (any faked leaf
  changes `block_hash` and the commit signatures then fail), (2) verifies the commit over that reconstructed
  `block_hash`, (3) verifies a tx inclusion proof `computeRoot(index, total, leafHash(SHA256(tx)), aunts) ==
  data_hash`. On real cosmoshub-4 data (height 31539885, a 2-tx block): `Run result: 0` at **344.5M cycles**;
  a tampered tx gives `Run result: 21` (its leaf no longer reaches `data_hash`). The header and inclusion
  encodings were pinned off-chain first (`reconstruct_header.mjs`, `verify_tx_inclusion.mjs`); the tx-tree leaf
  is `leafHash(SHA256(tx))`, not the raw tx.

This is the complete CKB-verifies-Cosmos direction: CKB-VM proves on-chain that a specific Cosmos transaction
landed in a finalized block, for ~344M cycles.

- **Validator-set anchoring** (`reconstruct_valset.mjs`, then in `tendermint_inclusion.rs`): the signing set is
  no longer trusted from the witness. The verifier computes `validators_hash = MerkleRoot([SimpleValidator(v)])`
  from the provided set and requires it to equal both the header's `validators_hash` (leaf[7], itself bound to
  `block_hash`) AND a PINNED trusted anchor passed in (in a live deploy this anchor lives in the bridge cell's
  state). On real data: with the real anchor, `Run result: 0` (350.5M cycles, the valset Merkle adds ~6M); with
  a wrong anchor, `Run result: 9` (the set is rejected). So a relayer cannot fabricate a validator set; it must
  supply the chain's real set, which must match the pinned trusted set. The encoding (`SimpleValidator =
  pub_key(PublicKey{ed25519}) ‖ voting_power`) matched the real `validators_hash` on the first try. The anchor
  is the lock's script args, so a deployed cell commits to its trust anchor instead of reading it from the
  witness.
- **LIVE on CKB Pudge** (`live_cosmos_verify.mjs`): `tendermint_inclusion` is deployed (codeHash `0xf41efc6e`,
  dep tx `0xea85cbef`). A cell was locked under the real cosmoshub-4 validator-set anchor (`0x404657c8`) and
  then UNLOCKED by supplying the Cosmos tx-inclusion proof in the witness (unlock tx `0x18f519b6`). The spend
  succeeded, so the live CKB-VM verified on-chain that a real Cosmos tx is in a finalized block. This is the
  CKB side of the binding, live, not just ckb-debugger.

## How to run

```
cd spike/cosmos-ckb && npm install
node fetch_commit.mjs                 # pull a fresh cosmoshub-4 commit + validator set
node verify_offchain.mjs              # off-chain: all committed precommits verify, > 2/3 power
wsl: cd ../burn-gated-unlock && RUSTFLAGS="-C target-feature=-a,+forced-atomics" cargo build --release --bin tendermint_verify
node build_witness_mock.mjs           # pack the real data into the CKB witness
wsl: ckb-debugger --max-cycles 5000000000 --tx-file tm_mock.json --script-group-type lock --cell-type input --cell-index 0   # 0
TAMPER=1 node build_witness_mock.mjs  # then ckb-debugger tm_mock_bad.json -> 20 (fail-closed)
```

## Where this sits, and what is left

The CKB-verifies-Cosmos direction is now complete at the proof level: CKB-VM proves a specific Cosmos tx is in
a finalized block (commit + header reconstruction + tx inclusion), `tendermint_inclusion.rs`, on real data.
What remains to reach a full live Cosmos to CKB isomorphic binding:

- **Validator-set lineage:** the BINDING is done (the set must hash to the header's `validators_hash` and to a
  pinned trusted anchor, see above). What remains is the ADVANCEMENT: as validators rotate, move the pinned
  anchor forward. The header already binds `next_validators_hash` (leaf[8]), so sequential advancement is
  adopting leaf[8] after each verified block; cross-epoch gaps need the skipping check (>1/3 overlap of the
  trusted set within the trust period). The anchor lives in the bridge cell's state, so advancement is a
  state-update operation, the direct analog of the AVK epoch advance in the Mithril leg.
- **The reverse verifier:** a CosmWasm contract that verifies the existing CKB-state proof (Cosmos verifies
  CKB), reusing the bridge's CKB-state circuit.
- **Asset + registry wiring:** reuse the chain-agnostic asset binding and the replay-once registry for the
  Cosmos to CKB pair, plus a deploy of `tendermint_inclusion` as a live code cell.

The keystone, the piece that was unknown and could have killed the design (can CKB-VM verify Tendermint
affordably, and bind a real tx to it), is done at ~344M cycles. Ethereum, Stellar, and Solana are backlogged
behind this template.

```
# full verifier
wsl: cargo build --release --bin tendermint_inclusion
node build_inclusion_mock.mjs         # header leaves + commit + tx inclusion proof for a real block
wsl: ckb-debugger --max-cycles 5000000000 --tx-file inc_mock.json --script-group-type lock --cell-type input --cell-index 0   # 0
TAMPER=1 node build_inclusion_mock.mjs  # then ckb-debugger inc_mock_bad.json -> 21 (tx not in block)
```
