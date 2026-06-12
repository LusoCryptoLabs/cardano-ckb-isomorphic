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
- **Validator-set advancement** (`tendermint_advance.rs`, `build_advance_mock.mjs`): Cosmos validators rotate,
  so the pinned anchor must follow them. The advance script (args = `current_anchor || new_anchor`) checks that
  the provided set hashes to `current_anchor` (= header `validators_hash`), that > 2/3 of it signed the block,
  and that `new_anchor` equals the block's `next_validators_hash` (header leaf[8]). On real data: a valid
  transition gives `Run result: 0`; a wrong new anchor gives `Run result: 21`. This is sequential advancement,
  the analog of the AVK epoch advance; the bridge cell holds the anchor and a tx advances it.

- **The asset layer: χATOM mint** (`catom_mint.rs`, `build_catom_mock.mjs`): the Cosmos-leg mirror of
  `xada_mint`. χATOM is wrapped ATOM on CKB (an xUDT-style token whose policy is this type script), and a mint
  is gated NOT on an admin key but on a finalized Cosmos escrow. The escrow is a bank `MsgSend` that locks ATOM
  into a fixed account, carrying the 32-byte CKB recipient lock-hash (hex) in the tx memo. The script composes
  the inclusion verifier above with a protobuf `MsgSend` reader (`TxRaw -> TxBody -> MsgSend + memo`, real Cosmos
  proto field numbers) and enforces: `to_address` == the pinned escrow, `denom` == the pinned denom,
  `Coin.amount` == χATOM minted (1:1 conservation), `memo` == hex(the lock-hash all minted χATOM is locked to);
  then it nullifies the certified Cosmos tx hash replay-once (leg tag `0x04`), reading the trusted validator-set
  anchor from a `TMCP` checkpoint cell-dep. The protobuf reader is the only new code vs the two parents and is
  host-unit-tested (independent encoders; the full parse, the type-URL guard, decimal-amount + overflow, the
  hex-32 memo, varint field-skipping). The whole script is then validated end-to-end in CKB-VM
  (`build_catom_mock.mjs` builds a synthetic single-validator Tendermint block whose one tx is the escrow
  `MsgSend`, so a chosen escrow/amount/memo sits in a self-signed block; the Tendermint encodings themselves are
  already proven against real cosmoshub data above): the valid mint gives `Run result: 0` at ~2.5M cycles, and
  four adversarial cases fail closed with distinct codes, wrong minted amount `24`, wrong recipient `28`, wrong
  validator-set anchor `9`, non-`MsgSend` `30`. So the Cosmos -> CKB direction is complete and verified offline:
  CKB verifies a Cosmos escrow is final, parses it in-VM, and mints wrapped ATOM bound 1:1 with replay-once.

## How to run

```
cd spike/cosmos-ckb && npm install
node fetch_commit.mjs                 # pull a fresh cosmoshub-4 commit + validator set
node verify_offchain.mjs              # off-chain: all committed precommits verify, > 2/3 power
wsl: cd ../burn-gated-unlock && RUSTFLAGS="-C target-feature=-a,+forced-atomics" cargo build --release --bin tendermint_verify
node build_witness_mock.mjs           # pack the real data into the CKB witness
wsl: ckb-debugger --max-cycles 5000000000 --tx-file tm_mock.json --script-group-type lock --cell-type input --cell-index 0   # 0
TAMPER=1 node build_witness_mock.mjs  # then ckb-debugger tm_mock_bad.json -> 20 (fail-closed)

# the χATOM mint (Cosmos -> CKB asset layer)
wsl: cd ../burn-gated-unlock && RUSTFLAGS="-C target-feature=-a,+forced-atomics" cargo build --release --bin catom_mint
wsl: cargo test --bin catom_mint --target x86_64-unknown-linux-gnu   # the protobuf MsgSend reader: 4 host tests
node build_catom_mock.mjs             # synthetic block + escrow MsgSend + checkpoint dep + registry input
wsl: ckb-debugger --max-cycles 5000000000 --tx-file catom_mock.json --script-group-type type --cell-type output --cell-index 0   # 0
BADAMOUNT=1 node build_catom_mock.mjs # then ckb-debugger catom_mock_badamount.json -> 24 (also BADRECIP 28 / BADPIN 9 / BADTYPEURL 30)
```

## Where this sits, and what is left

The CKB-verifies-Cosmos direction is now complete at the proof level: CKB-VM proves a specific Cosmos tx is in
a finalized block (commit + header reconstruction + tx inclusion), `tendermint_inclusion.rs`, on real data.
What remains to reach a full live Cosmos to CKB isomorphic binding:

- **Validator-set lineage:** binding (anchor) and sequential advancement are both done (`tendermint_advance`,
  above). What remains is the SKIPPING variant for big height gaps (verify the block's commit has > 1/3 overlap
  of the trusted set within the unbonding/trust period, then adopt the block's own set), which avoids
  processing every block. Sequential proves the mechanism; skipping is the throughput optimization.
- **The reverse verifier:** DONE. A CosmWasm contract (`spike/cosmwasm-ckb`) verifies the existing CKB-state
  Groth16 proof (Cosmos verifies CKB), in production host-function form, bound to a named CKB event, with a
  replay-once registry.
- **Asset + registry wiring:** DONE for the Cosmos -> CKB direction. `catom_mint` mints wrapped ATOM on a
  finalized Cosmos escrow, bound 1:1, replay-once (validated end-to-end in CKB-VM, above). `tendermint_inclusion`
  is already deployed as a live code cell on Pudge.
- **What remains needs external resources / a design decision:** the live CosmWasm testnet deploy (a funded
  Neutron/Osmosis account), the CKB -> Cosmos release leg (needs a CKB-burn proof committing a Cosmos recipient,
  a different circuit instance), and the SKIPPING light-client variant (throughput, not safety).

The keystone, the piece that was unknown and could have killed the design (can CKB-VM verify Tendermint
affordably, and bind a real tx to it), is done at ~344M cycles, and the full Cosmos -> CKB mint is now verified.
Ethereum, Stellar, and Solana are backlogged behind this template.

```
# full verifier
wsl: cargo build --release --bin tendermint_inclusion
node build_inclusion_mock.mjs         # header leaves + commit + tx inclusion proof for a real block
wsl: ckb-debugger --max-cycles 5000000000 --tx-file inc_mock.json --script-group-type lock --cell-type input --cell-index 0   # 0
TAMPER=1 node build_inclusion_mock.mjs  # then ckb-debugger inc_mock_bad.json -> 21 (tx not in block)
```
