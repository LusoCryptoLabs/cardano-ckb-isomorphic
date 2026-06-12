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

This is verifier 1 of 2 for the binding, and only its consensus core. To reach a full Cosmos to CKB isomorphic
binding:

- **Merkle inclusion proof:** after proving the block is final, prove a specific event or tx is in it (the
  header's data/app hash plus the Tendermint Merkle proof). That binds an actual Cosmos action to the CKB side.
- **Validator-set lineage:** pin a trusted validator set and advance it as it rotates (the analog of the AVK
  epoch advance in the Mithril leg), so the script trusts a known set rather than a witness-supplied one.
- **The reverse verifier:** a CosmWasm contract that verifies the existing CKB-state proof (Cosmos verifies
  CKB), reusing the bridge's CKB-state circuit.
- **Asset + registry wiring:** reuse the chain-agnostic asset binding and the replay-once registry for the
  Cosmos to CKB pair.

The keystone, the piece that was unknown and could have killed the design (can CKB-VM verify Tendermint
affordably), is done. Ethereum, Stellar, and Solana are backlogged behind this template.
