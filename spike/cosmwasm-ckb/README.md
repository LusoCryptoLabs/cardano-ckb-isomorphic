# Cosmos verifies CKB: the reverse leg of the binding

This spike proves the other half of the Cosmos <-> CKB isomorphic binding: a Cosmos chain verifying CKB. The
forward half (`spike/cosmos-ckb`) had CKB-VM verify a Tendermint commit; here a CosmWasm contract verifies the
bridge's CKB-state proof. Together they are the mutual on-chain verification that makes an isomorphic binding,
not an HTLC swap.

## What is verified

The bridge already proves CKB state with a Groth16 proof over BLS12-381 (the curve Cardano's Plutus builtins
use; the same proof `cardano_bound` verifies). The reverse leg reuses that exact proof. The check is the
standard Groth16 equation:

```
e(A, B) == e(alpha, beta) * e(vk_x, gamma) * e(C, delta),   vk_x = ic[0] + sum(pub_i * ic[i+1])
```

## What was proven

- **Off-chain** (`verify_ckb_proof.mjs`, `@noble/curves`): loads the real proof + vk + 5 public inputs
  (`leap_bound_windowed_redeemer.json`) and the equation holds, `verifies: true`. This pins the equation and
  confirms the proof is real before porting.
- **CosmWasm contract** (`contract/`, `cosmwasm-std` 2.2 + the `bls12_381` crate): a real contract with
  `instantiate` and a `VerifyCkbProof` query. The native `cargo test` verifies the real proof and REJECTS a
  tampered public input (fail-closed). It compiles to the wasm32 CosmWasm target (`ckb_verifier.wasm`, ~468 KB),
  so it is a deployable Cosmos contract.

So a Cosmos chain can verify the bridge's CKB-state proof on-chain. The reverse direction is feasible and the
math is the same one Cardano runs.

## How to run

```
cd spike/cosmwasm-ckb && npm install
node verify_ckb_proof.mjs        # off-chain: e(A,B) == e(alpha,beta)*e(vk_x,gamma)*e(C,delta) -> true
wsl: cd contract && cargo test   # verifies the real proof, rejects a tampered input
wsl: RUSTFLAGS="-C link-arg=--allow-undefined" cargo build --release --target wasm32-unknown-unknown --lib   # -> ckb_verifier.wasm
```

## Where this sits, and what is left

- **Gas / size optimization:** the contract does the full pairing in-wasm via the `bls12_381` crate (~468 KB,
  heavy gas). CosmWasm 2.x exposes BLS12-381 host functions (`bls12_381_pairing_equality`, G1 aggregate), so a
  production version would do the scalar muls for `vk_x` in-wasm and the final pairing via the host function,
  much smaller and cheaper. The feasibility (it verifies, it compiles to wasm) is what is proven here.
- **Deploy + bind:** instantiate the contract on a CosmWasm testnet (Neutron, Osmosis), and bind the proof's
  public inputs to a concrete CKB event (the window root, the locked/burned amount, the recipient), so a Cosmos
  action is gated on a verified CKB state, the mirror of how the CKB side gates on a verified Cosmos tx.
- **Asset + registry wiring:** reuse the chain-agnostic asset binding and the replay-once registry for the
  Cosmos <-> CKB pair.

With the forward leg live on CKB Pudge (`spike/cosmos-ckb`) and this reverse leg proven, both directions of the
mutual verification exist. What remains is wiring them into a live, deployed, two-way binding.
