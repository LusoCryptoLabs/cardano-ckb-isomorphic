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
- **CosmWasm contract** (`contract/`, `cosmwasm-std` 2.2): a real contract with `instantiate` and a
  `VerifyCkbProof` query. The native `cargo test` verifies the real proof and REJECTS a tampered public input
  (fail-closed). It compiles to the wasm32 CosmWasm target, so it is a deployable Cosmos contract.
- **Production form: the pairing runs in the host, not the wasm.** The contract computes `vk_x = ic[0] +
  sum(pub_i * ic[i+1])` in wasm (G1 scalar muls only) and delegates the four-pairing check
  `e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == e(A,B)` to CosmWasm 2.x's native
  `bls12_381_pairing_equality(ps, qs, r, s)` host function (`ps = alpha‖vk_x‖C`, `qs = beta‖gamma‖delta`,
  `r = A`, `s = B`), which runs the chain's audited BLS implementation. The test exercises this through
  `MockApi` (the same `cosmwasm-crypto` BLS the chain runs) and cross-checks it against the original
  all-in-wasm Miller-loop equation, both on the real proof and a tampered one; the two agree. Dropping the
  in-wasm pairing shrank the artifact from ~468 KB to **~304 KB** (`ckb_verifier.wasm`, 311536 bytes) and makes
  the on-chain pairing cheap (a host call) instead of a heavy in-wasm Miller loop and final exponentiation.

So a Cosmos chain can verify the bridge's CKB-state proof on-chain, in the cheap production form, with the same
math Cardano runs.

- **Bound to a concrete CKB event** (`VerifyCkbEvent`, `derive_inputs.mjs`): verifying a proof is not enough,
  the contract must gate on a NAMED event so a relayer cannot present a valid proof and then claim different
  public inputs. So the contract takes the event fields (window_root, seal, amount, recipient, tip_height, K)
  and DERIVES the 5 Groth16 public inputs exactly as the leap circuit does:
  `pi = [LEmod(window_root), LEmod(seal), LEmod(blake2b256(amount[16 LE] ‖ recipient[28] ‖ seal[32])),
  tip_height, K]`, where `LEmod(b) = (b read little-endian) mod r`. The derivation is cross-checked byte-for-byte
  against an independent off-chain reference (`derive_inputs.mjs`, `@noble/curves` + `@noble/hashes/blake2`) on a
  constructed event (the test asserts all 5 derived field elements equal the reference, including the mod-r
  reduction of an over-r window_root and the blake2b commitment), and the integer inputs (`tip_height`, `K`) are
  tied to the REAL committed redeemer (`21388353`, `12`). The one seam a static redeemer cannot cover is the
  hash inputs bound to THIS proof's hidden preimage; the leap prover now writes that preimage as a sidecar
  (`leap_bound_windowed_event.json`), so the next real proof run gives a full event-to-proof round-trip.

- **Replay-once registry** (`ExecuteMsg::RecordCkbEvent`): verifying a CKB event is not enough, the same event
  must be consumable only once on Cosmos. The `execute` path verifies the bound proof, then inserts the event's
  `seal` (the unique CKB tx hash) into a nullifier set under a per-leg domain tag
  (`chiral:cosmos-ckb:nf:`, mirroring the CKB-side `burn_nullifier_registry` separation); a second record of the
  same seal is rejected. The test drives this against the REAL verifying proof (record once, replay rejected,
  distinct seal still records) and checks `execute` is fail-closed (a proof that does not match the claimed event
  is rejected before anything is stored). This is the chain-agnostic replay registry, reused for the Cosmos leg.

## How to run

```
cd spike/cosmwasm-ckb && npm install
node verify_ckb_proof.mjs        # off-chain: e(A,B) == e(alpha,beta)*e(vk_x,gamma)*e(C,delta) -> true
node derive_inputs.mjs           # off-chain reference: event fields -> the 5 public inputs (the test's vectors)
wsl: cd contract && cargo test --release   # host-fn verify + in-wasm cross-check + event-binding derivation
wsl: RUSTFLAGS="-C link-arg=--allow-undefined" cargo build --release --target wasm32-unknown-unknown --lib   # -> ckb_verifier.wasm (~332 KB)
```

## Where this sits, and what is left

- **Gas / size optimization: done.** The contract now does the scalar muls for `vk_x` in wasm and the final
  pairing via CosmWasm's `bls12_381_pairing_equality` host function (~304 KB, cheap host pairing instead of an
  in-wasm Miller loop). The all-in-wasm version remains as a test-only cross-check reference.
- **Public-input binding: done.** `VerifyCkbEvent` derives the 5 public inputs from the concrete CKB event
  (window root, seal, amount, recipient, tip_height, K), so a Cosmos action gates on a NAMED CKB state, the
  mirror of how the CKB side gates on a named Cosmos tx. Cross-checked byte-exact against the off-chain
  reference; the prover emits the event preimage sidecar for the end-to-end round-trip.
- **Deploy:** instantiate the contract on a CosmWasm testnet (Neutron, Osmosis) and drive a live query (needs a
  funded testnet account + gas). The wasm and the verification logic are ready.
- **Asset + registry wiring:** reuse the chain-agnostic asset binding and the replay-once registry for the
  Cosmos <-> CKB pair.

With the forward leg live on CKB Pudge (`spike/cosmos-ckb`) and this reverse leg proven, both directions of the
mutual verification exist. What remains is wiring them into a live, deployed, two-way binding.
