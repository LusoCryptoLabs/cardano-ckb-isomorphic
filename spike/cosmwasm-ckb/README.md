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

- **χCKB forward mint (CKB -> Cosmos), the wrapped-CKB token** (`MintChiCkb` / `MintChiCkbRaw`, `deploy_chickb.mjs`):
  the contract mints a wallet-visible χCKB **Osmosis token-factory denom** (`factory/<contract>/uchickb`) gated on
  the CKB-state proof, the forward mirror of χOSMO-on-CKB. `CreateChiCkbDenom` emits a tokenfactory `MsgCreateDenom`
  (the contract becomes admin); `MintChiCkb` verifies a proof bound to the CKB lock event, nullifies the seal
  replay-once, and emits `MsgMint`. The Osmosis tokenfactory messages are `CosmosMsg::Stargate` with hand-encoded
  protobuf. **Live status on osmo-test-5** (`chickb_deploy.json`): the contract is deployed (codeId 13218,
  `osmo1yewevz…`) and the **token-factory denom was created live**; the proof **verification is provable live** (the
  `VerifyCkbProof` query returns valid). The **mint execute is blocked on this chain**: it runs the in-wasm
  BLS12-381 pairing, which exceeds osmo-test-5's **80M per-tx gas cap**, and the chain does NOT expose the
  `bls12_381_pairing_equality` host function that makes the pairing cheap. The mint is feasible on a CosmWasm chain
  that exposes the BLS host function (e.g. Neutron), where the host pairing fits the gas budget. So χCKB-on-Cosmos
  is contract-complete + denom-live + verification-live, with the gated mint host-fn-gated (a chain-capability
  limit, not a logic bug).

- **LIVE on Osmosis testnet (osmo-test-5).** The contract is deployed and a real Cosmos node verified the
  bridge's CKB-state proof on-chain: query `VerifyCkbProof` with the real redeemer returned `{"valid": true}`.
  codeId `13217`, contract `osmo1h9wvlfh7jfqpd5rtylqf0apnxt0d6at3nyxseh7ls9vsj6ht475sqkzt22`, store tx
  `2231F979…`, instantiate tx `8E45B590…` (see `osmo_deploy.json`). This is the reverse-direction analog of the
  live Pudge deploy that already does CKB-verifies-Cosmos, so the binding is now LIVE both ways.
  Two build notes were needed to land it: (1) osmo-test-5's wasmvm does NOT expose the BLS12-381 host functions
  (the host-fn build returns `not implemented: unknown request`), so the live build uses the `inwasm` cargo
  feature (the whole pairing in wasm, via `verify_ckb_proof.mjs`'s equation); (2) Rust 1.96 emits bulk-memory
  opcodes the chain rejects, so the wasm is lowered to MVP with `wasm-opt --llvm-memory-copy-fill-lowering
  --signext-lowering`. The default host-fn build stays the production form for chains that do expose the host
  functions (e.g. Neutron). `AssertCkbProof` is an execute variant that runs the same verify as a gas-paid tx
  (succeeds iff the proof verifies), the fallback if a chain's query gas cap is too low for the in-wasm pairing.

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
wsl: RUSTFLAGS="-C link-arg=--allow-undefined" cargo build --release --target wasm32-unknown-unknown --lib   # host-fn -> ckb_verifier.wasm (~332 KB)

# live deploy on osmo-test-5 (in-wasm pairing, since this chain lacks the BLS host fns)
node gen_osmo_wallet.mjs            # deployer address (mnemonic in ~/.chiral, never printed); fund at faucet.testnet.osmosis.zone
wsl: RUSTFLAGS="-C link-arg=--allow-undefined" cargo build --release --target wasm32-unknown-unknown --lib --features inwasm
wsl: wasm-opt ckb_verifier.wasm --enable-bulk-memory --enable-sign-ext --llvm-memory-copy-fill-lowering --signext-lowering --strip-target-features -o ckb_verifier.mvp.wasm
node deploy_osmo.mjs               # store + instantiate + live VerifyCkbProof -> {"valid": true}
```

- **χOSMO return leg (Cosmos <- CKB), LIVE + proof verified on-chain** (`RETURN_LEG.md`): a real χOSMO burn on
  CKB Pudge (`live_xosmo_burn.mjs`, receipt tx `0x4ca0e3c0…`, self-enforcing `Σin−Σout==amount`) is proven by
  `leap_burn_windowed` (the 20-byte-osmo-recipient mirror of `leap_bound_windowed`: PoW + window membership +
  CBMT + K-floor + value binding, `arkworks verify = true`, 5-case audit OK), and the LIVE osmo-test-5 contract
  verified that burn proof: `VerifyCkbProof -> {"valid": true}`, with the proof's 5 public inputs equal to
  `derive_burn_inputs(event)` byte-for-byte (so it is bound to THIS named burn). The only step not executed live
  is the final `BankMsg::Send` uosmo payout in `ReleaseOnCkbBurn`, host-fn-gated on osmo-test-5 exactly like the
  χCKB mint (cleared on Neutron). See `RETURN_LEG.md` for every live hash and the reproduce steps.

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
