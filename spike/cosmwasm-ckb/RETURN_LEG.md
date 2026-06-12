# χOSMO return leg (Cosmos <- CKB): LIVE, proof verified on-chain

The forward leg locks OSMO on osmo-test-5 and mints χOSMO on CKB Pudge (live: `catom_owner_live.json`). The
RETURN leg burns χOSMO on CKB and releases the OSMO. This is the mirror of the χADA/χCKB Groth16 value leg,
done with a 20-byte Osmosis recipient instead of a 28-byte Cardano credential. Everything up to the final
uosmo payout is LIVE and verified on-chain; the payout itself is the same host-fn-gated step as the χCKB mint.

## The pipeline (all real, no mocks)

1. **Burn χOSMO on CKB Pudge** (`relayer/onchain/live_xosmo_burn.mjs`). Spend the displayable χOSMO xUDT and
   emit a live `xosmo_burn_receipt` cell that SELF-ENFORCES `Σχosmo_in − Σχosmo_out == amount` (it can never
   overstate the burn). A portion is burned and a same-token change cell is kept, so "Chiral OSMO" stays
   displayable in the explorer.
   - burn tx `0x4ca0e3c04deb60a6881fd24bb9b6dd6ff26edd9e31462af1c6dad19507975372` (block 21402557)
   - receipt cell `0x4ca0e3c0…:0` = `MAGIC"XOS1" ‖ amount(400000, 16 LE) ‖ recipient(20 = 476facba3f2b084528ce10a63e8d38da30ebc24c)`
   - recipient = `osmo1gah6ew3l9vyy22xwzznrarfcmgcwhsjv39xelf` (the released-uosmo address)
   - `xosmo_burn_receipt` code cell `0xf7b4acd4c55d6bc8df77853fcb7839e01285b3cf84e53663b89a9d8d63749a4f`
   - change χOSMO cell `0x4ca0e3c0…:1` (600000 χOSMO, same token id `0x8059cdb0…`, stays displayable)

2. **Prove the burn** (`spike/ckb-to-cardano/circuit/prover/src/bin/leap_burn_windowed.rs`). The 20-byte-recipient
   mirror of `leap_bound_windowed`: one Groth16/BLS12-381 proof attests R1 Eaglesong PoW + R2' shallow
   window-root membership + R3 tx-CBMT inclusion + the K_MIN reorg floor (diff = tip − height >= 12) AND the
   value binding `commitment = blake2b256( amount(16 LE) ‖ recipient(20) ‖ seal(32) )`, where the
   amount/recipient are DERIVED from the receipt's own body (not free witnesses) and the receipt's type
   code-hash is pinned in-circuit. The witness is built from the LIVE burn:
   - `relayer.py` (4 real headers + CBMT for the burn tx) and `relayer_window.py` (64 real CKB header hashes,
     receipt 12 deep below tip) feed the prover; `build_burn_lock.mjs` reconstructs the exact RawTransaction
     body (`ckbhash(body) == tx_hash`) and the receipt field offsets.
   - 5-case differential audit passes: real burn ACCEPTED; tampered amount, wrong receipt code-hash, K=0 below
     the pinned K_MIN, and a shallow (diff < K) all REJECTED. `arkworks verify = true`.
   - artifacts: `relayer/onchain/leap_burn_windowed_redeemer.json` (proof + vk + 5 public inputs) and
     `leap_burn_windowed_event.json` (the raw event preimage the contract re-derives from).

3. **Verify on Cosmos, bound to the named burn** (`verify_burn_release.mjs`). Two checks:
   - **Binding**: `derive_burn_inputs(event)` (the contract's exact derivation, recomputed independently from
     the event sidecar) equals the proof's 5 public inputs, byte-for-byte. So the proof attests THIS burn
     (amount + osmo recipient + seal committed in-circuit), not just "some valid proof".
   - **On-chain**: the LIVE osmo-test-5 ckb-verifier contract
     `osmo1h9wvlfh7jfqpd5rtylqf0apnxt0d6at3nyxseh7ls9vsj6ht475sqkzt22` verified the χOSMO-burn proof:
     `VerifyCkbProof -> {"valid": true}`. (`burn_release_verified.json`.)

## What this proves, and the one residual

The contract's `ReleaseOnCkbBurn` does exactly: derive_burn_inputs -> verify the Groth16 proof -> nullify the
burn seal replay-once -> `BankMsg::Send amount uosmo` to the recipient. Steps 1-3 above are the verify; the
binding + the live `VerifyCkbProof: true` show the on-chain verification SUCCEEDS for this real burn. The only
step not yet executed live is the final `BankMsg::Send`, because on osmo-test-5 the release execute runs the
in-wasm BLS12-381 pairing, which exceeds the chain's 80M per-tx gas cap (osmo-test-5 does NOT expose the
`bls12_381_pairing_equality` host function). This is the SAME chain-capability gate as the χCKB forward mint,
and it clears on a CosmWasm chain that exposes the BLS host function (e.g. Neutron), where the host pairing is a
cheap call. So the χOSMO return leg is: live CKB burn + real burn proof + event-bound + on-chain-verified, with
the uosmo payout host-fn-gated (a chain limit, not a logic gap), at full parity with the χCKB forward direction.

## Reproduce

```
# CKB side (Pudge)
node relayer/onchain/live_xosmo_burn.mjs            # burn χOSMO -> live xosmo_burn_receipt (idempotent)
node relayer/onchain/build_burn_lock.mjs            # reconstruct body + offsets -> burn_lock_live.json
# witness (WSL)
cd spike/ckb-to-cardano/relayer
TARGET_TX=<burn_tx> TARGET_BLOCK=<height> python3 relayer.py https://testnet.ckb.dev /tmp/witness_burn.json
python3 relayer_window.py https://testnet.ckb.dev <height> /tmp/window_burn.json
# prove (WSL)
cd ../circuit/prover
PROVE=1 WINDOW_DEPTH=6 CHIRAL_K_MIN=12 K=12 CHIRAL_WINDOW=/tmp/window_burn.json \
  EVENT_OUT=<repo>/relayer/onchain/leap_burn_windowed_event.json \
  cargo run --release --bin leap_burn_windowed /tmp/witness_burn.json <repo>/relayer/onchain/burn_lock_live.json \
  > <repo>/relayer/onchain/leap_burn_windowed_redeemer.json
# verify on Osmosis
node spike/cosmwasm-ckb/verify_burn_release.mjs     # binding check + live VerifyCkbProof -> valid:true
```
