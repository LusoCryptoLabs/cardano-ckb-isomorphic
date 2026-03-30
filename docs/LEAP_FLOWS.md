# Leap flows — orchestration (leap-in, transfer, leap-out)

> How the pieces (Cardano binding lock + seal NFT; CKB BoundAsset + the verification oracle)
> compose into the end-to-end value flows.
>
> **Status (2026-06): the live run is DONE.** All three flows below ran on preview↔Pudge against
> real Mithril certs: leap-in/genesis `0x0318d35f`, transfer/transition `0x94d0620f` (consumed the
> genesis cell), leap-out finalize `0x795f4bb9` — driven by the real seal lifecycle (mint
> `83dd51d2` → Transfer `a98b6636` → Unbind `6c729ea6`). The relayer (`relayer/`) and the unified
> witness-driven `BoundAsset` (`spike/phase1/`) are built. See `LIVE_STATUS.md`.

## Notation
- `binding_lock` (Cardano, Aiken) holds the **seal** (a one-shot NFT). `seal NFT` ↔ one bound asset.
- `BoundAsset` (CKB) is the bound cell's type script. `commitment = blake2b256(state ‖ seal_outpoint)`.
- `cardano_tx_is_certified(tx)` = Mithril cert verify (→ certified tx-set root, chained to the
  light-client checkpoint cell) + MKMapProof that `blake2b256(tx)` is in that root. (Proven on real
  data; wired into `bound_asset_leap`.)

## Leap-in (Cardano → CKB: bind an asset)
1. **Cardano:** owner mints the seal NFT under `binding_lock` (one-shot, consumes a seed UTxO),
   datum `SealDatum{ owner, commitment = blake2b256(S0 ‖ seal0) }`, optionally locking anchored
   value. Tx `T_in`.
2. **Wait** for `T_in` to be Mithril-certified (the latency gap).
3. **CKB:** mint the bound cell with state `S0`, seal `= seal0`. `BoundAsset` genesis rule runs the
   wired check on `T_in`: certified + creates the seal at `binding_lock` + commitment binds `S0`.
   → the asset is now bound: ownership on Cardano (the seal), state on CKB.

## Transfer (on the bound asset)
1. **Cardano:** owner spends the seal (`binding_lock` `Transfer`): recreates the seal at the lock
   with `SealDatum{ new_owner, commitment = blake2b256(S' ‖ seal') }`. Tx `T`.
2. **Wait** for `T` to be certified.
3. **CKB:** spend `BoundCell{seal, S}` → `BoundCell{seal', S'}`. `BoundAsset` runs the wired check:
   `cardano_tx_is_certified(T)` ∧ `T` consumes `seal` ∧ `commitment(T) == blake2b256(S' ‖ seal')`.
   → the bound cell follows the Cardano seal, trust-minimized.

## Leap-out (CKB → Cardano: unbind / release)
1. **Cardano:** owner spends the seal (`binding_lock` `Unbind`): seal NFT not recreated (burned /
   leaves), anchored value released to a plain UTxO. Owner-signed. *(Cardano never verifies CKB.)*
2. **CKB:** finalize/burn the bound cell — a spend that proves (oracle) the seal was consumed
   without recreation. The asset is now unbound; ownership is a normal Cardano UTxO again.

## The relayer (liveness only — cannot forge) — BUILT (Phase 3, `relayer/`)
A permissionless relayer: watches `binding_lock` seal spends on Cardano; once a spend is
Mithril-certified, fetches the cert + MKMapProof, transcodes them + the tx body into the CKB
witness, classifies TRANSITION vs FINALIZE (by whether the seal is recreated at the lock), and
submits the `BoundAsset` spend. If it stalls, transfers are delayed, not unsafe — anyone can relay,
and the CKB script re-verifies everything. The transcode is **validated byte-for-byte** against the
witness the live CKB transition accepted (`relayer/validate_transcode.py`); the full pipeline was
exercised on real preview data (unbind→FINALIZE, transfer→TRANSITION).

## Leap-out finalize — BUILT + PROVEN (Phase 3)
The CKB `BoundAsset` FINALIZE mode: spend the bound cell with **no** output cell, requiring the
certified Cardano Unbind tx to (1) be in the certified tx-set root (MKMapProof), (2) consume the
old seal, and (3) **not** recreate the seal NFT at the `binding_lock` (a Conway output/multiasset
parse — the Unbind released the seal to a plain address). Proven in CKB-VM on the **real certified
Unbind** `6c729ea6` (205,581 cycles). *Cardano never verifies CKB here — the owner controls the
seal; CKB just observes the unbind.* This is the asymmetry paying off.

## What's proven — and what ran live
- **Proven (CKB-VM, real data / wired):** the verification oracle (cert + tx-membership), the
  Conway tx parse (seal detect + commitment), the BoundAsset commitment binding, and the wired
  leap transition. Cardano side (seal NFT + binding lock) compiled + tested in Aiken (91 checks).
- **Ran live (DONE):** deployed `binding_lock` + seal policy on **preview**; minted a real seal
  (`83dd51d2`, commit `S0`); waited out **real Mithril certification**; minted the bound cell on
  **Pudge** (`0x0318d35f`); did a real transfer (real seal spend `a98b6636` → real cert + MKMapProof
  → real CKB transition `0x94d0620f`, consuming the genesis cell); and closed the **leap-out
  finalize** (`0x795f4bb9`) against the real Unbind `6c729ea6`. The relayer + witness/molecule
  plumbing are built; certification latency is handled as settlement-style UX. No new in-script
  cryptography was needed — exactly as predicted.
