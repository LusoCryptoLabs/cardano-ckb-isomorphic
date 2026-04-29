# Terminology — "leap" vs "bind / unbind" (authoritative)

A reviewer correctly flagged that Chiral's original "leap-in / leap-out" did NOT mean what "leap" means in
RGB++. This document fixes the terminology and is the authoritative reference.

## leap — the RGB++ sense — IMPLEMENTED (v2)
A **leap** is an **ownership toggle on a SURVIVING CKB cell**: the same bound cell persists and only its owner
flips between **Cardano-owned** (`CardanoBound{seal, commitment}`) and **CKB-owned** (`CkbOwned{lock}`). No
mint, no burn. This is the RGB++ leap (the `genBtcJumpCkbVirtualTx` / `genCkbJumpBtcVirtualTx` analog), with
Cardano playing the owner-only role Bitcoin plays in RGB++. Implemented + verified in real CKB-VM:
- **on-chain:** `spike/burn-gated-unlock/src/bin/bound_asset_v2.rs` branches `LEAP_TO_CKB` (S5) /
  `LEAP_TO_CARDANO` (S4); the Cardano carrier `cardano/binding/validators/binding_lock.ak` `LeapToCkb` +
  `LeapSealDatum`.
- **off-chain:** `spike/dex-integration/relayer/v2_leap_builders.mjs` (`assembleLeapToCkb` /
  `assembleLeapToCardano`) + `v2_cell.mjs`.
- **design:** `docs/LEAP_BRIEF_V2.md` + `docs/RECIPIENT_COMMITMENT.md`.

## bind / unbind — the OLD "leap-in / leap-out" (a MISNOMER)
The original Chiral "leap-in / leap-out" are **MINT / BURN** of a wrapped asset, with ownership pinned to a
Cardano seal the whole time — NOT an ownership toggle. Read them as:
- **bind**   = old "leap-in"  = GENESIS / mint the bound cell or wrapped FT (`leap_mint_guard.LeapInMint`, the
  Groth16 mint leg).
- **unbind** = old "leap-out" = FINALIZE / burn / release (`leap_mint_guard.LeapOutBurn`, the burn-gated unlock).

That mint/burn bridge is the **Groth16 leg, which is PARKED** (`docs/MINT_AUDIT.md`,
`docs/RECIPIENT_COMMITMENT.md` §6: a free-witness amount/recipient circuit problem). **Identifier renames in
that parked leg are deliberately DEFERRED** — churn on tested code (101 Aiken tests) for a parked leg with no
functional benefit. Where older docs/code say "leap-in / leap-out" (e.g. `relayer/ckb_leap.mjs`,
`cardano_leap.mjs`, `LEAP.md`), read **bind / unbind**, not the v2 toggle.

## one-line rule
**leap = ownership toggle on a surviving CKB cell (v2, live-VM-tested).
bind / unbind = the old mint/burn bridge (Groth16 leg, parked).**
