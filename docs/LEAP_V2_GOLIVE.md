# Leap v2 — LIVE on testnet (Pudge ⇄ preview)

The RGB++-style ownership-toggle leap is **deployed and the FULL ownership toggle is proven end-to-end on
both testnets.** A single living seal round-trips **CkbOwned →(S4 leap-to-cardano)→ CardanoBound →(S5
leap-to-ckb)→ CkbOwned**, each leg a Mithril certify-then-prove cycle, with the source seal nullified
against replay. The genesis (CkbOwned minted from a certified Cardano seal) succeeded first (tx
`0x408d9c28…`), then both toggle directions executed live.

## The full toggle — live transaction trail

| Leg | Cardano (preview) | CKB (Pudge) | what it proves |
|---|---|---|---|
| **Genesis** (∅→CkbOwned) | seal mint `08000078…` | `0x408d9c28…` | certified Cardano event validates on CKB |
| **S4 leap-to-cardano** (CkbOwned→CardanoBound) | Transfer `5c60bfb3…` (state-only datum) | `0x838e39f2…` | owner leaves CKB; state preserved, CardanoBound names the cert, lock slot zeroed |
| **S5 leap-to-ckb** (CardanoBound→CkbOwned) | LeapToCkb `f81a66bf…` (RC datum) | `0xb45812da…` | owner returns; **B1** recipient binding, **B3** actual-lock pin, **RC** keystone, **B4** seal nullifier insert |

The toggle conserves ONE seal NFT under the deployed `bound_asset_v2`'s baked `seal_policy` (`ec8d2c74…`):
S4/S5 spend+re-park the *same* seal at `binding_lock`, toggling its datum shape (2-field state-only ↔
3-field `LeapSealDatum{owner, RC, recipient}`) — not minting a fresh one-shot policy (which would carry a
different policy id and fail the verifier's `seal_at_lock`). This is the literal RGB++ model: one seal,
ownership toggles.

- **S5 keystone, verified byte-identical across languages:** `RC = blake2b256(state ‖ src_seal36 ‖
  recipient) = 9e69a079…` — computed by the pycardano driver into the certified datum AND recomputed by the
  CKB verifier over the CardanoBound cell's seal field; they match (error 27 passes). Nullifier key =
  `blake2b256(src_seal36) = f30ff09b…`; registry SMT root `5b7ed70c…` → `f5a10236…` (one-shot insert).
- **Both S5 script groups dry-ran `Run result: 0` in ckb-debugger** before the live send (bound 282K
  cycles; registry SMT insert 4.8M cycles), on a faithful mock with the real secp lock dep_group.
- **Terminal state verified on Pudge:** final CkbOwned `0xb45812da:0` LIVE (locked to recipient
  `0x7a971a3b…`, state preserved); continuing registry `0xb45812da:1` LIVE (nullifier inserted); the
  genesis CkbOwned, the CardanoBound, and the registry genesis singleton all consumed.

Drivers: `cardano/binding/leap_to_cardano_ours.py` (S4) + `leap_to_ckb_ours.py` (S5, the new pycardano
LeapToCkb driver); `relayer/onchain/leap_to_cardano_v2.mjs` (S4 CKB) + `leap_to_ckb_v2.mjs` (S5 CKB) +
`leap_common_v2.mjs` (shared) + `reg_nullifier_witness.py` (registry SMT insert witness).

## The genesis

The genesis — a CkbOwned cell created on CKB by proving a Mithril-certified Cardano seal mint, validated by
the live `bound_asset_v2` against the M2 44-byte checkpoint — **succeeded on Pudge** (tx `0x408d9c28…`).

## Live deployment

**CKB — Pudge:**
| Component | code / tx | constant |
|---|---|---|
| cv_deploy_v2 (M2 44-byte checkpoint verifier) | code `0x75b288f3`, deploy `0xa42e3942` | `CHIRAL_LCKP_TH 0xa055798e` |
| AVK epoch checkpoint advance 1323→1324 | `0x2519ee3c` | (also un-stuck live v1) |
| 44-byte `LCKP‖root‖height` checkpoint | published `0xe5e61bdc` (re-published each leap) | type hash = CHIRAL_LCKP_TH |
| burn_nullifier_registry | code `0x2b96f094`, genesis singleton `0x4e159851` | `CHIRAL_REG_TH 0xdc18fd56` |
| bound_asset_v2 | code `0xb33fc200`, **`V2_BOUND_CODE_HASH 0x4cc7ae86`** | LCKP+REG baked |
| **GENESIS CkbOwned cell** | **`0x408d9c28…`** | seal=08000078, state="bound-asset:demo:v1" |

**Cardano — preview:** v2 `binding_lock` `addr_test1wprutk2vjvuzgwlsvf956we9ssxqlyfl9jdeywrlv6tsyccz32l5e`,
seal policy `ec8d2c74…`, seal mint `08000078…` (Mithril-certified).

## What deploying caught that VM-testing never would have
1. **CKB-VM rejects RISC-V atomics** (opcode 0x2F → `InvalidInstruction`). The burn-gated-unlock binaries must be
   built `RUSTFLAGS="-C target-feature=-a,+forced-atomics"` + carry the `__sync_*` polyfill, then stripped.
2. **`hex32` didn't strip the `0x` prefix** — baking `CHIRAL_LCKP_TH=0x…` produced a byte-shifted hash
   (`[0, a0, 55, …]`). Fixed to strip `0x`/`0X`.
3. **`checkpoint_root` OOM'd on the 1 MiB secp256k1_data cell.** A lock dep_group expands into its referenced
   cells; `load_cell_data` on every cellDep loaded the 1 MiB secp table → heap abort → script error `-1`. Fixed
   to check the cheap 32-byte type hash FIRST and only load data for a trusted checkpoint. **This only manifests
   with a real secp-locked funding input — the in-VM tests used always-success funding, so it stayed hidden until
   the live tx.** Reproduced + fixed via `ckb-debugger --tx-file` on the dumped tx; regression-guarded by
   `v2vmtest/tests/genesis_real.rs` (faithful real-witness repro) + `mmr_diag.rs`.

The AVK was also a stale epoch (1323 vs 1324); advancing it un-stuck the live v1 lineage too.

## Status: FULL TOGGLE PROVEN end-to-end on both testnets
Genesis + S4 + S5 all executed live (trail above). The dangerous S5 direction works: a permissionless
relayer builds the CKB tx, yet the surviving cell can only land at the owner-signed, Mithril-certified
recipient (RC keystone + actual-lock pin), and the consumed seal is nullified so it can never be replayed.

Mithril snapshot latency IS the finality guarantee; on preview each leg certified in ≈5 min.

What remains is breadth, not depth:
- **Repeated toggles / a non-self recipient:** the first S5 used our own lock as recipient (round-trip).
  A second toggle must read the CURRENT registry outpoint from `boundasset_v2_state.json::registry` (the
  genesis singleton is now consumed) and, for a non-empty SMT, supply real (not empty-tree) siblings —
  `reg_nullifier_witness.py` currently handles only the genesis-empty insert.
- **The parked mint leg (Groth16/χCKB)** stays out of scope (see `docs/LEAP_BRIEF_V2.md`); the toggle is
  the value-bearing path.

## On-chain orchestration (relayer/onchain/)
deploy_cv_deploy_v2 · advance_1324 (+ adversarial/advance_check_1324.py) · refresh_checkpoint_v2 (44-byte
publisher) · deploy_regcode · deploy_bound · reclaim (fund consolidation) · boundasset_v2 (genesis builder, with
`--dump` → ckb-debugger ReprMockTransaction). State: `deployed.json` / `chain_state.json` / `checkpoint_v2.json`
/ `v2_registry.json`. Keys: `~/.chiral/{pudge,preview}_relayer.key`.
