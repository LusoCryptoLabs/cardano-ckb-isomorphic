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
| **2nd toggle S4** (repeat) | Transfer `5e05899e…` | `0x021344ad…` | re-Transfer of the 3-field seal accepted |
| **2nd toggle S5** (repeat) | LeapToCkb `1daf5e38…` | `0xc36e1164…` | **NON-EMPTY** registry insert (`f5a10236…`→`91bbf07a…`, set 1→2) |

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
| bound_asset_v2 | code `0xf135e9ef` (was `0xb33fc200`, reclaimed+redeployed), **`V2_BOUND_CODE_HASH 0x4cc7ae86`** | LCKP+REG baked |
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

**Repeatable toggles — DONE and PROVEN LIVE.** A SECOND full round-trip ran end-to-end on testnet:
S4 Cardano Transfer `5e05899e…` → CKB `0x021344ad` (CkbOwned→CardanoBound), then S5 Cardano LeapToCkb
`1daf5e38…` → CKB `0xc36e1164` (CardanoBound→CkbOwned). It exercised the previously-untested paths: the
Cardano node ACCEPTED the re-Transfer of the now-3-field `LeapSealDatum` seal, and the registry performed
its first NON-EMPTY SMT insert live (root `f5a10236…`→`91bbf07a…`, set size 1→2).

`reg_nullifier_witness.py` is now a full sparse-Merkle client over the tracked nullifier set
(`registry_state.json`): it rebuilds the REAL siblings on each new key's path (not just the empty-tree case)
and asserts its reconstructed root equals the live on-chain root. `leap_to_ckb_v2.mjs` reads the CURRENT
registry outpoint from `boundasset_v2_state.json::registry` and appends each nullifier after the tx confirms.
Also validated in-VM (`v2vmtest/tests/registry_smt.rs`, 3 tests): the real `burn_nullifier_registry` binary
accepts a 2nd insert into a NON-EMPTY tree, rejects a replay (err 12), and the client SMT reproduces the live
anchor roots. (A non-self recipient just means passing a different `recipient_lock_hash` to
`leap_to_ckb_ours.py`; the CKB side already pins the surviving cell's actual lock to it.)

**Operational lesson from the 2nd run:** `reclaim.mjs` (fund consolidation) did NOT protect the v2
`bound_asset_v2` code cell (a lock-only data cell, easy to mistake for an orphan) and swept it, breaking the
next leap's `cellDep` (`Unknown OutPoint`). No value lost — the binary is unchanged and cells reference it by
`codeHash` — but it had to be redeployed (`v2_registry.json::boundCode` → `0xf135e9ef…`, same `codeHash
0x4cc7ae86`). `reclaim.mjs`'s protected set now includes `reg.boundCode`. Reclaim only ever touches
lock-only, non-protected cells, but a deployed CKB *code* cell IS lock-only — any consolidation must
explicitly protect every live code cell by outpoint.

**Relayer automation + monitoring — DONE.** `relayer/onchain/leap_orchestrator.mjs` drives the whole toggle
state machine end-to-end (picks the next leg from on-chain state → Cardano leg → poll Mithril cert → CKB leg
→ `leap_log.jsonl`), with pre-flight code-cell-liveness + funding checks (safe auto-reclaim) and a both-chain
`status` monitor (`node leap_orchestrator.mjs status|leg|toggle|run N`, `--verify` for in-loop ckb-debugger).
`status` also surfaces the one slow operational bleed: each `refresh_checkpoint_v2` parks a ~167 CKB typed
checkpoint cell that isn't auto-reclaimed (the witness cell IS recycled, so only checkpoints grow).

What remains is out of the testnet-repeatable scope:
- **The parked mint leg (Groth16/χCKB)** stays out of scope (see `docs/LEAP_BRIEF_V2.md`); the toggle is
  the value-bearing path.
- **Mainnet-with-value** (mainnet deploy, key custody, professional audit) is a separate, deferred track.
  The trust-root question is now ANSWERED: the on-chain cert-verify DOES validate the Mithril STM multisig
  (BLS aggregate + per-signer stake-Merkle membership + lottery + an AVK chain pinned to a hardcoded genesis)
  — it is genuinely trust-minimized, not a relayer-posted root. An audit of that verifier found ONE critical
  gap — the STM quorum `k` and the `total` stake were taken from the witness unanchored (a single compromised
  SPO key could forge a checkpoint) — now FIXED (pin `k`/`m`, bound indices, anchor `total`) and validated
  off-chain. See `docs/SEC_STM_QUORUM_PIN.md`. Deploying the fix is part of the mainnet redeployment cascade.

## On-chain orchestration (relayer/onchain/)
deploy_cv_deploy_v2 · advance_1324 (+ adversarial/advance_check_1324.py) · refresh_checkpoint_v2 (44-byte
publisher) · deploy_regcode · deploy_bound · reclaim (fund consolidation) · boundasset_v2 (genesis builder, with
`--dump` → ckb-debugger ReprMockTransaction). State: `deployed.json` / `chain_state.json` / `checkpoint_v2.json`
/ `v2_registry.json`. Keys: `~/.chiral/{pudge,preview}_relayer.key`.
