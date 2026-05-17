# Chiral CKB ⇄ Cardano bridge — MASTER STATUS (what's built, working, wired, deployed)

> **Read this first.** It is the single authoritative index so no one rebuilds what already exists. Every
> component below is marked **BUILT / TESTED / DEPLOYED (hash) / GATED**. Detailed docs are linked, not
> duplicated. Last verified: 2026-06-11 (commit `2284c9c`+).

The bridge has **two legs**. Both are demonstrated live on testnet (CKB Pudge ⇄ Cardano preview).

| leg | direction | who verifies whom | oracle | use |
|---|---|---|---|---|
| **Mithril leg** | CKB verifies a Cardano event | CKB re-runs a Mithril STM cert in CKB-VM | Mithril | ownership toggle **+ the return trip (burn→unlock)** |
| **Groth16 leg** | Cardano verifies CKB consensus | Cardano verifies a Groth16 proof of CKB PoW+inclusion | Groth16 | the forward native-token mint (lock CKB → mint χCKB) |

A native-token round-trip (path B) uses BOTH: forward = Groth16 (mint χCKB), return = Mithril (release CKB).

---

## 1. Component matrix

### Mithril leg (CKB-verifies-Cardano) — LIVE on Pudge + preview
| component | file | status | on-chain id |
|---|---|---|---|
| Mithril STM cert verifier (advance) | `spike/light-client-cell/cert-verify` | DEPLOYED **(pre-STM-pin)** | `cv_advance` code `0xe877a802`, type `0x59efd99d` |
| Mithril cert verifier (M2 44-byte checkpoint/deploy) | same source, deploy mode | DEPLOYED **(pre-STM-pin)** | `cv_deploy_v2` code `0x75b288f3`, **LCKP type `0xa055798e`** |
| AVK checkpoint lineage (genesis 1319 → epoch 1324) | `advchain*.mjs`, `lca_advance.mjs` | LIVE | epoch-1324 AVK cell `0x2519ee3c:0`; genesis `0x248ac2b5:0` |
| 44-byte authenticated checkpoint (root‖height) | `refresh_checkpoint_v2.mjs` | LIVE (re-published per leap) | latest `checkpoint_v2.json` root `0x44c1462a…`, height `4368824` |
| burn-nullifier registry (replay-once, genesis-pinned) | `burn_nullifier_registry.rs` | DEPLOYED | code `0x9d2fc246`:0 (`0x2b96f094`), genesis `0x4e159851`:0, **REG type `0xdc18fd56`** |
| bound_asset_v2 (RGB++ seal lock, Mithril-gated) | `bound_asset_v2.rs` | DEPLOYED | code `0xf135e9ef`:0, **hash `0x4cc7ae86`** (LCKP+REG baked) |
| ownership toggle (CkbOwned↔CardanoBound) | `leap_to_cardano_v2.mjs`, `leap_to_ckb_v2.mjs`, `leap_orchestrator.mjs` | LIVE round-trip | genesis `0x408d9c28`; S4 `0x838e39f2`; S5 `0xb45812da` |
| **burn→unlock release lock** | `burn_gated_unlock_v2.rs` | **BUILT + VM-TESTED (13 tests), NOT yet deployed** | — (see §3, go-live B) |

Detail: `relayer/onchain/LIVE.md`, `relayer/onchain/V2_DEPLOY_RUNBOOK.md`, `docs/LEAP_V2_GOLIVE.md`,
`spike/ckb-to-cardano/RETURN_TRIP.md`.

### Groth16 leg (Cardano-verifies-CKB) — value binding PROVEN live; full deploy CEREMONY-GATED
| component | file | status | id |
|---|---|---|---|
| leap prover: value-binding **+ reorg K-floor in ONE proof** | `circuit/prover/src/bin/leap_bound_windowed.rs` | BUILT + PROVEN live; **Aiken verifier ACCEPTS** | proof on block 21,388,341, cpu 2.54B |
| on-chain leg verifier | `groth16/validators/cardano_bound.ak` | BUILT + TESTED | expects 5 PI `(window_root,seal,commitment,tip,K)` |
| mint guard (no-inflation/replay/caps) | `groth16/validators/leap_mint_guard.ak` | BUILT + TESTED + RE-AUDITED | — |
| seal-nullifier (Cardano replay-once) + genesis pin | `seal_nullifier.ak` / `seal_thread.ak` | BUILT + TESTED | — |
| reorg caps (aggregate + per-leap) | `leap_ratelimit.ak` / `chiral_policy.ak` | BUILT + TESTED + **ENABLED in derivation** | cap 1,000,000 CKB/window |
| bridge receipt (forward lock, value-locked) | `bridge_lock_v1.rs` | DEPLOYED (code) + live receipt | code `0x1c2589e8`, live lock `0xcfaaf177` (200 CKB) |
| deploy derivation (acyclic apply chain) | `groth16/d6_deploy.py` | DERIVATION DEMO (placeholders) | gated on finalize ceremony + funded key |
| CKB-header window checkpoint on Cardano (ckbcert) | `advance_ckbcert.ak`, `advance_windowed.rs` | BUILT; **NOT deployed** (placeholder NFT) | gated with the leg deploy |

Detail: `spike/ckb-to-cardano/VALUE_BINDING_FIX.md`, `AUTHZ_DOUBLEMINT_AUDIT.md`,
`circuit/RESTRUCTURE.md`, `spike/ckb-to-cardano/circuit/ceremony/`.

---

## 2. Deployed-on-chain inventory (do NOT rebuild these)

**CKB Pudge** (key `~/.chiral/pudge_relayer.key`, addr `ckt1qzda0cr0…dvfumt`):
```
cv_advance          code 0xe877a8028eac379e962a596671d1cd918aceddfa4c4cd78163168ba3b533ac55  type 0x59efd99d
cv_deploy_v2        code 0x75b288f3774bfe553fc72895f940578214e2111208f5a85fb5c5dbf5e9017bf9  LCKP 0xa055798e911a4f7ed074d5e1ee6273683e9a446c70d3e22adab680d70eea5b74
burn_null_registry  code 0x9d2fc246766108bda40b6818abd8adb137ac993699d04ba30ecad4127bbca743  REG  0xdc18fd562bca1834536c926ce8c9d94f608318c3a79a43959c0c46a84265a24e
  registry genesis singleton  0x4e159851cb5459f41fd9548748c48ad378453dad278b0b39a16aa513057714d7:0
bound_asset_v2      code cell 0xf135e9ef…:0   hash 0x4cc7ae86c48944f145dbe3c0f6bd44dda7be623c382e4b31c98feef97c1020b7
bridge_lock_v1      code 0x1c2589e8790232de3d1a728bc3497768e4d0287a02010f99f9e405e323b65b8b  (live receipt tx 0xcfaaf177)
AVK lineage         genesis 0x248ac2b5…:0 -> epoch-1324 0x2519ee3c…:0
```
State files (the source of truth for outpoints — read these, don't re-derive): `relayer/onchain/deployed.json`
(`cv_*`), `chain_state.json` (AVK 1324), `checkpoint_v2.json` (latest 44-byte ckpt), `v2_registry.json`
(registry + bound code), `boundasset_v2_state.json` (live seal + registry root), `bridge_lock_live.json`
(forward receipt body+offsets), `registry_state.json` (off-chain SMT mirror, 3 keys).

**Cardano preview** (key `~/.chiral/preview_relayer.key`, addr `addr_test1vqklgnr…0y8mvq`):
```
v2 binding_lock     addr_test1wprutk2vjvuzgwlsvf956we9ssxqlyfl9jdeywrlv6tsyccz32l5e   seal mint 0x08000078…
seal_policy (baked) ec8d2c74…
owner vkh           2df44c71a4312463ba31315c5aa7725b6ad44cd544a055a3dde915a6
```

---

## 3. Remaining go-live work (categorized; each item says exactly what's done vs left)

### A. Real CKB-header window root for `leap_bound_windowed` — PARTIALLY GATED
- DONE: the combined prover + the on-chain `cardano_bound` expect a real `window_root`.
- The prover's window membership currently uses **stand-in window leaves in the demo**.
- Achievable now (prover/relayer): build the window root from REAL recent CKB headers the AdvanceCKBCert way.
- GATED: the on-chain `ckbcert` checkpoint that PUBLISHES the window root lives on Cardano and is **not deployed**
  (placeholder `CHECKPOINT_NFT` in `d6_deploy.py`); it deploys with the Groth16 leg (ceremony-gated).

### B. Forward funds locked UNDER `burn_gated_unlock_v2` — PARTIALLY GATED
- DONE: the receipt type (`bridge_lock_v1`) + the release lock (`burn_gated_unlock_v2`) compose on one cell —
  proven by `chckb_bridge_cell_roundtrip_unlocks` (VM). The release lock binds amount + **asset identity**
  (policy AND name) + replay-once.
- The live forward demo (`0xcfaaf177`) locked under the **deployer secp lock as a placeholder**.
- Achievable now: construct the forward lock UNDER `burn_gated_unlock_v2` (deployed registry `0xdc18fd56` +
  checkpoint `0xa055798e` + the χCKB policy/name) and a creation→release VM round-trip.
- GATED: the **real χCKB policy id** comes from a live Groth16-leg deploy (`leap_mint_guard`), which is
  ceremony-gated; until then the policy is representative.

### C. STM-quorum-pin redeploy (`cert-verify`) — DEFERRED ON PURPOSE (mainnet-prep, AUDIT-GATED)
- **VERIFIED FACT (corrects any prior assumption): the deployed verifiers `cv_advance` (0xe877a802) and
  `cv_deploy_v2` (0x75b288f3) DO NOT contain the STM pin.** The pin is commit `86ed321` (2026-06-10 23:58),
  AFTER the deploy commits (`8a89ad9` 14:53 / `b537e91` 16:41); `git merge-base --is-ancestor` confirms the
  deploy predates the pin, and the deployed `cv_deploy_v2.bin` was last built in the pre-pin commit.
- The fix IS in source + validated off-chain (real epoch-1324 cert: k=1944, 2345 wins, max idx 16941 → accepts;
  4 forged variants → reject). See `docs/SEC_STM_QUORUM_PIN.md`.
- Putting it on-chain is a **destructive cascade**: new binary → new `cv_*` hashes → re-genesis the AVK chain
  from `PINNED_GENESIS` → re-bake the new LCKP hash into `bound_asset_v2` → redeploy → re-genesis the seal. It
  **resets the live testnet toggle for zero testnet benefit** (no value at risk on testnet) and the project doc
  explicitly says it should follow a **professional cryptographic audit**. So it is correctly deferred.
- **What is safe to do now (and is being staged):** rebuild the STM-pinned binaries, record their new code
  hashes, update `deploy_cv_deploy_v2.mjs::EXPECT`, and keep the cascade runbook ready — WITHOUT executing the
  live re-genesis. Do not tear down the live stack without an explicit go + the audit.

### Other mainnet gates (not testnet blockers)
- Finalize trusted-setup ceremony for the Groth16 leg (`finalize_vk` is a placeholder = leap vk in `d6_deploy`).
- Professional cryptographic audit (STM pin, PINNED_GENESIS vs Mithril genesis cert, BLS domain separation).
- Hosted, monitored relayer daemon.

---

## 4. Doc index (the detail behind each row)
- `relayer/onchain/LIVE.md` — Mithril leg live round-trip (addresses + per-step in-VM checks).
- `relayer/onchain/V2_DEPLOY_RUNBOOK.md` + `docs/LEAP_V2_GOLIVE.md` — v2 deploy operator log + re-run.
- `spike/ckb-to-cardano/VALUE_BINDING_FIX.md` — forward value-binding fix (design + live proof).
- `spike/ckb-to-cardano/AUTHZ_DOUBLEMINT_AUDIT.md` — authz + doublemint re-audit.
- `spike/ckb-to-cardano/RETURN_TRIP.md` — burn→unlock return leg (symmetry table + VM tests).
- `docs/SEC_STM_QUORUM_PIN.md` — the STM quorum finding/fix + the deferred-cascade note.
