# Chiral CKB ⇄ Cardano bridge — MASTER STATUS (what's built, working, wired, deployed)

> **Read this first.** It is the single authoritative index so no one rebuilds what already exists. Every
> component below is marked **BUILT / TESTED / DEPLOYED (hash) / GATED**. Detailed docs are linked, not
> duplicated. Last verified: 2026-06-11 (commit `2284c9c`+).
>
> 🔒 **Security:** see [`SECURITY_FIXES.md`](SECURITY_FIXES.md) — 2026-06-11 adversarial audit. 5 code fixes
> shipped (singleton forge-cert guard, K_MIN floor, nullifier domain separation, escrow placeholder guard);
> 4 operational remediations gate mainnet (real MPC setup, STM-pin+singleton redeploy, advance ceremony/K,
> upgrade-key lockdown). All testnet, no value at risk. **Read before any redeploy** (codeHash re-bake notes).

The bridge has **two legs**. Both are demonstrated live on testnet (CKB Pudge ⇄ Cardano preview).

| leg | direction | who verifies whom | oracle | use |
|---|---|---|---|---|
| **Mithril leg** | CKB verifies a Cardano event | CKB re-runs a Mithril STM cert in CKB-VM | Mithril | ownership toggle **+ the return trip (burn→unlock)** |
| **Groth16 leg** | Cardano verifies CKB consensus | Cardano verifies a Groth16 proof of CKB PoW+inclusion | Groth16 | the forward native-token mint (lock CKB → mint χCKB) |

A native-token round-trip (path B) uses BOTH: forward = Groth16 (mint χCKB), return = Mithril (release CKB).

**Two assets, two directions (true 2-way leap).** The χCKB leg moves **CKB** value (lock CKB → χCKB on
Cardano → back). The mirror **χADA leg** moves **ADA** value (lock ADA → **χADA on CKB** → back) and uses each
oracle the other way: forward χADA = Mithril (CKB verifies the Cardano ADA-lock), return χADA = Groth16
(Cardano verifies the CKB χADA-burn). Spec + status: `spike/cardano-to-ckb-zk/XADA_LEG.md`.
**✅ χADA FORWARD LEG IS LIVE: 5,000,000 χADA minted on CKB Pudge** (mint tx `0x07e81ab7ed04e894…`) from a
real Mithril-certified preview ADA lock — so the bridge now moves value BOTH assets BOTH directions on testnet.
(Required advancing the AVK lineage 1324→1325 + an indefinite-CBOR datum-parser fix.) Return leg = P5a
(burn receipt) done; P5b circuit reuse resolved; P5c (burn ceremony + ckbcert deploy) remains.

---

### Status deltas (2026-06-11 security-hardening session) — read alongside §1/§2

**Proper-xUDT χADA redo (supersedes the bespoke `xada_mint`).** χADA is now a canonical **xUDT** owner-gated
by the bridge. Owner lock `xada_mint_owner` DEPLOYED — code `0xc4e9077f`, codeHash `0xd409ffcf`, owner hash
`0x72f4edb5`; **χADA token id (xUDT type hash) `0xe3a8d7be94191ed6ba7ac647673b5c8b2fd328cfcd970286a2458d8ecf64d73c`**.
Active escrow **`c0be40c4`** (3 ADA, nonce 2) at `addr_test1wpaxh6v…` (block 4,371,689; Mithril-certified).
**✅ The live proper-xUDT mint FIRED** — mint tx **`0x98f9383d2bbc70ef164c54280de587fbd1ef81e0d1222acc78326f2b2252ef26`**,
**3,000,000 χADA** to relayer lock `7a971a3b…` (cell `0x98f9383d…:0`); both the canonical xUDT type script and
the bridge owner lock validated `Run result: 0` in ckb-debugger before submit. χADA is now a real
wallet/DEX-recognized xUDT. **Token metadata published** (xUDT carries only the amount; identity lives in a
Unique-type info cell the explorer indexes) — tx `0x5f78ab97dd667e7dc9973da1cda27eb519fb29c67894c43fb34fb40ffd6968e9`:
name **Chiral ADA**, symbol **xADA**, decimals **6** (mirrors ADA), info cell `…:0`, bound to the token via a
χADA output in the same tx; live χADA cell is now `0x5f78ab97…:1` (`xada_token_info.mjs`). (The original 5M
bespoke χADA `0x07e81ab7` was frozen when its old code cell was reclaimed; intentionally superseded.) Note: the
mint required tolerating Koios's expired TLS cert on the read-only tx-CBOR fetch — safe, re-verified on-chain
(`relay.py::_urlopen_tolerant`).

**Security audit + fixes (see `SECURITY_FIXES.md`).** 5 code fixes shipped to `main` — singleton forge-cert
guard (`f7a725e`), K_MIN reorg floor (`76a2ba0`), per-leg nullifier domain tags (`a442604`), placeholder-vk
escrow guard (`1fdd52e`), compat shim (`CHIRAL_NULL_TAG`). **The SOURCE is now ahead of the DEPLOYED contracts:**
the live `cv_*` (pre-STM-pin AND pre-singleton-guard), `bound_asset_v2`, `xada_mint_owner`, `burn_gated_unlock_v2`
all need redeploy to carry the fixes. Off-chain nullifier builders DEFAULT to untagged to match the live
(pre-#7) contracts; the redeploy sets `CHIRAL_NULL_TAG` per leg (01/02/03).

**Redeploy is funding-blocked.** Relayer plain-spendable ≈ **4,195 CKB**; each cert-verify code cell needs
~100k+ CKB (1 CKB/byte). The ~600k total is locked in the existing code cells, so the only realistic funding
path is reclaiming the old code cells (~500k recoverable) — a deliberate teardown that resets the live demo.

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
| **burn→unlock release lock** | `burn_gated_unlock_v2.rs` | **BUILT + VM-TESTED (15 tests incl. full χCKB round-trip), NOT yet deployed** | — (see §3, go-live B) |
| **χADA forward-mint type script** (lock ADA → mint χADA on CKB) | `burn-gated-unlock/src/bin/xada_mint.rs` | **BUILT + VM-TESTED (4 host + 9 in-VM, fail-closed) + DEPLOYED on Pudge** | code `0x9ec60f9a`, **codeHash `0x92e94035`** (stripped 56,664 B); baked LCKP `0xa055798e` + reg `0xdc18fd56` |
| **χADA burn receipt** (return leg: burn χADA → bind amount+recipient) | `burn-gated-unlock/src/bin/xada_burn_receipt.rs` | **BUILT + VM-TESTED (7 in-VM, fail-closed)**, NOT deployed | self-enforces ΣχADA in−out == amount; `xada_mint` reused unchanged |

Detail: `relayer/onchain/LIVE.md`, `relayer/onchain/V2_DEPLOY_RUNBOOK.md`, `docs/LEAP_V2_GOLIVE.md`,
`spike/ckb-to-cardano/RETURN_TRIP.md`.

### Groth16 leg (Cardano-verifies-CKB) — value binding PROVEN live; full deploy CEREMONY-GATED
| component | file | status | id |
|---|---|---|---|
| leap prover: value-binding **+ reorg K-floor in ONE proof** | `circuit/prover/src/bin/leap_bound_windowed.rs` | BUILT + PROVEN live (REAL 64-header window via `CHIRAL_WINDOW`); **Aiken verifier ACCEPTS** | proof on block 21,388,341, cpu 2.54B |
| on-chain leg verifier | `groth16/validators/cardano_bound.ak` | BUILT + TESTED | expects 5 PI `(window_root,seal,commitment,tip,K)` |
| mint guard (no-inflation/replay/caps) | `groth16/validators/leap_mint_guard.ak` | BUILT + TESTED + RE-AUDITED | — |
| seal-nullifier (Cardano replay-once) + genesis pin | `seal_nullifier.ak` / `seal_thread.ak` | BUILT + TESTED | — |
| reorg caps (aggregate + per-leap) | `leap_ratelimit.ak` / `chiral_policy.ak` | BUILT + TESTED + **ENABLED in derivation** | cap 1,000,000 CKB/window |
| bridge receipt (forward lock, value-locked) | `bridge_lock_v1.rs` | DEPLOYED (code) + live receipt | code `0x1c2589e8`, live lock `0xcfaaf177` (200 CKB) |
| deploy derivation (acyclic apply chain) | `groth16/d6_deploy.py` | wired to REAL ceremony VKs; derives `cardano_bound` `206873ab…` | gated on funded key + ckbcert checkpoint |
| trusted-setup ceremonies (transition + finalize) | `circuit/ceremony/` | ✅ DONE 2026-06-11 (2^21, 3+3); on-chain-accepted | vk_blake2b: transition `b73bd298…`, finalize `d26e679f…` |
| CKB-header window checkpoint on Cardano (ckbcert) | `advance_ckbcert.ak`, `advance_windowed.rs` | BUILT; **NOT deployed** (placeholder NFT) | gated with the leg deploy |
| **χADA escrow + return-leg release verifier** (lock ADA / release on a Groth16 CKB-burn proof) | `groth16/validators/ada_escrow.ak` | **BUILT + TESTED (10 Aiken tests; full suite green)**; LIVE escrow on preview (placeholder return-vk) | escrow tx `0x6f57b569`, addr `addr_test1wpaxh6v…`; 5 ADA locked, datum binds CKB recipient `7a971a3b…` |

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

### A. Real CKB-header window root for `leap_bound_windowed` — ✅ DONE at prover level (on-chain publish gated)
- ✅ DONE (2026-06-11): the relayer now builds a **real window root over 64 real CKB header hashes**
  (`relayer/relayer_window.py` → ring buffer `leaves[h%W]=blockhash(h)`, tip=receipt+K_MIN), and
  `leap_bound_windowed` proves against it when `CHIRAL_WINDOW` is set (the stand-in leaves are demo-only now).
  Verified: real window for block 21,388,341 (slot 53, diff=12) → differential 1 accept + 4 reject, full Groth16
  `verify=true`, **on-chain Aiken verifier ACCEPTS** the real-window proof. The stand-in-leaves fidelity gap is
  removed at the prover/relayer level.
- GATED (with the Groth16-leg deploy): the on-chain `ckbcert` checkpoint that PUBLISHES this window root lives on
  Cardano and is not deployed (placeholder `CHECKPOINT_NFT` in `d6_deploy.py`) — ceremony-gated.

### B. Forward funds locked UNDER `burn_gated_unlock_v2` — ✅ loop proven in VM (live broadcast gated + unsafe now)
- ✅ DONE (2026-06-11): the full loop is proven on CKB-VM (`integration/tests/v2.rs`, 15 tests):
  `chckb_forward_lock_create_valid` (the 200-CKB χCKB cell is a VALID `bridge_lock_v1` CREATE under the release
  lock; `chckb_forward_lock_undercapitalized_rejected` proves capacity==amount), and
  `chckb_bridge_cell_roundtrip_unlocks` (the same cell spec is released by a certified χCKB burn) +
  asset-identity negatives. So forward-create and return-release are proven on the identical cell spec.
- INTENTIONALLY NOT BROADCAST: a LIVE forward lock under `burn_gated_unlock_v2` would strand funds — there is no
  live χCKB to burn until the Groth16 leg (`leap_mint_guard`) is deployed (ceremony-gated). The relayer change
  is a one-line lock swap (deployer secp → `burn_gated_unlock_v2(checkpoint 0xa055798e, amount, χCKB policy,
  registry 0xdc18fd56, χCKB name)`) to apply WHEN the χCKB policy exists.

### C. STM-quorum-pin redeploy (`cert-verify`) — ✅ build-ready & staged; live cascade DEFERRED (audit-gated)
- **VERIFIED FACT (corrects any prior assumption): the deployed verifiers `cv_advance` (0xe877a802) and
  `cv_deploy_v2` (0x75b288f3) DO NOT contain the STM pin.** The pin is commit `86ed321` (2026-06-10 23:58),
  AFTER the deploy commits (`8a89ad9` 14:53 / `b537e91` 16:41); `git merge-base --is-ancestor` confirms the
  deploy predates the pin, and the deployed `cv_deploy_v2.bin` was last built in the pre-pin commit.
- ✅ build-ready (2026-06-11): the STM-pinned source compiles clean for BOTH `cv_deploy` (default) and
  `cv_advance` (`--features advance`) for `riscv64imac`. Validated off-chain (real epoch-1324 cert: k=1944,
  2345 wins, max idx 16941 → accepts; 4 forged variants → reject — `docs/SEC_STM_QUORUM_PIN.md`).
- Putting it on-chain is a **destructive cascade**: new binary → new `cv_*` hashes → re-genesis the AVK chain
  from `PINNED_GENESIS` → re-bake the new LCKP hash into `bound_asset_v2` → redeploy → re-genesis the seal. It
  **resets the live testnet toggle for zero testnet benefit** (no value at risk on testnet) and the project doc
  explicitly says it should follow a **professional cryptographic audit**. So it is correctly DEFERRED — NOT
  executed (executing it would tear down the live toggle). Runbook: rebuild via `cert-verify/adversarial/build.sh`
  → update `deploy_cv_deploy_v2.mjs::EXPECT` to the new hash → deploy code cell → re-establish AVK chain →
  rebuild+redeploy `bound_asset_v2` with the new LCKP hash → re-genesis the seal.

### D. Groth16-leg trusted setup — ✅ DONE (the deploy keystone is cleared)
- ✅ DONE (2026-06-11): real two-phase MPC ceremonies (Powers-of-Tau ×3 + delta ×3, 2^21 domain) over the
  **transition** circuit (`leap_bound_windowed`, vk_blake2b `b73bd298…`) AND the **finalize** circuit
  (`finalize_windowed`, vk_blake2b `d26e679f…`, previously an empty placeholder). Both VKs are **on-chain
  accepted** by `cardano_bound`'s verifier (`bound_windowed_test` + `finalize_test`, recorded in git) and
  **wired into `d6_deploy.py`** — which now derives the full leg (`cardano_bound 206873ab…`, `leap_mint_guard
  4a7903f2…`) against them. Full Aiken suite 208/0.
- The ~440/393 MB `pk.bin` proving keys are local (gitignored, regenerable via `CEREMONY_OUT=...`); the VKs
  themselves are version-controlled inside the two `*_test.ak` files. So the value leg is now **deployable** —
  what remains is the deploy EXECUTION (funded key, `ckbcert` window checkpoint, the two genesis mints), not the
  setup.

### E. Value-leg deploy execution — pre-flight done (2026-06-11); one architectural wrinkle to resolve
Careful pre-flight (no live tx fired) of the live Groth16-leg deploy on Cardano preview:
- ✅ Funding/infra OK: preview key `addr_test1vqklgnr…` has ~9,993 tADA / 4 UTxOs; tx path = `cardano/binding/
  cardano_net.py` (pycardano + Koios, manual ExUnits — Koios has no tx-eval).
- ✅ Genesis datum is proof-consistent: `relayer/validate_window_binding.py` confirms the 32-byte
  `window_root 0x6f01df31…` satisfies `cardano_bound.field_of(window_root) == proof PI[0]` and
  `tip_height 21388353 == PI[3]`. So the pinned `Checkpoint` datum binds the ceremony proof — genesis won't
  brick the leg.
- ✅ The leap tx FITS budget: it runs FOUR scripts (cardano_bound verify + leap_mint_guard mint +
  seal_nullifier 256-SMT insert + leap_ratelimit), summing to ~6.9 B cpu (**69%**) and ~13.7 M mem (**83%** of
  the real 16.5 M preview limit — NOT 14 M). Deployable with ~17% mem headroom; the seal_nullifier 256-SMT
  insert (12.9 M mem) is the dominant cost.
- ✅ RESOLVED (commit `4ab48b8`): the `advance_ckbcert(vk, thread_policy)` ↔ `ckbcert_thread(…, cp_script =
  advance_ckbcert hash)` mutual-parameterization cycle. `advance_ckbcert` drops `thread_policy` and pins the
  lineage by CONTINUITY (`g16/ckbcert.lineage_token`: the sole non-ADA qty-1 token on the input must continue
  on the output). Sound because `cardano_bound` reads the checkpoint by the REAL genesis NFT; +6 adversarial
  tests; suite 220/0. Derivation is now acyclic: `advance_ckbcert(vk) → cp_script → ckbcert_thread(gref,
  pinned, cp_script) → CHECKPOINT_NFT`.
- ✅ RESOLVED (commit `10bca58`): the SECOND cycle `seal_nullifier(thread_policy)` ↔ `seal_thread(genesis_ref,
  reg_script)`. `seal_nullifier` is now continuity-pinned (no `thread_policy`), AND `leap_mint_guard.seal_consumed`
  finds the registry by its **genesis NFT** (exactly-one, fail-closed) instead of by script hash — so a decoy
  registry at the same hash (different token) is never matched and replay-once holds. +adversarial tests
  (`no_lineage_token_rejected`, `continuity_broken_rejected`, `seal_consumed_rejects_decoy_registry_nft`);
  AUTHZ_DOUBLEMINT_AUDIT updated; suite 224/0.
- ✅ FULL ACYCLIC DERIVATION validated (`deploy_groth16_leg.py`, dry): with the real ceremony VKs (ic=6 each)
  the whole leg derives end-to-end — `advance_ckbcert(vk) 255db00f → ckbcert_thread → checkpoint_nft fa03ff57`;
  `seal_nullifier() → seal_thread → seal_registry_nft 491d493d`; `cardano_bound d299c074`; `leap_mint_guard
  c78c3bf5`. The structural blockers are gone; the leg is now deployable.
- ✅ FIRST LIVE GENESIS ON-CHAIN: the **CKB-light-client checkpoint** is deployed on Cardano preview
  (`genesis_ckbcert.py --live`, tx `d80bc0ac…`, confirmed). Mints the one-shot `ckbcert_thread` NFT
  `CHECKPOINT_NFT e66554ae` onto a checkpoint cell at the `advance_ckbcert` address `255db00f`, carrying the
  pinned datum (window_root `6f01df31`, tip `21388353`) that binds the ceremony proof. State →
  `deployed/cardano/preview/ckbcert-genesis.json`. (A pycardano `script_hash == derived policy id` assert now
  guards consistency. The earlier apparent "encoding mismatch" was a reader bug — `compiled()` was grabbing the
  first `.mint` validator in the multi-validator plutus.json instead of `ckbcert_thread`; once filtered by name,
  pycardano == aiken == ledger == `e66554ae`. `d6.val_hash` was correct all along.)
- ✅ FULL GROTH16-LEG INFRASTRUCTURE LIVE on preview (`genesis_threads.py --live`): all 4 genesis singletons
  deployed — ckbcert checkpoint `d80bc0ac` (NFT `e66554ae`), seal registry `08619eda` (`4f234265`), policy cell
  `d49c21b0` (`94bfde5b`, K=12 + sane caps), ratelimit cell `779f747f` (`2ac3ce79`). Derived against them:
  `cardano_bound 3f5b0b74`, `leap_mint_guard b6112ba2`. Manifest → `deployed/cardano/preview/groth16-deploy.json`.
- ✅✅ **LIVE χCKB MINT — the CKB→Cardano value leg is COMPLETE end-to-end on Cardano preview.** Leap tx
  `07a8023d…` (block 4371186, confirmed): a real CKB lock (200 CKB, receipt `0xcfaaf177`) → value-bound Groth16
  proof → **`cardano_bound` verified the proof ON-CHAIN** → `leap_mint_guard` minted exactly **20,000,000,000
  χCKB (200 CKB)** to the bound recipient `Script(2df44c71)` (= `addr_test1wqklgnr…`), with `seal_nullifier`
  recording the seal (replay-once) and `leap_ratelimit` ticking. All 4 scripts passed phase-2.
  `leap_mint.py` (BoundState `2255888` + 4 reference scripts `7d79d5a3`); `validate_leap_binding.py` proved
  seal/commitment bind the proof; `proof.b` (96B G2) indefinite-CBOR chunked.
- Two real bugs were surfaced + fixed by the live run (NO funds lost — pre-inclusion rejections): (1) the
  4-script tx exceeded the 16.5 M Conway mem limit, dominated by the seal 256-deep SMT insert (~15.6 M) →
  **SMT depth 256→128** (low 128 bits of the 32B key; replay-once intact, see `seal_set.ak`) ≈ 8 M, fits.
  (2) `leap_ratelimit` compared the validity-interval width against `max_width=600` "slots" but Plutus V3
  reports `validity_range` in **POSIXTime ms** → it always returned False → **`max_width`/`window_len` → ms**;
  the prover sets `RateState.window_start` to the POSIXTime-ms `now`. Live deploy hashes: checkpoint
  `e66554ae`, cardano_bound `3f5b0b74` (unchanged), seal_registry `19651f80`, ratelimit_thread `c4e8344a`,
  leap_mint_guard `86f38509`.
- Remaining (operability, not value): the advance ceremony (advance_windowed) for an advanceable (vs pinned)
  checkpoint; the relayer should lock the forward CKB under `burn_gated_unlock_v2` so the return trip releases
  it (the live forward receipt used the deployer secp lock). The bridge is now demonstrated LIVE in BOTH
  directions (Mithril toggle/return + Groth16 value mint).
- ckbcert demo deploy note: the *advance* circuit ceremony (`advance_windowed`) is not done, so a live deploy
  would use the leap VK as a placeholder `advance_ckbcert.vk` (checkpoint pinned at the real window state +
  referenced by the leap; advancing needs the advance ceremony + redeploy — a documented follow-up). The CYCLE
  (the structural blocker) is resolved regardless.
- TODO (glue, not built): the genesis-mint SUBMISSION scripts (pattern = `cardano/binding/mint_seal_ours.py`)
  + a `GROTH16_LIVE.md` runbook.

### Other mainnet gates (not testnet blockers)
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
