# Leap v2 — status and the gated go-live

The RGB++-style ownership-toggle leap is **design-complete, implemented, VM-verified on both chains, with every
on-chain residual closed and the off-chain deploy + Cardano wiring built and tested.** What remains is purely
the **outward-facing broadcast** (funded keys + live submission). This doc is the bridge from "done locally" to
"live on testnet."

## What's done (on-chain + off-chain)
- **Design**, adversarially verified over 2 rounds: `LEAP_BRIEF_V2.md`, `RECIPIENT_COMMITMENT.md`,
  `LEAP_DESIGN_REVIEW.md`.
- **On-chain Cardano:** `binding_lock.ak` `LeapToCkb` + `LeapSealDatum` — 5 aiken tests.
- **On-chain CKB:** `bound_asset_v2.rs` (tag dispatcher, all 5 branches, RC, lock-pin, nullifier consumer, M2
  height-bind, RQ-4 checkpoint-conflict guard, RQ-8 one-leap-per-tx guard) — riscv build + **7 host unit tests**
  (incl. the cross-language RC/state-only vectors) + **16 in-VM (ckb-testtool) tests** covering the FULL positive
  matrix **S1–S5** (genesis, transition, finalize, both leap directions), the S5 negatives, both hardening
  guards (RQ-4→53, RQ-8→51), dispatch arms, and the leap driven by the **real** nullifier registry SMT.
- **Off-chain leap builders:** `relayer/v2_cell.mjs` + `v2_leap_builders.mjs` — 7 JS tests + an assembler smoke
  test; a **cross-language layout vector** ties the builder bytes to the verifier layout.
- **Off-chain CKB deploy wiring:** `relayer/deploy_v2.mjs` — derives the immutable code hashes, deploys the
  registry genesis singleton + the bound_asset_v2 code cell (staged, gated `--live`), prints the constants to
  bake. 4 pure smoke tests (empty-SMT-root, code-hash derivation, dep block).
- **Off-chain Cardano v2 wiring:** `relayer/cardano_leap_v2.mjs` — `buildLeapToCkbPlan` (RC keystone) +
  `buildSealPrimeMintPlan` (state-only). 6 JS tests, incl. the **cross-language RC + state-only vectors** that
  match `bound_asset_v2::b2b256` exactly. (The parked Groth16 mint leg stays in `cardano_leap.mjs`, untouched.)
- **Terminology:** `TERMINOLOGY.md` (leap = the toggle; old leap-in/out = bind/unbind).

## ✅ Closed residuals
- **M2 (reorg/finality) — Option A.** The Mithril cert AUTHENTICATES `latest_block_number`; `cert-verify`
  publishes `"LCKP"‖root‖height(8 LE)` (44 B) and advances it **monotonically**; `bound_asset_v2` binds each leap
  to a non-zero authenticated finalized height (`return 6`). Mithril certifies immutable (finalized) data, so
  this makes the inherited finality explicit + on-chain-checked. A literal `tip − K` gate is redundant and
  deliberately unbuilt (`LEAP_BRIEF_V2.md` §7).
- **RQ-4 (checkpoint singleton).** The LCKP checkpoint is a type-id singleton; `checkpoint_root()` scans all
  cell-deps and **fails closed (`return 53`)** if two trusted checkpoints disagree (in-VM tested).
- **RQ-8 (cross-group same-seal batch).** `count_instances()` rejects any tx with >1 bound-cell of the verifier's
  own CODE among inputs (`51`) or outputs (`52`) — one-leap-per-tx across all instances (in-VM tested).
- **S1 genesis** positive path now in-VM tested (`v2_leap::s1_genesis_accepts`) — the matrix is complete.

## 🔒 Gated go-live (outward-facing — needs confirmation + funded keys)
These submit live transactions; do them deliberately, not by inference.
1. **Upgraded checkpoint (CHIRAL_LCKP_TH).** M2 changed the checkpoint format (36 → **44 bytes**), so v2 needs the
   **upgraded `cert-verify` (44-byte) checkpoint lineage** — NOT the live 36-byte `0x855231b3`. Deploy/identify it
   with the light-client tooling and take its **type hash** → `CHIRAL_LCKP_TH`.
2. **Deploy the v2 CKB scripts** (Pudge), staged via `relayer/deploy_v2.mjs`:
   - `node deploy_v2.mjs` → dry plan (code hashes + steps).
   - `… --live --stage registry` → deploys the `burn_nullifier_registry` genesis singleton → prints `CHIRAL_REG_TH`.
   - rebuild: `CHIRAL_LCKP_TH=… CHIRAL_REG_TH=… cargo build --release --bin bound_asset_v2 …`.
   - `… --live --stage bound` → deploys the immutable `bound_asset_v2` code cell (new code_hash, disjoint from v1
     `0x42f74fbc`) → prints `V2_BOUND_CODE_HASH` + the leap cell-dep block.
3. **Cardano side:** deploy the v2 `binding_lock` (with `LeapToCkb`); drive `cardano_leap_v2.mjs`
   (`buildLeapToCkbPlan` / `buildSealPrimeMintPlan`) through your Cardano lib (Lucid/MeshJS/cardano-cli) to emit
   the owner-signed seal-spend (RC datum) and the one-shot `seal_prime` mint.
4. **End-to-end on testnets** (preview ↔ Pudge, real Mithril certs): genesis → **leap-to-CKB** → CKB-native
   transfer → **leap-to-Cardano** → finalize, explorer-visible. The real RGB++-style leap, live.

## Residuals (tracked, not blocking)
- **Genesis (S1)** is now positively tested in-VM; no open positive branches remain.
- **Mint-leg RECIP-1/INFL-1** — the parked Groth16 leg's circuit work (`MINT_AUDIT.md`); not part of the v2 leap.
