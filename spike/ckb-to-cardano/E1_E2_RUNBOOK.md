# E1 / E2 execution runbook (post-pilot, gated on sign-off)

## STATUS (2026-06-20)
- **E1 — DONE + LIVE.** Ran the relay_bind MPC ceremony (1,543,533 constraints / 2^21; phase-1 PoT 3 +
  phase-2 delta 3, all verified; arkworks verify=true; pk 446 MB). Baked the ceremony vk → **new χCKB policy
  `92832ec45733a5e44d06722a878ffaa264ec9fe214b532c18ead358e`** (replaces `bcd28c5f`). **Linchpin validated:**
  the ceremony proof verifies under the on-chain g16 verifier (`live_relayer_leap_verifies` PASS); emit produces
  valid mint params under the new policy (qty==amount). Wired everywhere (applied.json overwritten; server.mjs
  derives CHI_POLICY_ID from applied.json + proves with `CEREMONY_PK`; .env + bridge_lock_unified updated).
  Old applied.json backed up (`.bak-bcd28c5f`, gitignored). **Remaining: one browser mint+burn dry-run** (the
  self-custody step I can't run autonomously) before re-inviting testers.
- **E2 — DEPLOY-READY (live cutover staged).** Validator `ckpt_registry.ak` verified (4 tests pass, blueprint
  emits, no existing-hash collateral). Drivers `ckpt_registry_genesis.py` + `ckpt_reanchor.py` authored and
  `--dry` validated (both derive the same script `5b830eb3c5d739246ccf81ebabfb4535d187df0524e8d8ea88f1c2f1`;
  governor = relayer cred `2df44c71…`). **Remaining (one focused on-chain session — the deferrable part):**
  genesis the registry `--live` (anchor from `advance_relayer.py init`), swap `escrow_lock.py`/`release_xada.py`
  `derive()` to bake the stable registry NFT, rewire `xada_burn_orchestrate.mjs` step 3 to `ckpt_reanchor.py` +
  the stable escrow, then re-validate two returns. These touch the LIVE return path so they go together.

---


Derived from the 9-agent blast-radius analysis (2026-06-20). **Sequencing decision: pilot the current
optimized deployment first → E1 → defer E2.** All the *off-chain* prep below is safe (no chain mutation);
every **IRREVERSIBLE** step is gated and must not run without explicit sign-off + the stated preconditions.

---

## E1 — close the forgeable-vk hole (relay_bind → ceremony key)

**Why:** `relay_bind.rs` ran `StdRng::seed_from_u64(7)` + `circuit_specific_setup` per request — a
deterministic, publicly-recoverable-toxic-waste vk. That vk is a **compile-time parameter** of the deployed
`zk_chiral_mint` policy, so it backs a **forgeable** χCKB mint. (Confirmed mechanism: a different vk →
different applied script → different policy id; verified by reproducing the build — see the caveat below.)

**Decision (Q2): new ceremony for the standalone 3-input relay_bind circuit** (smallest on-chain blast radius;
the deployed validator stays 3-input/4-IC). The bigger alternative — migrate the forward mint onto the
already-ceremonied 5-input `leap_bound_windowed` circuit (reuses its key + adds the reorg K-floor relay_bind
lacks) — is tracked as a **separate** "unify circuits + K-floor" follow-up, not folded into a security cutover.

### Done (safe, shipped in this branch)
- `relay_bind.rs`: added the `CEREMONY_OUT` / `CEREMONY_PK` / seeded-dev-fallback selector (verbatim shape from
  `advance_live.rs` / `leap_bound_windowed.rs`) + `#[derive(Clone)]` on `RelayBind`. **The seeded path is
  preserved as the dev fallback, so the current pilot forward leg is unchanged.** Builds clean (`cargo build
  --release --bin relay_bind`).

### Caveat found during prep (cutover precondition)
The seeded vk in `circuit/prover/leap_proof.bind.json` builds policy `bb8afed3…`, **not** the live `bcd28c5f…`
— that artifact is from a **different relay_bind circuit structure** (MMR path depth). The ceremony bakes the
circuit *structure*, so before cutover: **build relay_bind from the exact production circuit and run the
ceremony over a witness with the production MMR depth** (or knowingly accept the new structure — E1 mints a new
policy regardless). Confirm `vk_cbor_bytes == 561` / IC length 4 on the ceremony redeemer (else wrong circuit).

### Still to do at cutover (off-chain prep is safe; deploy steps are IRREVERSIBLE)
1. (optional, safe) Factor `relay_bind` main assembly into `build_circuit()` + add a `serve()` via
   `setup_mpc::serve_warm` so the forward leg warm-serves once it has a ceremony key (mirror leap's serve()).
2. (safe) Back up `zk_chiral_mint.applied.json`, `server.mjs:67` `CHI_POLICY_ID`, `deploy/.env`,
   `bridge_lock_unified.mjs:18` (already-stale `3120e1ba` default — fix in the same change), `unified_receipt.json`.
3. **DRAIN (on-chain, coordinated):** announce the swap; burn/settle every χCKB + forward receipt under
   `bcd28c5f` so nothing strands (the cutover is permanent for un-drained positions). Verify zero in-flight locks.
4. **IRREVERSIBLE-A (ceremony):** `CEREMONY_OUT=<dir> relay_bind <witness> <bridge_lock>` → `relay_bind_pk.bin`
   + transcript. *Sign-off needed: who are the ≥1 genuinely-independent contributors* (a single-box scripted run
   only marginally beats the seed). Optionally `CHIRAL_BAKE_UC=1` for the `.uc` fast-load sidecar.
5. **IRREVERSIBLE-B (new policy):** `CEREMONY_PK=… relay_bind … > red.json`; `build_chiral_policy.py red.json
   chiCKB zk_chiral_mint.applied.json` → **new policy id**.
6. **CONFIG cutover (irreversible to testers):** update `CHI_POLICY_ID` (server default — better: derive from
   `applied.json` at startup to kill drift), `deploy/.env`, `bridge_lock_unified.mjs`; regenerate
   `unified_receipt.json` bgArgs; restart the dapp + prover with `CEREMONY_PK=relay_bind_pk.bin`.
7. **RE-VALIDATE (mandatory):** full forward round trip on the new policy (lock → relay_bind prove → mint qty==
   locked → burn → Mithril-certify → keyless `burn_gated_unlock_v2` release — it reads policy from per-lock args,
   **no code-cell redeploy**). Confirm IC length stays 4 (`verifier.ak` pins `length(inputs)==length(ic_rest)`).
   Only re-invite testers when `/api/health` is `ready`.

---

## E2 — stable χADA return escrow (kill the per-return re-anchor churn)

**Why:** the return re-anchors the checkpoint per return (`genesis_ckbcert.py` mints a FRESH thread NFT each
time); since `ada_escrow` bakes the checkpoint NFT as a compile-time param, a new NFT → new escrow script → ref
scripts redeployed (~190 ADA) + ~3-4 min churn **every return**.

**Good news from the analysis (verdict: claim REFUTED):** E2 scoped to the return leg **breaks nothing testers
touch** — the forward lock address testers pay is the owner-lock-baked static address (`707a6be9…`, → the χADA
token id), served from a static file; the return escrow is already isolated (`CHIRAL_ESCROW_NO_OVERRIDE` +
`CHIRAL_ESCROW_OUT=xada-return-escrow.json`). Only the transient return escrow address changes, once.

**Design decision: rolling-single + governor-gated** (the dapp serializes returns via `xadaReturnGate`, so a
single rolling "current checkpoint" needs no SMT — sidestepping the per-tx ExUnits budget risk a 128-deep set
fold would add on top of the seal Insert). **Trust is identical to today** (the per-return re-genesis is already
a trusted anchor); a trustless always-current checkpoint stays blocked by the per-block PoW wall
(`circuit/CHECKPOINT_THROUGHPUT.md`).

### Done (safe, shipped in this branch)
- `groth16/validators/ckpt_registry.ak` (NEW): a stable checkpoint cell governed by a **governor-gated in-place
  re-anchor** = `advance_ckbcert` **minus the SNARK, plus a governor signature** + lineage-token continuity +
  monotonic tip. Governor baked as a param so the datum stays a pure `Checkpoint` → **`ada_escrow` needs no
  source change**. Compiles + 4 tests pass (`aiken check`): re-anchor-ok, unsigned-rejected, rollback-rejected,
  token-dropped-rejected. Genesis **reuses the existing `ckbcert_thread`** (pinned at `ckpt_registry`'s hash).

### Still to do at deploy (off-chain authoring is safe; genesis/deploy steps are IRREVERSIBLE)
1. (safe, author at deploy) `ckpt_registry_genesis.py` — clone the genesis half of `genesis_ckbcert.py`: mint the
   stable NFT (via `ckbcert_thread`, gref one-shot) onto a genesis checkpoint cell at `ckpt_registry`'s hash;
   write `deployed/cardano/preview/ckpt-registry.json {registry_nft, registry_script, genesis_tx}`.
2. (safe, author at deploy) `ckpt_reanchor.py` — governor-signed spend of the stable cell via `ReAnchor{…}` to a
   fresh burn+K_MIN anchor (replaces the per-return `genesis_ckbcert.py --live`).
3. (safe, author at deploy) `escrow_lock.py` / `release_xada.py` `derive()`: bake the **stable registry NFT**
   instead of `M["checkpoint_nft"]`; keep `CHIRAL_ESCROW_NO_OVERRIDE`/`OUT` so the FORWARD config is untouched.
4. (safe, author at deploy) `xada_burn_orchestrate.mjs`: replace step-3 re-anchor + per-return ref-script deploy
   with `ckpt_reanchor.py` + Release against the **stable pre-funded escrow + deploy-once ref scripts**. Preserve
   `xada_seal_state.json` SMT root continuity across the one-time escrow swap.
5. **IRREVERSIBLE-A:** `ckpt_registry_genesis.py` mints the stable registry NFT (one-time). *Sign-off.*
6. **IRREVERSIBLE-B (return-leg only):** deploy the registry-bound `ada_escrow` + ref scripts once. *Sign-off must
   confirm the forward leg is NOT re-derived.*
7. **RE-VALIDATE:** two consecutive returns through the stable escrow (exercise the repeated-return SMT path);
   confirm ExUnits stay under the per-tx cap with the extra reference input.

---

## Irreversible triggers needing explicit sign-off
- **E1-A** ceremony run (trust event — needs the contributor decision).
- **E1-B** new policy minted into existence (replaces `bcd28c5f`).
- **E1-CONFIG** flipping live `CHI_POLICY_ID` — strands un-drained old positions **permanently**; needs DRAIN done + zero in-flight.
- **E2-A** registry NFT genesis.
- **E2-B** registry-bound escrow + ref-script deploy (forward leg must stay untouched).
- **E2-reanchor** governor authority + monotonic-tip are the soundness crux — a permissive re-anchor lets a forged window drain the escrow.

Before any irreversible step: dry-run `_restore_code_cell.mjs` against the exact state files each redeploy touches so revert is proven.
