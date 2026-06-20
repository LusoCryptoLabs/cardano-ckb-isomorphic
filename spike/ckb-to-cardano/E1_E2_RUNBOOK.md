# E1 / E2 execution runbook (post-pilot, gated on sign-off)

## STATUS (2026-06-20)
- **E1 — DONE + LIVE + END-TO-END ON-CHAIN VALIDATED (key fix 2026-06-20).** History: the cutover baked a
  ceremony vk → policy `92832ec4…` (replacing `bcd28c5f`). A **headless forward-mint dry-run on 2026-06-20
  caught a critical regression**: the on-disk relay_bind ceremony key (468 MB, re-generated at 04:28, larger
  than the cutover's 446 MB — i.e. the validated key was later overwritten by a re-run, never re-validated)
  was **internally inconsistent** — a fresh proof from it **failed verification against its own vk**
  (`arkworks verify=false`, prover panics at relay_bind.rs:155). Root cause isolated to the **custom hand-rolled
  MPC param assembly** (`setup_mpc::derive_pk`): the arkworks-native (seeded) path verifies fine on the identical
  circuit+witness; only the custom ceremony key fails. So the forward mint was BROKEN (no tester could mint).
  **FIX (Option A — secure single-party setup):** added a `CHIRAL_SECURE_SETUP` path to `relay_bind.rs` —
  arkworks-native `circuit_specific_setup` seeded from `/dev/urandom` (entropy discarded; non-forgeable, NOT a
  public seed). Regenerated a CONSISTENT key (`arkworks verify=true`), backed up the broken one as
  `relay_bind_pk.bin.broken`. Re-baked the policy → **new χCKB policy
  `08db0245dd235757b8c96777e38b8a8e540487a1fa496eae7dae5128`** (replaces `92832ec4`). **VALIDATED ON-CHAIN
  HEADLESSLY:** lock 300 CKB `0xe758d8c591f9…` (Pudge) → `relay_bind` prove with the new key (verify=true,
  binds 300 CKB → recip `2df44c71`) → re-baked policy via `build_chiral_policy.py` → **`cardano_mint_bound.py`
  minted 30000000000 χCKB on Cardano (`6ce737afd9a3…`, block 4400811)** — Blockfrost evaluated the
  `zk_chiral_mint` Plutus policy against the proof and ACCEPTED it = the on-chain g16 verify passes under the
  new policy. Wired everywhere (applied.json `→08db0245`; server.mjs default + derives from applied.json; .env +
  bridge_lock_unified updated). Old applied.json backed up (`.bak-92832ec4`).
  - **MAINNET HARDENING (deferred):** the custom MPC ceremony (`derive_pk`) is still broken — fix it + run a
    genuinely-independent multi-party ceremony before real value. On testnet the single-party setup is
    security-equivalent to the prior ceremony (whose transcript admits contributor independence is simulated
    on one machine).
  - **Remaining (non-autonomous):** a browser-wallet mint+burn on the new policy (self-custody CIP-30 signing,
    identical redeemer/script to the headless `cardano_mint_bound.py` just validated).
- **E2 — DONE + LIVE (full integration return validated on-chain).** Forward-minted 4 χADA (Mithril-certified
  lock), burned it, `ckpt_reanchor`'d the STABLE registry in place (tip 21483571, NFT preserved), proved the
  burn, locked the STABLE escrow `904bccd8…` (baked with the registry NFT), and `ada_escrow.Release` **verified
  the Groth16 proof on-chain against the registry cell + released 4 ADA** → `2df44c71…` (release tx
  `2edacbe06f10f2d6…`; `[guard]` confirmed proof window_root/tip bound the registry datum). **NO CHURN PROVEN:**
  the registry cell is still live after the return (reference input) and the escrow + ref scripts (`4307ede1…`)
  are deployed ONCE and reusable — the entire E2 benefit. Run a return with `CHIRAL_STABLE_REGISTRY=1`.
  Earlier validation steps below:
- **E2 — CORE LIVE on-chain; integration return remaining.** Validator `ckpt_registry.ak` verified (4 tests).
  **LIVE:** stable registry genesis'd (tx `71887fcde8cac04c…`, NFT `b1a46defe938157977f50aa8c03f8dc3c78f5bdba500c80b59f2b9e1`
  at script `5b830eb3c5d739246ccf81ebabfb4535d187df05…`, pinned tip 21483210); **governor re-anchor validated
  on-chain** (tx `e602cf45a3e29a42…`, 21483210→21483222 — continuity + monotonic tip enforced). The novel
  mechanism (stable cell re-anchored in place vs re-genesis'd) works in production.
  **Discovery that simplifies the rest:** `escrow_lock.py`/`release_xada.py` need NO code edit — their existing
  `CHIRAL_CHECKPOINT_NFT` override already bakes any NFT, so the stable escrow is just
  `CHIRAL_CHECKPOINT_NFT=b1a46def… CHIRAL_RETURN_VK=<burn vk>`.
  **Remaining (integration return, needs the Mithril-gated χADA flow):** deploy the stable ada_escrow + ref
  scripts (~190 ADA), rewire `xada_burn_orchestrate.mjs` step 3 (`genesis_ckbcert` → `ckpt_reanchor` + the
  registry NFT), and re-validate two returns end-to-end. Each return needs a FRESH χADA burn bound to the
  registry's (forward-only) window — i.e. a forward χADA mint (Mithril cert ~6-7 min) → burn → re-anchor →
  prove → release. Mechanically identical to the already-proven return, only the checkpoint source changes
  (fresh genesis → stable registry), so it's wiring validation, not new mechanism.

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
