# Security Fixes — Chiral CKB ⇄ Cardano bridge

Tracking doc for the 2026-06-11 adversarial security audit and its remediations.
Master status doc: `BRIDGE_STATUS.md`. All work below is on **testnet** (Pudge / preview); **no real value is at risk**.

## Audit summary

A 6-auditor adversarial review (one per attack class: Mithril cert-verify, mint/value-conservation,
replay/SMT registry, Groth16 return leg, reorg/economic, backdoors/governance/trusted-setup) plus direct
source verification. **Verdict:** the forward-leg on-chain SAFETY is sound — a malicious *relayer* cannot
steal or forge on the mint path (owner-mode, value conservation, recipient binding, replay-once all verified).
The open issues are in the *oracle* trust (Mithril cert verification + Groth16 trusted setup) and operational
posture (single keys, placeholder vks, reorg params).

---

## Shipped code fixes (committed to `main`)

| # | Sev | Fix | Commit | Test evidence |
|---|-----|-----|--------|---------------|
| 1 | 🔴 CRITICAL | **Singleton guard on Mithril checkpoint scripts.** `cert-verify` advance + deploy modes validated only `GroupOutput[0]`; an attacker could ride a 2nd output (or use the public-constant genesis branch permissionlessly) wearing the trusted `ADV_TYPEHASH`/`LCKP` type with forged AVK/tx-root data, accepted downstream by type-hash alone → forged cert → unbacked mint. Now rejects any 2nd group input/output (codes 40–45), mirroring `bound_asset_v2`/`burn_nullifier_registry`. | `f7a725e` | adversarial suite **28/28** (new Battery D: 5 sibling-forgery attacks rejected; all happy paths still accept) |
| 1b | 🔴 | Same guard added to the **superseded** `advance-cert` / `txset-cert` prototypes (marked superseded) so a revival isn't silently vulnerable. | `f7a725e` | both compile clean |
| 8 | 🟡 MEDIUM | **On-chain K_MIN reorg floor.** `read_k` (ada_escrow, cardano_bound) + chiral_policy update clamped K to `[0,32]`; the real floor (circuit `kmin=12`) was in-circuit only, so a governor could set a sub-floor (reorg-unsafe) K on-chain. Now `const k_min=12`, bound `[k_min,32]` in all three. | `76a2ba0` | `aiken check` **123 checks, 0 errors** (new `k_below_floor_rejected`: K=11 → rejected) |
| 7 | 🟡 MEDIUM | **Per-leg nullifier domain separation.** The shared replay-once registry keyed on `blake2b256` of raw preimages with no domain tag; the χADA-mint (escrow body) and CKB-release (burn body) legs shared the same keyspace + hash. Now a 1-byte leg tag prefixes the preimage on-chain **and** off-chain: `0x01` χADA-mint, `0x02` CKB-release, `0x03` χCKB-leap. The cert-proof leaf stays untagged. Domain separation is **safety-monotone** (distinct tags can only make keys more disjoint — worst case is a caught liveness failure, never a double-spend). | `a442604` | integration **31/31** (v2 15, xada 9, xada_burn 7); leg `0x03` on-chain↔off-chain key parity verified directly |
| 4 | 🟠 HIGH (guard) | **Placeholder-vk escrow funding guard.** The `ada_escrow` Release path verifies the return-vk, currently the leap **placeholder** whose proving key is on disk → drainable. `escrow_lock.py` now refuses `--live` funding > `DEMO_MAX` (5 ADA) while VK is the placeholder; warns every run; lifts when the real burn-vk is set; `CHIRAL_ESCROW_FORCE=1` overrides for throwaway demos. | `1fdd52e` | logic-tested (refuses 10 ADA at placeholder; allows 3-ADA demo / real-vk / FORCE) |

### Redeploy coordination notes (REQUIRED on the next on-chain deploy)
- **Fix #1 changes `cv_advance`'s codeHash** → its type-hash changes. The `ADV_TYPEHASH` constant in
  `cert-verify/src/main.rs` (deploy mode) MUST be re-baked to the new advance verifier's type-hash, or the
  deploy-mode avk binding will reject the (new) genuine checkpoint.
- **Fix #7 changes the deployed registry-consumer codeHashes** (`xada_mint(_owner)`, `burn_gated_unlock_v2`,
  `bound_asset_v2`). They must be redeployed together with the matching off-chain builders. Old (untagged)
  keys already in the live SMT remain valid as "used"; new mints/leaps insert tagged keys — **no migration**.
- Fixes #1 and #3 (STM pin, below) must ship **together**: the STM-quorum pin alone does NOT close the
  singleton forge-cert path, and the singleton guard alone does not close the witness-supplied-k path.

---

## Operational remediations still required before any mainnet value

These cannot be closed by a source edit alone — they need ceremonies, redeploys, or key-management decisions.

| # | Sev | What | Required action |
|---|-----|------|-----------------|
| 2 | 🔴 CRITICAL | **Groth16 trusted setup is single-operator** (`circuit/prover/src/setup_mpc.rs` runs all contributions in one process from one RNG). The trapdoor was never destroyed → whoever ran it can forge any proof → unlimited unbacked mint. Code self-documents this as a sandbox caveat. | Import a recognized public Powers-of-Tau (e.g. Hermez/perpetual-PoT) and run a genuine **multi-party phase-2** with independent contributors who each destroy their secret. Re-bake all vks. Do NOT market the current ceremony as production-grade. |
| 3 | 🟠 HIGH | **Deployed `cv_advance` (`0xe877a802`) / `cv_deploy_v2` (`0x75b288f3`) predate the STM-quorum pin** — `k`/`total` are witness-supplied, so one compromised SPO key forges a cert. The pin exists in source (`STM_K=1944`, `STM_M=16948`) but is not deployed. | Redeploy the cert-verify family with the STM pin **and** the singleton guard (#1) together. Re-bake `ADV_TYPEHASH`. Re-pin the AVK genesis/lineage. |
| 5 | 🟠 HIGH | **Groth16 reorg defense not actually running.** The checkpoint tip/window_root are operator-pinned (`total_difficulty=0`); the cumulative-PoW `advance_ckbcert` ceremony is not done. K=12 (~2.5 min) is far below CKB finality and W=64 caps K≤63. Relayer confirms at depth 1. | Run the `advance_windowed` ceremony + deploy a real advanceable checkpoint so the tip is PoW-backed. Raise K (and W) to a CKB-finality-grade depth, or re-derive the economic caps as the design header requires. Raise relayer confirmation depth above 1. |
| 6 | 🟡 MEDIUM | **Single-key upgrade + governance.** Every code cell is locked by the relayer's plain secp key (no timelock/multisig); a single governor can pause forever / (pre-#8) set K low. Mitigated for retroactivity by `hashType:data1` (a code swap can't rewrite already-minted cells). | Lock down the upgrade authority (burn or governance + timelock) and the governor (multisig + timelock + rotation/recovery) — the project's deferred "T-1". Do this LAST, since locking blocks further upgrades. |

---

## What was verified CLEAN (no change needed)
- xUDT owner-mode mint: no bypass — `xada_mint_owner` runs the full bind on every spend (no early-return / mode-flag / `--setup` shortcut).
- Value conservation: `checked_add`, `minted == locked` 1:1, no overflow.
- Recipient binding: minted output forced to the certified recipient; all-zero lock rejected.
- Replay-once SMT: genesis type-id singleton, monotonic absent→present only, un-rewindable.
- BLS-STM core: genuine pairing check, genesis-AVK pinned, no stub/backdoor.
- Groth16 5-input binding: all bound to on-chain facts, vk pinned compile-time (except the placeholder escrow, #4).
- No hidden code backdoors (no debug/admin/magic-witness branch).
- Mithril leg is reorg-immune as designed (settled-snapshot binding, monotonic height) — reorg risk is only the Groth16 return direction (#5).
