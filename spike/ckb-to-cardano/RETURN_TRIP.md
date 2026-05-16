# The χCKB return trip: Cardano burn → CKB unlock (Mithril-gated)

Completes the bidirectional native-token bridge (path B). The **forward** leg (lock CKB → value-bound Groth16
→ mint χCKB on Cardano) is in [VALUE_BINDING_FIX.md](VALUE_BINDING_FIX.md), combined with the reorg K-floor in
`leap_bound_windowed.rs`, and audited in [AUTHZ_DOUBLEMINT_AUDIT.md](AUTHZ_DOUBLEMINT_AUDIT.md). This is the
**return** leg.

## Flow

1. **Cardano — burn χCKB.** `leap_mint_guard.ak` `LeapOutBurn` (a pure negative mint; `authorize_burn` enforces
   exactly `credited` burned, no net mint). This produces a real Cardano burn tx.
2. **Mithril — certify the burn.** The same oracle the ownership-toggle uses: the burn tx is included under a
   Mithril-certified tx-set root, exposed on CKB as the genesis-pinned checkpoint cell (`LCKP‖root`).
3. **CKB — release the locked CKB.** The forward-locked bridge cell carries TWO scripts:
   - **TYPE = `bridge_lock_v1`** — the receipt. On CONSUME (no continuing receipt output) it allows, deferring
     the gate to the lock.
   - **LOCK = `burn_gated_unlock_v2`** — the Mithril-gated release. It reads the burn tx body + its MKMapProof
     from the witness, verifies cert-membership against the authenticated checkpoint, parses the Conway `mint`
     field, and requires a burn of **exactly the bound amount** of **exactly `(χCKB policy, χCKB name)`**, then
     **nullifies** the burn in the global `burn_nullifier_registry` (replay-once).

## Why it's safe (symmetric with the forward leg)

| property | forward (mint) | return (release) |
|---|---|---|
| event authentication | Groth16 of CKB PoW+inclusion (`cardano_bound`) | Mithril cert-membership (`burn_gated_unlock_v2`) |
| value binding | amount derived from `bridge_lock_v1` receipt body in-circuit | amount parsed from the Conway `mint` field, `== -bound` |
| asset identity | FT name pinned in `leap_mint_guard` | `(policy, name)` pinned in the lock args |
| replay-once | `seal_nullifier` (one CKB seal → ≤1 mint) | `burn_nullifier_registry` (one Cardano burn → ≤1 unlock) |
| registry genesis pin | `seal_thread` (one-shot token, empty root) | type-id == `ckbhash(outpoint)`, empty root |

So a given certified burn releases **at most one** cell, of **exactly** the burned amount of the **exact**
asset — the mirror of "one CKB seal mints at most once, of exactly the locked amount."

## Status (CKB-VM proven)

`spike/burn-gated-unlock/integration/tests/v2.rs` (13 real `ckb-testtool` tests, all pass):
- release: `certified_burn_of_bound_amount_unlocks`, `chckb_bridge_cell_roundtrip_unlocks` (the full cell with
  **both** scripts, real χCKB asset, 200 CKB).
- amount binding: `wrong_amount_rejected`; asset identity: `chckb_wrong_asset_name_rejected`,
  `chckb_wrong_policy_rejected`.
- cert: `tampered_proof_rejected`, `missing_checkpoint_rejected`, `malformed_txbody_rejected`.
- replay-once: `missing_registry_rejected`, `replay_same_burn_rejected`, `registry_genesis_*`.

Build note: `burn_gated_unlock_v2` needs the `__sync_*` atomic polyfill (CKB-VM has no A-extension;
`-a,+forced-atomics`) — the `bytes`/molecule `Arc` refcount lowers to `__sync_*_8`. Same polyfill as
`bridge_lock_v1`.

## Remaining for go-live (not blocking the mechanism)

- A relayer path that, on the forward lock, places the funds under `burn_gated_unlock_v2(amount, χCKB policy,
  χCKB name)` (the live forward demo locked under the deployer's secp lock as a placeholder).
- The Mithril checkpoint feeding CKB must be the production one (the cert-verify quorum-pin fix
  [[audit-stm-quorum-pin]] redeployed).
