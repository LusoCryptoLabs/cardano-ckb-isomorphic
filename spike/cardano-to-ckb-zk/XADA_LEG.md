# χADA leg — the SECOND direction (Cardano → CKB → Cardano). Build spec + reuse map.

> **Why this exists.** The bridge today moves **CKB value** in a circle (lock CKB → mint χCKB on Cardano →
> burn χCKB → release CKB). That is a *one-asset* bridge. A real 2-way leap must also move **ADA value**:
> lock ADA on Cardano → **mint χADA on CKB** → burn χADA → release ADA. This doc is the mirror of the live
> χCKB leg. It is a **mirror, not a rebuild**: both verification engines (Mithril-in-CKB-VM and
> Groth16-in-Plutus) are already deployed. What is new is the *value-path glue* for the opposite asset.
> Master index: `../../BRIDGE_STATUS.md`. Forward-leg detail it mirrors: `../ckb-to-cardano/VALUE_BINDING_FIX.md`.

## 0. Symmetry table (read this first)

| role | χCKB leg (LIVE) | χADA leg (THIS doc) | new? |
|---|---|---|---|
| asset that moves | CKB (shannons) | ADA (lovelace) | — |
| wrapped token | χCKB on **Cardano** (policy `86f38509…`, decimals 8) | **χADA on CKB** (xUDT; asset name `cf87414441`, decimals 6) | NEW token |
| **forward** lock | `bridge_lock_v1.rs` (CKB receipt) | `ada_escrow.ak` (Cardano escrow UTxO) | NEW (Aiken) |
| **forward** verify+mint | `cardano_bound.ak` + `leap_mint_guard.ak` (Groth16, on Cardano) | `xada_mint.rs` (Mithril, on CKB) | NEW (CKB-VM) |
| forward oracle | Groth16 (Cardano verifies CKB PoW) | **Mithril** (CKB verifies Cardano stake) | REUSED engine |
| **return** burn | burn χCKB on Cardano | burn χADA on CKB (`xada_mint.rs` burn path emits receipt) | NEW path |
| **return** verify+release | `burn_gated_unlock_v2.rs` (Mithril, on CKB) | `ada_escrow.ak` release (Groth16, on Cardano) | NEW (Aiken) |
| return oracle | Mithril (CKB verifies Cardano burn) | **Groth16** (Cardano verifies CKB burn) | REUSED engine |
| replay-once (forward) | `seal_nullifier.ak` (Cardano SMT) | `burn_nullifier_registry.rs` (CKB SMT, genesis-pinned) | REUSED |
| reorg caps | `leap_ratelimit.ak` / `chiral_policy.ak` | same pattern on CKB side of `xada_mint` | mirror |

**Each leg uses the oracle that points the right way.** Forward χADA (Cardano→CKB) is a *Cardano event CKB
must believe* ⇒ **Mithril** (CKB re-runs a Cardano STM cert in CKB-VM — the exact primitive already deployed
for the χCKB return trip). Return χADA (CKB→Cardano) is a *CKB event Cardano must believe* ⇒ **Groth16** (the
exact primitive already live for the χCKB forward mint).

## 1. Reuse map — what is ALREADY BUILT/DEPLOYED and is consumed verbatim

The forward `xada_mint` CKB type script is assembled from primitives that already exist in
`spike/burn-gated-unlock/src/bin/`:

| primitive | source (verbatim) | role in `xada_mint` |
|---|---|---|
| LCKP authenticated checkpoint read | `bound_asset_v2.rs::checkpoint_root` / `burn_gated_unlock_v2.rs::cert_root_from_checkpoint` | the trusted Cardano finalized tx-set root (deployed: LCKP type `0xa055798e`) |
| two-level MKMap cert-membership proof | `burn_gated_unlock_v2.rs` (witness `R` layout + `MerkleProof::verify` ×2) | prove the escrow tx is certified |
| Conway CBOR reader (`hdr`/`skip`/bounds-checked) | `burn_gated_unlock_v2.rs` | parse the escrow tx body |
| Conway **output** walker + address match + value/datum extract | `bound_asset_v2.rs::seal_at_lock` / `parse` / `seal_*` | read locked **lovelace** + the bound CKB recipient from the escrow output datum |
| genesis-pinned replay-once registry | `burn_nullifier_registry.rs` + `registry_inserts_key` | one escrow lock ⇒ at most one χADA mint, ever |
| `__sync_*` polyfill block | all bins | CKB-VM has no A-extension |
| ckb-testtool rig (synthetic Conway tx + MKMapProof + SMT registry) | `integration/tests/v2.rs` | `xada_mint` tests reuse it wholesale |

The deployed Mithril infrastructure (`cv_deploy_v2` code `0x75b288f3`, LCKP type `0xa055798e`, the AVK
lineage, the burn-nullifier registry genesis `0x4e159851`) is **the same trust anchor** — `xada_mint` plugs
into it; no new light client, no new cert verifier.

## 2. Forward path (Cardano → CKB): lock ADA, mint χADA  ← Phase 2–4, the keystone

### 2.1 `ada_escrow.ak` (NEW, Cardano/Aiken) — the lock side, mirror of `bridge_lock_v1`
A user locks `amount` lovelace at the escrow script address with an inline datum:
```
EscrowDatum {
  ckb_recipient_lock_hash: ByteArray,  // 32B — the CKB lock the χADA must be minted to
  amount: Int,                          // lovelace locked (== output coin; cross-checked)
  nonce: Int,                           // distinguishes equal-value locks (one outpoint = one mint anyway)
}
```
The escrow UTxO **is** the canonical lock receipt (constant-offset, like `bridge_lock_v1`'s 49-byte blob).
*Spending* it = the return-leg release, gated on the Groth16 proof of a CKB χADA-burn (§3). On the forward
leg the escrow output is read-only (CKB just proves it exists + is certified).

### 2.2 `xada_mint.rs` (NEW, CKB-VM) — the keystone, mirror of `leap_mint_guard` + `cardano_bound`
An xUDT-style fungible type script. Its hash IS the χADA policy. `args = escrow_addr(Cardano script address
bytes) ‖ LCKP_type_hash(32, baked) ‖ registry_type_hash(32, baked)`.

Per-tx dispatch on the **net** χADA delta `minted = Σ outputs_of_this_type − Σ inputs_of_this_type`:
- `minted == 0` → **transfer**: allow (normal movement; conservation holds).
- `minted < 0`  → **burn**: allow (Phase 2); Phase 5 requires the burn to emit the return receipt (§3).
- `minted > 0`  → **MINT**: gated. ALL of the following, else fail closed:
  1. **M (Mithril):** `checkpoint_root()` yields `(cert_root, height)`, `height != 0`; the witness carries
     `escrow_tx_body` + its MKMap proof, verified certified under `cert_root` (verbatim from `bound_asset_v2`).
  2. **B (binding):** walk `escrow_tx_body` outputs; find the one at `escrow_addr`; read its lovelace `locked`
     and its inline `EscrowDatum`. Require `datum.amount == locked` and `minted == locked` (χADA 1:1 lovelace).
  3. **R (recipient):** every newly-minted χADA output cell is locked at `datum.ckb_recipient_lock_hash`
     (no minting to an attacker; mirror of `leap_mint_guard`'s recipient binding).
  4. **N (replay-once):** the escrow outpoint `(txid, idx)` is nullified exactly once this tx in the
     genesis-pinned registry (`registry_inserts_key`, keyed `blake2b256(txid‖idx_le)`). One lock ⇒ one mint.
  5. **S (singleton mint):** at most one `xada_mint` type group mints per tx (mirror A6/RQ-8 — serialize mints).

### 2.3 Relayer (NEW glue, Phase 4)
Watch `ada_escrow` for new locks → wait until the lock tx is **Mithril-certified** (in the published LCKP
checkpoint) → build the CKB mint tx (witness = tx_body + MKMap proof; spend+insert the registry) → submit on
Pudge. Mirrors `relayer/onchain/leap_to_ckb_v2.mjs` (same witness shape) + `leap_mint.py` (the Cardano-side mint builder), inverted.

## 3. Return path (CKB → Cardano): burn χADA, release ADA  ← Phase 5, closes the round-trip

1. **CKB burn + receipt:** `xada_mint.rs` burn path requires a `bridge_lock_v1`-style receipt cell binding
   `(amount, cardano_recipient)` (the return mirror of the χCKB forward lock). The burn destroys χADA.
2. **Groth16 proof:** reuse the `leap_bound_windowed` circuit (value-binding + reorg K-floor in one proof),
   **rebound** so the bound "value" is the χADA-**burn** receipt (amount + Cardano recipient) instead of a
   CKB lock. PoW+inclusion machinery is unchanged.
3. **`ada_escrow.ak` release:** verify the Groth16 proof (reuse `cardano_bound.ak`'s verifier) → release
   `amount` lovelace to `cardano_recipient`; nullify the CKB-burn outpoint once (reuse `seal_nullifier.ak`).

This is the most involved half (a circuit rebind + a new release verifier); it is **separable** — Phases 2–4
already deliver the headline ("real ADA lock on Cardano ⇒ real χADA minted on CKB"), and Phase 5 closes the
ADA round-trip.

## 4. Token identity (off-chain display)
χADA = wrapped ADA on CKB. xUDT amount = lovelace, 1:1. **decimals 6** (1 ADA = 1,000,000 units), mirroring
χCKB's decimals 8 (shannons). Registry/sUDT metadata is off-chain (CKB token-info cell / explorer), same
caveat as the χCKB token-registry discussion: integer-on-chain, decimals are display-only.

## 5. Status / phasing
- [x] **P1** this spec (XADA_LEG.md).
- [x] **P2** `xada_mint.rs` (forward mint keystone) — BUILT + TESTED. `spike/burn-gated-unlock/src/bin/xada_mint.rs`
  (118 KB riscv64 bin). 4 host parser tests + **9 in-VM ckb-testtool tests pass** (`integration/tests/xada.rs`):
  the happy path mints exactly the locked lovelace to the committed recipient; wrong amount / datum mismatch /
  wrong recipient / tampered proof / missing checkpoint / missing-or-miskeyed registry / stray χADA input all
  fail closed. Reuses the deployed Mithril core verbatim (LCKP read, MKMap proof, replay registry).
- [x] **P3** `ada_escrow.ak` — BUILT + TESTED. `spike/ckb-to-cardano/groth16/validators/ada_escrow.ak`.
  The Cardano lock side: `EscrowDatum{ckb_recipient, amount, nonce}` is the forward receipt `xada_mint` reads;
  the `Release` path is the return-leg verifier — a Groth16 proof of a CKB χADA-burn (reuses `g16/verifier`,
  the genesis-pinned CKB-header checkpoint, the 5-input `(window_root, seal, commitment, tip, K)` binding, and
  governance-K verbatim from `cardano_bound`), bound to `amount ‖ cardano_recipient`, replay-once via the seal
  registry (`g16/seal_set`), with the released ADA actually paid to the recipient. 10 Aiken tests pass; the
  full groth16 suite still passes (no regression).
- [~] **P4** relayer forward wiring + **live χADA mint on Pudge** from a real preview ADA lock.
  - [x] **P4b** `xada_mint` code cell DEPLOYED on Pudge: tx `0x9ec60f9a…`, codeHash
    `0x92e9403546f98255752c6a150201718cd551291c6cc8537a139e790fafec2fbd` (stripped 56,664 B; re-tested in-VM).
    Baked to the live LCKP checkpoint `0xa055798e` + replay registry `0xdc18fd56`. (`relayer/onchain/deploy_xada_mint.mjs`.)
  - [ ] **P4c** create the `ada_escrow` address on preview + lock real preview ADA with an `EscrowDatum`.
  - [ ] **P4d** relayer builds the χADA mint tx (escrow tx → Mithril cert → MKMap proof vs the live LCKP →
    spend+insert registry → mint) + submit live on Pudge. Adapts `relayer/onchain/leap_to_ckb_v2.mjs` (same
    witness shape; `xada_mint` reads the proof from `input_type` on GroupOutput witness 0).
- [ ] **P5** return leg circuit: rebind the `leap_bound_windowed` prover to a CKB χADA-**burn** receipt + a CKB
  burn-receipt cell (`bridge_lock_v1`-style) + deploy `ada_escrow`'s checkpoint — completes the 2-way round-trip.

Nothing here re-implements the Mithril light client, the cert verifier, the replay registry, or the Groth16
verifier — all four are already deployed and are consumed as-is (see §1).
