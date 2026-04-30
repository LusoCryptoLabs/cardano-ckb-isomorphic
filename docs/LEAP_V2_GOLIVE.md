# Leap v2 — status, the one decision, and the gated go-live

The RGB++-style ownership-toggle leap is **design-complete, implemented, and verified in real VMs on both
chains.** It is **not deployed.** This doc is the bridge from "VM-tested" to "live on testnet": the test
tally, the one open decision (M2), the gated outward-facing steps, and the residuals.

## What's done (Phases 1–5)
- **Design**, adversarially verified over 2 rounds: `LEAP_BRIEF_V2.md`, `RECIPIENT_COMMITMENT.md`,
  `LEAP_DESIGN_REVIEW.md`.
- **On-chain Cardano:** `binding_lock.ak` `LeapToCkb` + `LeapSealDatum` — 5 aiken tests.
- **On-chain CKB:** `bound_asset_v2.rs` (tag dispatcher, all 5 branches, RC, lock-pin, nullifier consumer) —
  riscv build + 6 host unit tests + **8 in-VM (ckb-testtool) tests**: guards, FINALIZE, dispatch arms,
  TRANSITION, both leap directions + negatives, and the leap driven by the **real** nullifier registry SMT.
- **Off-chain:** `relayer/v2_cell.mjs` + `v2_leap_builders.mjs` (`assembleLeapToCkb/Cardano`) — 7 JS tests +
  an assembler smoke test; a **cross-language layout vector** ties the builder's output to the verifier byte
  layout.
- **Terminology:** `TERMINOLOGY.md` (leap = the toggle; old leap-in/out = bind/unbind).

## ⚖️ The one decision — M2 (RQ-4): reorg/finality
v2 has **no on-chain confirmation-depth gate** (RGB++'s `BTC_TIME_lock` is one; ours is the relayer waiting for
a Mithril cert). It is unimplementable as-is — the `LCKP` checkpoint is `"LCKP"‖root` with no slot source.
**Choose one:**
1. **Accept the inherited Mithril assumption** (parity with the live mint/transfer/unbind flows; finality =
   Mithril honest-stake-majority snapshot). Zero extra work. Recommended for the demo + first testnet run.
2. **Fund the verifier upgrade** — extend the TxSetCert verifier + `LCKP` to carry an authenticated
   `root_max_slot`/tip, enabling an on-chain `root_max_slot ≤ tip − K` gate (`LEAP_BRIEF_V2.md` §7.2). A real
   sub-project; warranted only for high-value-at-risk instances.

## 🔒 Gated go-live (outward-facing — needs confirmation + funded keys)
These submit live transactions; do them deliberately, not by inference.
1. **Deploy the scripts** (Pudge): `bound_asset_v2` (new code_hash, disjoint from v1 `0x42f74fbc`), the
   `burn_nullifier_registry` singleton (genesis type-id), reusing the live `LCKP` checkpoint (`0x855231b3`).
2. **Bake the constants:** `LEAP_REGISTRY_TYPE_HASH` = the registry's genesis type-id, `LCKP_TYPE_HASH` already
   set — both via `CHIRAL_REG_TH` / `CHIRAL_LCKP_TH` at build (`option_env`), then a final release build.
3. **Cardano side:** deploy the v2 `binding_lock` (with `LeapToCkb`); wire `cardano_leap.mjs` to emit the
   `LeapToCkb` seal-spend committing the CKB recipient, and the `seal_prime` mint (commitment = `b2b256(state)`)
   for the outbound leg.
4. **End-to-end on testnets** (preview ↔ Pudge, real Mithril certs): bind → **leap-to-CKB** → CKB-native
   transfer → **leap-to-Cardano** → unbind, explorer-visible. This is the real RGB++-style leap, live.

## Residuals (tracked, not blocking the above)
- **RQ-8** (`LEAP_BRIEF_V2.md` §10): the exotic cross-type-group **same-seal** batch — pick the batch registry
  or a verifier-side one-leap-per-tx guard at deploy. Single-seal path is safe + tested.
- **Genesis (S1) positive in-VM test** — deferred (no-input witness-loading subtlety); the branch logic is
  simple (seal-at-lock + commitment + LS pin, all exercised elsewhere).
- **Mint-leg RECIP-1/INFL-1** — the parked Groth16 leg's circuit work (`MINT_AUDIT.md`); not part of the leap.
