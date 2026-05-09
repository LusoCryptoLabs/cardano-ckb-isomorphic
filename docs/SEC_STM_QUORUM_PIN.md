# Security finding + fix: STM quorum / total were taken from the witness (cert-verify)

Found while answering "are we production ready?" by auditing the on-chain Mithril cert verifier
(`spike/light-client-cell/cert-verify/src/main.rs`) — the trust root of the whole leap.

## The good news (the architecture is sound)
The verifier does **real, on-chain Mithril STM verification**, not a relayer-trusted root:
- `check_bls` — BLS12-381 aggregate-signature verification via pairings.
- `check_merkle` — every signer's `(mvk, stake)` leaf must be in the Merkle tree committed by `avk_root`.
- `check_lottery` — the STM stake-weighted lottery (φ with `phi_f = 0.2`, the hardcoded `C_NUM/C_DEN = ln 0.8`).
- `check_m1` — `signed_message = Sha256(parts)`.
- `avk_root` is ANCHORED: deploy mode forces it to equal an AVK-checkpoint cell carrying the canonical
  advance-verifier type hash; the advance chain starts at a hardcoded `PINNED_GENESIS` and re-verifies a
  quorum-signed cert at every epoch step. A relayer with no SPO keys cannot forge a checkpoint.

## The finding (critical for mainnet value)
The STM quorum parameter `k` and (in deploy/checkpoint mode) the `total` stake were read **from the witness,
unanchored**:
- `k` came straight from the MWIT witness and was used as the threshold (`count >= ct.k`).
- `avk_checkpoint()` returned only `avk_root`, so `ct.total` was never checked against the authenticated
  checkpoint's total.
- lottery indices were never bounded to the `m` slots.

**Exploit:** an attacker who compromises a *single* registered Mithril SPO signing key can craft a witness
with `k = 1` (and/or a deflated `total`, and/or out-of-range indices), have that one SPO sign a message
carrying a **fake `cardano_transactions_merkle_root`**, and pass all four checks — collapsing the security
from "needs a **stake majority**" to "needs **one SPO key**". Under Mithril's own threat model (some SPOs are
assumed adversarial) this is a real break. Harmless on testnet; unacceptable for mainnet value.

## The fix
Pin the network STM parameters and anchor `total` (commit in `cert-verify/src/main.rs`):
- `STM_K` / `STM_M` are PINNED constants (preview: `k = 1944`, `m = 16948`), build-overridable per network via
  `CHIRAL_STM_K` / `CHIRAL_STM_M` (mainnet has different values).
- `check_lottery` now: rejects `ct.k != STM_K`; rejects any lottery index `>= STM_M`; requires
  `count >= STM_K` (the pinned quorum, not the witness `k`).
- deploy mode: `avk_checkpoint()` also returns the authenticated `total` (checkpoint bytes `[40..48]`), and
  the path asserts `ct.total == ck_total` (new error `17`). Advance mode already anchored `total` (it checks
  the input checkpoint's total == `ct.total`), so the shared `verify()` → `check_lottery` fix secures both.

`phi_f` was already correct: the hardcoded `C_NUM/C_DEN` equals `ln(1 - 0.2)` to 15 digits.

## Validation
- All three build variants (deploy / advance / embedtest) compile with the fix.
- Audited a REAL live cert (epoch 1324): `k = 1944`, **2345** winning indices, max index **16941**, 2 signers
  controlling ~67% stake — so the pinned `K = 1944` / `M = 16948` do NOT reject legitimate certs.
- Ran the fixed `check_lottery` decision logic (the only logic changed; BLS/ev_le/Merkle/avk-anchor untouched),
  per-signer, against the real witness + four forged variants:
  - REAL cert (2345 wins) → **ACCEPT**
  - forged `k = 1` → **REJECT** · index `>= m` → **REJECT** · deflated `total` → **REJECT** · sub-quorum (10
    wins) → **REJECT**

## Deploy status / what's left
The fix is in the verifier source and validated off-chain. Putting it on-chain is the mainnet-prep
redeployment cascade (it changes the binary → new `cv_advance` + `cv_deploy_v2` code hashes → re-establish the
AVK chain from genesis → re-bake the new LCKP type hash into `bound_asset_v2` → redeploy it). The live testnet
stack still runs the pre-fix verifiers (no value at risk). Before mainnet, a **professional cryptographic
audit** should (1) confirm this fix and bound it precisely, (2) run the actual binary against adversarial
witnesses, (3) verify the `PINNED_GENESIS` AVK against Mithril's genesis certificate, and (4) confirm the
BLS hash-to-curve domain separation + the mainnet STM params.
