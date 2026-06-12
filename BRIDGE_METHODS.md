# Bridge methods runbook

Every operation the Chiral CKB <-> Cardano isomorphic bridge can perform, one line each, grouped by purpose.
This is the "what can I run and how" index. For live deployed hashes and status, read `BRIDGE_STATUS.md` first.
For the v2 leap toggle operator log, see `relayer/onchain/V2_DEPLOY_RUNBOOK.md`.

Conventions: `.mjs` scripts run with `node` on Windows from `relayer/onchain/`. Python Cardano scripts run where
pycardano is installed; scripts that call `aiken` run in WSL (distro `ChiralSP1`). The CKB Rust toolchain and
`ckb-debugger` live in WSL. The relayer key is `~/.chiral/pudge_relayer.key` (never printed or committed). All
of this is testnet only (CKB Pudge, Cardano preview), unaudited.

## 0. Shared libraries (not run directly)
- `relayer/onchain/_signer.mjs`: CKB Pudge client, signer, `myLock`, `balance`, `deployCodeCell`, `plainCells`, `wait`.
- `relayer/onchain/leap_common_v2.mjs`: v2 cell encoders, `alignCheckpointAndWitness`, `pickPlain`, `guard`, `dumpMock` (ckb-debugger mock), the `PROTECTED` code-cell set.
- `cardano/binding/cardano_net.py`: keyless Cardano preview access (Koios + pycardano), `chain_context`, `account`, tolerant TLS.

## 1. Setup and monitoring
- `node check_funds.mjs`: relayer CKB funding snapshot (total, plain spendable, code-cell gap).
- `python cardano/binding/cardano_status.py`: Cardano preview health (tADA, collateral, seal location).
- `node leap_orchestrator.mjs status`: both-chain snapshot (state, balances, registry size, code-cell liveness).
- `node reclaim.mjs --live`: consolidate orphaned plain cells (never touches PROTECTED code/checkpoint cells).

## 2. One-time infrastructure deploys (CKB)
- `node deploy_verifiers.mjs`: publish cert-verify code cells (cv_advance, cv_deploy).
- `node deploy_cv_deploy_v2.mjs`: publish the 44-byte-checkpoint verifier (cv_deploy_v2), bound to bound_asset_v2.
- `node deploy_bound.mjs`: publish bound_asset_v2 (built atomic-free + stripped, bakes CHIRAL_LCKP_TH + CHIRAL_REG_TH).
- `node deploy_regcode.mjs`: publish burn_nullifier_registry code + genesis singleton (CHIRAL_REG_TH).
- `node lc_chain.mjs`: build the light-client AVK chain (genesis epoch + advances), resumable via `chain_state.json`.

## 3. Mithril light-client maintenance (CKB)
- `python spike/light-client-cell/cert-verify/adversarial/advance_check_<N>.py`: derive `ck[N]` from cert N own AVK and `ck[N+1]` from its next AVK, build `wit_<N>.bin`, validate `cv_advance` offline (exit 0 = safe). One file per epoch.
- `node advance_<N>.mjs --live`: broadcast AVK advance N-1 -> N (spend the epoch-(N-1) checkpoint, emit epoch-N). Funds the ~10k-CKB witness cell by recycling the previous (still-live) witness cell.
- `node refresh_checkpoint_v2.mjs`: publish a fresh 44-byte checkpoint (LCKP || root || height) for the CURRENT Mithril cert; recycles the prior witness cell. Required before any cert-gated mint when the cert root has drifted.
- `python relayer/produce_witness.py <cardano_txid>`: emit the MKMapProof witness + certified root for a Cardano tx; `status: ready` means Mithril-certified. (`transcode.py` does the proof->witness byte transform.)

## 4. Mithril leap toggle (CkbOwned <-> CardanoBound, the same living seal)
- `python cardano/binding/mint_seal_ours.py`: mint the seal NFT at `binding_lock` (records `seal-instance-ours.json`).
- `node boundasset_v2.mjs genesis <seal_mint_txid>`: create the genesis CkbOwned bound cell (writes `boundasset_v2_state.json`).
- S4 (CkbOwned -> CardanoBound): `python cardano/binding/leap_to_cardano_ours.py` (Transfer seal) -> wait for cert -> `node leap_to_cardano_v2.mjs [--dump]`.
- S5 (CardanoBound -> CkbOwned): `python cardano/binding/leap_to_ckb_ours.py [recipient_lock_hash]` (LeapToCkb seal) -> wait for cert -> `node leap_to_ckb_v2.mjs [--dump]` (inserts the seal nullifier; recipient pins the result cell's lock).
- `node leap_orchestrator.mjs leg|toggle|run N [recipient]`: drive one leg, a full round-trip, or N toggles, with cert polling, funding auto-reclaim, and `--verify` ckb-debugger pre-flight.
- `node verify_toggle.mjs`: confirm the terminal on-chain toggle state.

## 5. chi-ADA forward leg (lock ADA on Cardano -> mint chi-ADA xUDT on CKB) [Mithril-gated]
- `python spike/ckb-to-cardano/groth16/escrow_lock.py --live`: lock ADA at the `ada_escrow` address with an EscrowDatum (CKB recipient, amount, nonce). Writes `deployed/cardano/preview/xada-escrow.json`. (Set `NONCE` for a fresh escrow.)
- Wait for the escrow tx to be Mithril-certified: `python relayer/produce_witness.py <escrow_tx>` until `ready`. If the AVK is stale, do section 3 (advance + refresh) first.
- `node deploy_xada_owner.mjs` (or `deploy_xada_owner_reclaim.mjs` to fund by reclaiming the old owner cell): deploy the xUDT owner lock; derives the chi-ADA token id = xUDT(args = owner_lock_hash).
- `node xada_xudt_mint.mjs --setup`: create the owner authority cell. Then `CHIRAL_NULL_TAG=01 node xada_xudt_mint.mjs [--dump]`: mint chi-ADA via xUDT owner mode (Mithril cert + escrow binding + tagged replay registry), emitting the Unique info cell IN the issuance tx. `--dump` writes `xada_xudt_dump.json` for ckb-debugger.
- EXPLORER RULE: the Magickbase explorer fixes a token's name/symbol/decimals at its FIRST on-chain sighting, only once. The Unique info cell MUST be in the token id's first transaction, or that id is permanently un-namable on-chain (see BRIDGE_STATUS chi-ADA delta). A new token id needs a new owner hash (the owner args carry a salt byte for this).
- (Legacy) `node xada_mint_relayer.mjs`: the older bespoke type-script mint (not a standard xUDT). `node xada_token_info.mjs`: standalone info cell (does NOT retro-fix a poisoned id).

## 6. chi-CKB forward leg (lock CKB -> mint chi-CKB on Cardano) [Groth16-gated, ceremony-gated]
- Ceremony: run the Powers-of-Tau + delta for `leap_bound_windowed` and finalize (see `spike/ckb-to-cardano/circuit/`), then `python cardano/binding/inject_vk.py` to wire the VK into the Aiken tests.
- `python spike/ckb-to-cardano/groth16/d6_deploy.py` / `deploy_groth16_leg.py`: derive the acyclic deploy chain (policy_thread -> policy_script -> bound -> mint_guard -> ratelimit).
- `python cardano/binding/genesis_ckbcert.py`: genesis the CKB-header checkpoint (ckbcert) on Cardano. `python cardano/binding/genesis_threads.py`: genesis the seal/policy/ratelimit singletons.
- `node bridge_deploy_lock.mjs`: deploy `bridge_lock_v1` and submit the canonical CKB receipt tx (writes `bridge_lock_live.json` with the field offsets the circuit reads).
- `python cardano/binding/leap_mint.py --create` then `--leap`: create the BoundState UTxO, then mint chi-CKB on Cardano (verifies the Groth16 proof on-chain + nullifier insert + ratelimit tick).

## 7. Known gaps (not yet scripted)
- Generalized AVK advance: each epoch currently needs its own `advance_check_<N>.py` + `advance_<N>.mjs`. A single parameterized advance method (epoch in, derive + broadcast) would remove the per-epoch copy.
- Groth16-leg advance ceremony (`advance_windowed`): the on-Cardano ckbcert checkpoint is pinned under a placeholder leap VK; advancing it needs this ceremony. Not scripted.
- Forward-lock switch to `burn_gated_unlock_v2`: a one-line change in `bridge_deploy_lock.mjs` (deployer secp -> burn_gated_unlock_v2 args), gated on the chi-CKB policy existing (ceremony). Not scripted.
- A `GROTH16_LIVE.md` glue runbook wrapping the section-6 sequence end to end.

## 8. Troubleshooting
- cert-gated mint fails with cert-verify code 6 (AVK mismatch): the AVK is stale, run section 3 advance to the current Mithril epoch, then refresh.
- checkpoint root drift between witness and checkpoint: re-run `refresh_checkpoint_v2.mjs` (the mint aligns with up to 5 retries).
- "InsufficientCapacity" on a code-cell deploy: a code cell costs ~1 CKB per byte; reclaim an obsolete code cell (see `deploy_xada_owner_reclaim.mjs` for the pattern) or a leftover witness cell.
- a spend would consume a live code cell: the `PROTECTED` guard throws first; never bypass it.
