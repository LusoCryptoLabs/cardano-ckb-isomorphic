# Cross-chain status — what's done, and exactly what reaching a live transfer takes

> **✅ RESOLVED (2026-06) — the live cross-chain transfer was reached.** This doc sized the path
> (items 1–6) from "verify Cardano on CKB" to a live transfer; **all six landed**: MKMapProof
> in-script (`spike/cross-chain/`), tx-root binding (`TxSetCert`, `0xe4e1b0c6`), witness-driven
> verifier + relayer transcode (`spike/phase1/`, `relayer/`), bound cell + binding lock (Phase 3,
> live), the SNARK-lottery target (`spike/phase2/`), and the live preview↔Pudge lifecycle
> (`LIVE_STATUS.md`). Kept as the audit trail of how it was sized. Current state: `CHIRAL_STATUS.md`.
>
> Honest map from "verify Cardano on CKB" (done) to a live cross-chain transfer.
> No hand-waving: each remaining item is sized against real data already gathered.

## Done (proven in CKB-VM on real preview data)

- **Full Mithril certificate verify** — aggregate BLS + stake lottery (all 2330 indices) +
  batch-Merkle membership + quorum, on a real preview cert. `spike/mithril-verify/`.
- **AdvanceCert type script** — a checkpoint cell `{epoch, avk_root, total_stake}` that verifies a
  real cert against its current avk and rolls forward (epoch 320→321). Works in CKB-VM at
  **2.46e9 cycles (~70% of a block)**; once per epoch/checkpoint. `spike/light-client-cell/`.

This is the load-bearing capability: **a real Cardano certificate verified inside the CKB VM.**

## The cross-chain primitive: prove a Cardano *transaction* on CKB

Mithril certifies the **Cardano transaction set** (a `CardanoTransactions` certificate whose
protocol message commits a tx-set Merkle root). To prove "tx X happened on Cardano" on CKB:
1. verify the `CardanoTransactions` certificate (← the verifier we built);
2. extract the certified tx-set root from its protocol message (authenticated by compute_hash);
3. verify a **tx-membership proof** that tx X is under that root.

Real evidence gathered (`spike/cross-chain/real_tx_membership_proof.json`): a certified preview
tx (`64fbcc23…`, cert `eab050d0…`) with its proof. **The proof is an `MKMapProof`** — a two-level
structure: a top-level **MMR** (`master_proof`) over block-ranges, and per-range **`sub_proofs`**
(Merkle trees of txs). This verification lives in **`mithril-common`** (`crypto_helper`, the
`MKMap`/`MKProof`/MMR types) — **not** in `mithril-stm`, so it is a separate port (≈ the size of the
Merkle-batch work already done, but two-level).

Also observed (the latency point, `FEASIBILITY.md` (b)): tx certification lags the tip — the
certified `latest_block_number` was ~50 blocks behind tip; a tx must be below it to be provable.

## Remaining to a live cross-chain transfer (sized)

1. **Port `MKMapProof` verification in-script** (MMR `master_proof` + `sub_proofs`) and verify the
   real preview tx-membership proof in CKB-VM. *(New algorithm from mithril-common; ~1 build like
   the Merkle-batch port, two-level.)* → completes "Cardano tx proven on CKB".
2. **`next_avk` / tx-root binding**: extract the relevant root from the authenticated
   `next_aggregate_verification_key` / `cardano_transactions_merkle_root` protocol-message part
   (compute_hash already authenticates the part bytes; parse mithril's JSON-array encoding).
3. **Witness-driven verifier + relayer transcode**: parse the cert from the witness (the relayer
   transcodes the ~27 KB JSON → compact molecule) instead of embedded consts; molecule schema +
   type-id uniqueness for the cell.
4. **Bound cell + binding lock (Phase 3)**: the CKB bound-cell transition that consumes
   "tx X final" (from #1) + the Cardano-side binding lock (Plutus) that holds the anchored value
   with the commitment (DESIGN §3). This is the actual leap-in/leap-out.
5. **Lottery cost**: the naive per-index lottery is ~70% of a block. The ~5% optimization needs
   mithril's **SNARK-lottery target** (`compute_target_value_for_snark_lottery`) — a verifiable
   precomputed target — NOT a boundary check (verifying the boundary is *more* expensive: the
   Taylor series can't early-stop at the boundary, ~1e9 cycles/call — measured).
6. **Live**: host differential-test vs mithril-stm/common; devnet → Pudge across real epochs; a
   real Cardano→CKB leap-in driven by a real preview cert + tx proof.

## Honest assessment

The hardest *cryptographic* question — can a CKB script verify a real Cardano certificate — is
**answered yes, in-script, on real data**. Reaching a live cross-chain transfer is now an
**engineering** path (items 1–6), not a research risk: each piece is concrete and sized against
real artifacts. Items 1, 4 are the substantive builds; 2, 3, 5 are mechanical; 6 is integration.
