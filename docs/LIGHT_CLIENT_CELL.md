# Light-client cell — a self-advancing Cardano checkpoint on CKB

> The architecture that turns the **proven in-script Mithril verifier** (BLS aggregate + stake
> lottery + Merkle membership, all verified in CKB-VM on a real preview cert) into a living
> **Cardano light client** that any CKB script can trust.
>
> **Status (2026-06): BUILT AND LIVE ON PUDGE.** `AdvanceCert` (`spike/light-client-cell/advance-cert/`)
> advances the stake checkpoint epoch 320→321 by verifying a real Mithril cert in-VM (164.4M cycles,
> tx `0xb7ada085`); `TxSetCert` (`txset-cert/`) authenticates the certified tx-set root the same way
> (`0xe4e1b0c6`). The bound asset reads the authenticated root from this checkpoint cell as a cellDep.

## What it is

A single CKB **cell** (uniqueness enforced by a type-id, like the bridge's state cell) whose data
is the current **trusted Cardano checkpoint**:

```
LightClientState {
    epoch:        u64,        // Cardano epoch this checkpoint is for
    avk_root:     [u8; 32],   // Mithril aggregate verification key: the stake-key Merkle root
    total_stake:  u64,        // total stake registered for this epoch
}
```

`avk = (avk_root, total_stake)` is exactly what the in-script verifier checks signatures against.
The cell is the on-chain root of trust for "what Cardano's stake distribution is."

## How it advances (the Mithril certificate chain)

Mithril certificates form a chain: each certificate is **signed by epoch N's stake** and its
`protocol_message` carries `next_aggregate_verification_key` = **epoch N+1's avk**. So a checkpoint
can roll forward trustlessly:

**`AdvanceCert` transition** — spend the cell + supply a newer Mithril certificate; the type script:
1. **Verifies the certificate against the cell's CURRENT `avk`** using the proven verifier:
   - aggregate BLS over `msgp = signed_message ‖ avk_root` (empty DST, sum aggregate);
   - **eligibility**: every winning index won the stake lottery (`ev < target`, target verified per
     party against the cell's `total_stake`);
   - **Merkle membership**: the winning signers' `(mvk,stake)` leaves are in the cell's `avk_root`;
   - **quorum**: Σ unique winning indices ≥ `k`.
   ⇒ proves **≥ stake-threshold of epoch N's stake signed** this certificate.
2. **Recomputes `signed_message`** = `ProtocolMessage::compute_hash` (SHA-256 over the ordered
   parts) from the parts in the witness, and checks it matches what was signed — binding the
   certificate to its `protocol_message`.
3. **Extracts `next_aggregate_verification_key`** from the protocol message → the new `avk` (root +
   total_stake) for epoch N+1.
4. **Writes the continuing cell** with `epoch+1`, the new `avk_root`, `total_stake`; nothing else
   may change.

Genesis: the cell is created once from a hard-coded **trusted genesis certificate / avk** (a social
checkpoint — same trust root Mithril clients use). From there it advances permissionlessly: anyone
can submit the next epoch's certificate; a stalled relayer delays, it cannot forge.

## How the rest of the bridge uses it

Once the checkpoint is current, the **binding lock / bound-cell** (Phase 3) proves a Cardano event
is final by:
- referencing the light-client cell (a CKB cell dep) for the trusted `avk_root` / certified snapshot;
- supplying a **Cardano transaction-membership proof** (Mithril certifies the tx set with a Merkle
  proof) that the anchor-spend tx is in the certified snapshot;
- the bound-cell transition checks that proof against the certified root, then applies the
  isomorphic state transition (DESIGN §3).

So the light-client cell is the shared, trust-minimized oracle; the binding logic consumes it.

## Trust model

- The cell advances only via certificates that **≥ stake-threshold of the previous epoch's stake**
  signed — verified in-script, no committee, no governor.
- Root of trust = the genesis checkpoint (a one-time social fact) + Mithril's honest-stake-majority
  assumption. This is **trust-minimized**, the same assumption Mithril light clients rely on; the
  trustless endgame swaps the Mithril verify for a ZK-of-Praos proof behind the same cell interface.

## Cost (from the proven verifier)

Each `AdvanceCert` runs one full verify ≈ **~175M cycles ≈ ~5% of a CKB block** (≈ once per Cardano
epoch, or per certified checkpoint cadence — cheap relative to block budget). Cardano-tx-membership
proofs consumed by the binding are just Merkle hashing (~negligible).

## Status / next steps

- [x] In-script verifier components proven on a real cert (BLS, lottery, Merkle) — `spike/mithril-verify/`.
- [x] Assembled into one `verify_certificate(state.avk, cert) -> next_avk` entrypoint —
      `spike/light-client-cell/light_client_advance.rs`.
- [x] `AdvanceCert` type script built (`advance-cert/`) + `TxSetCert` (`txset-cert/`); SNARK-lottery
      target folded in (Phase 2: eligibility ~70% → ~1% of a block).
- [x] **LIVE on Pudge:** genesis checkpoint (epoch 320) `0x122b71f0`; authenticated advance 320→321
      `0xb7ada085` (164.4M cycles); authenticated tx-set checkpoint `0xe4e1b0c6`.
- [x] Binding lock + bound cell consume this checkpoint cell (Phase 1 live; `BoundAsset` reads
      `"LCKP"||root` from the cellDep).
- [x] **Witness-supplied cert (not embedded consts):** the verifier now reads the Mithril cert from
      a relayer-transcoded **witness cellDep** and verifies *any* live cert (ckb-debugger 147.5M);
      LIVE authenticated checkpoint from a witness-supplied cert `0xf1d61caf` (165.9M cycles). See
      `spike/light-client-cell/cert-verify/`, `mithril_verify/src/bin/transcode_witness.rs`.
- [ ] Remaining (external): mainnet genesis-checkpoint social root; a hosted relayer that drives
      `AdvanceCert` continuously across epochs. See `CHIRAL_READINESS.md`.
