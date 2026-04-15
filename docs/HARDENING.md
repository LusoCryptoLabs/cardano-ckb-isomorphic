# Hardening + correctness (Phase 4)

> Turning the proven mechanism into something that can't *silently* break. Covers the
> differential-test gate, reorg/finality, Mithril liveness/latency, the replay/monotonicity
> invariants, and verifier size. Companion: `spike/phase4/`, `.github/workflows/verifier-difftest.yml`.

## 1. Differential / tamper gate (built) — `spike/phase4/difftest`
A host copy of the **exact** in-script verifier logic (compute_hash, aggregate BLS, the Phase-2
lottery target, the avk Merkle reconstruction), run against a **real preview-cert fixture**, asserting:
- **Accept the genuine cert:** BLS aggregate verifies; every declared index wins the lottery and the
  unique count ≥ k; the avk batch-commitment root reconstructs; and our `compute_hash` **equals
  mithril's own `signed_message`** (a direct cross-check against mithril-common's output).
- **Reject every single-component tamper (soundness):** flipping a byte of any sigma, mvk, the
  message, the avk root inside `msgp`, an authenticated message part, a Merkle signer leaf, or
  drastically lowering a party's stake — each is rejected. 11/11 tests pass.

**Live drift watch** (`spike/phase4/live_drift_check.py`, CI job `live-drift`): fetch the *current*
preview cert and re-confirm our `compute_hash` construction still equals its `signed_message`.
This already earned its keep: between the epoch-320 fixture and now, mithril **changed the
message-part set** (added `latest_block_number`, `cardano_blocks_transactions_*`) — and our generic
construction (SHA-256 over the BTreeMap-ordered `key‖value`, hex) **still matches**. The gate catches
a change to the *algorithm*; the fixture pins a known-good *instance*; together they stop silent drift.

## 2. Reorg / finality
- **Cardano (below the certified tip):** the bridge only ever acts on **Mithril-certified** txs. A
  Mithril certificate attests a tx-set Merkle root over **immutable** Cardano files (settled history),
  so a bound-cell transition can only reference a tx already past Cardano's stake-settlement / immutable
  boundary. Reorgs at the volatile tip are invisible to the bridge by construction — it trails the tip
  by the certification gap (§3), which is strictly deeper than practical Cardano rollback depth.
- **CKB:** treat a bound-cell transition as final after the usual CKB confirmation depth before a
  relayer/UX considers the leap complete. The seal (Cardano) is the source of truth; a CKB reorg just
  re-applies the same certified transition (idempotent — same seal, same commitment).

## 3. Certification latency (inherent — design for settlement UX)
We measured it live: a bound-cell transition can only happen **after** the seal-spend tx is
Mithril-certified — minutes per leg on preview. This is a settlement-style latency, not instant
finality; surface it as a pending state. Tracking mithril#1701 (low-latency tx certification) directly
improves it. The bound cell trails Cardano by exactly this gap; never a safety issue, only liveness.

## 4. Mithril liveness / availability
- The relayer is **permissionless** and **cannot forge** (the CKB script re-verifies). If the relayer
  stalls, transfers are delayed, not unsafe; anyone can run one.
- If the **aggregator** is unavailable, proofs can be reconstructed from any Mithril signer/aggregator
  (the cert + MKMapProof are publicly reproducible from the certified root). The light-client
  checkpoint cell only advances on a valid AdvanceCert, so an unavailable aggregator stalls advances
  (liveness), never admits a bad root (safety).

## 5. Replay / monotonicity invariants (enforced)
| Invariant | Enforced by |
|---|---|
| A seal moves at most once | Cardano consensus (the seal UTxO is spent once) + the cell names its seal |
| New CKB state is the owner-authorized one | commitment in the certified tx == `blake2b256(new state)` |
| Spend is real + final on Cardano | Mithril cert verify + MKMapProof, root from the checkpoint cell |
| Checkpoint advances monotonically | AdvanceCert requires `out_epoch == in_epoch+1` and the cert chains to the in-avk |
| Leap-out is genuine (not a disguised transfer) | FINALIZE requires the seal **not** recreated at the binding_lock |

## 6. Verifier size (deploy capacity)
Measured, size profile (`opt-level="z"`, LTO, `panic=abort`, strip):
- **BoundAsset** (per-transfer verifier: MKMapProof + Conway parse + commitment + finalize): **~48 KB**.
  No BLS — the heavy curve code is only in AdvanceCert. Deployed **once**, shared, reclaimable.
- **AdvanceCert** (the epoch verifier: aggregate BLS over `bls12_381` + lottery + Merkle): the larger
  one; `bls12_381` + `num-bigint` dominate. Phase 2 already dropped `num-rational` (the lottery now
  uses a fixed-point integer target), removing that dependency from the hot path.
- **Shrink levers (open):** replace `num-bigint` in the lottery with a fixed-width `u512` (drop the
  bignum crate); prune `bls12_381` to only the features used; share one hashing impl. Each reduces the
  one-time, reclaimable deploy capacity — not a per-user cost.

## 7. What remains for Phase 5
Security audit of the novel crypto-in-script (BLS/STM/MMR reimpl, the lottery target derivation, the
Conway parser), the mainnet genesis-checkpoint social root, and ops/monitoring.
