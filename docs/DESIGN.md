# Design - Cardano ⇄ CKB via isomorphic binding + a CKB-hosted Cardano light client

> Architecture doc. Sibling to `cardano-ckb-bridge` (the bonded-committee optimistic bridge).
> This document is the architecture; `ROADMAP.md`/`BUILD_PLAN.md` are the build order;
> `PRIMITIVES.md` is the reuse manifest.
>
> Status (2026-06): the architecture below is built and proven live on testnets, both
> directions. The Cardano→CKB (Mithril-in-CKB-VM) leg ran the full bind→transition→leap-out
> lifecycle on Pudge; the mirror CKB→Cardano (Groth16-of-CKB-consensus in Plutus) leg ran a full
> lock→verify→mint→burn→unlock round trip. See `CHIRAL_READINESS.md` (gap map),
> `LIVE_STATUS.md`/`CHIRAL_STATUS.md` (live status), `CKB_TO_CARDANO.md` (the mirror leg). The §5
> "open research questions" are annotated below with where each was resolved.

## 0. Why a second design at all

The sibling bridge is a lock-and-mint, bonded-authority bridge with an optimistic
challenge window. Its load-bearing safety property is *forced delay + 1-of-N honest veto +
bonded deterrence* - explicitly not trustless. Its own docs name the trust-minimizing
endgame as future work:

- `CHALLENGE_PROTOCOL.md`: adjudication (`Resolve`) is "the unresolved hard part"; a
  light client / ZK proof of the source event is "the only fully trustless option, and the
  expensive long-term north star."
- `THREAT_MODEL.md §9`: whether to add "a long-term light-client path as a second,
  trust-minimizing verification route" is left open.

This repo takes that path - but reframes it. Instead of bolting a light client onto a
symmetric lock-and-mint bridge, it adopts an asymmetric architecture (isomorphic
binding) that needs only one light client, in the tractable direction.

## 1. What isomorphic binding is (RGB++ lineage)

In RGB++ (Cipher / Nervos), a CKB cell is bound - structure-preservingly
("isomorphic") - to a UTxO on an *anchor* chain (Bitcoin). The split of duties:

- The anchor UTxO holds ownership: spending it is what authorizes a state transition
  of the bound cell. Double-spend safety is inherited from the anchor chain.
- CKB holds the rich state + transition logic: the cell carries the asset's data and
  the script that validates transitions.
- Each transition is committed into the anchor-chain transaction (a commitment hash in
  the anchor tx), and CKB scripts verify that commitment in-script against a light
  client of the anchor chain that CKB maintains.

The enabling primitive is precisely *CKB as a verification layer running a light client of
the anchor chain*. RGB++ relies on a Bitcoin SPV/light client maintained on CKB.

### Why Cardano is a *better* anchor than Bitcoin

- EUTxO + inline datums. The isomorphic commitment rides in a first-class datum
  field, not squeezed into a Bitcoin `OP_RETURN`. Richer, cleaner, and validatable by the
  Cardano-side script too if desired.
- Native assets. The anchored value can be real Cardano native tokens / ADA, with the
  anchor lock enforcing the binding rules.
- Plutus can co-validate. Unlike Bitcoin, Cardano can run a script on the anchor side
  to enforce the commitment format and the binding invariant, hardening the protocol
  without needing the heavy direction (Cardano verifying CKB - see §3).

## 2. The asymmetry insight (the whole point)

| | Lock-and-mint bridge (sibling) | Isomorphic binding (this repo) |
|---|---|---|
| Verify CKB on Cardano | Required - and brutal: CKB PoW = Eaglesong, not a Plutus builtin, so native verification blows the exec budget; needs a ZK-of-Eaglesong proof. | Not required. Cardano is only the anchor; it never has to verify CKB. |
| Verify Cardano on CKB | Required - Mithril/ZK. | Required - Mithril/ZK (the one light client we keep). |
| Asset model | Wrapped (wADA/wCKB), custody pool, peg + redemption risk. | Same asset, ownership anchored to Cardano UTxOs; transacts on CKB. No wrapped-token custody. |
| Trust in safety path | Bonded committee + governor adjudication. | Anchor-chain (Cardano) security for ownership + soundness of the CKB-side Cardano verifier. No bonded authority. |

The deletion of "verify CKB on Cardano" is the key win: it removes the single worst
feasibility risk in the bridge's own analysis (a production-grade ZK proof of Eaglesong PoW
small enough to verify inside a Plutus budget).

## 3. Architecture

### 3.1 Components

```
        CARDANO (anchor: ownership + commitments) CKB (state + verification)
   ┌───────────────────────────────────────────┐ ┌─────────────────────────────────────┐
   │ binding lock (Plutus) │ │ bound cell (asset state + logic) │
   │ - holds the anchored value │ │ - asset data, owner = f(anchor) │
   │ - datum carries the isomorphic commitment │ │ - transition script verifies the │
   │ - enforces commitment format / binding │ │ anchor spend via the LC below │
   └───────────────────────────────────────────┘ │ │
                                                     │ Cardano light-client cell │
   (Mithril signers certify snapshots) ───────────▶ │ - verifies Mithril cert (BLS) and │
                                                     │ advances a trusted Cardano root │
                                                     │ replay accumulator (SMT) │
                                                     └─────────────────────────────────────┘
```

### 3.2 The binding (one cell ↔ one Cardano UTxO)

- A bound cell on CKB names a specific Cardano output (the anchor) and a
  transition rule. Its "owner" is defined as *whoever can spend the anchor UTxO with a
  matching commitment*.
- A commitment = `hash(next CKB cell state ‖ transition metadata)` is embedded in the
  datum of the Cardano transaction that spends/recreates the anchor. (In RGB++ this is
  a commitment in the Bitcoin tx; here it is a Cardano datum field, optionally
  format-checked by the binding lock.)
- To transition the bound cell on CKB, the spender presents: (a) a proof that the anchor
  UTxO was spent on Cardano, (b) the committing datum, and (c) the new cell state - and the
  CKB transition script checks `commitment == hash(new state ‖ metadata)` and that the
  anchor spend is final per the light client.

### 3.3 The Cardano light-client cell on CKB (the load-bearing piece)

This is what makes the design trust-minimized. Two candidate verifiers, weakest→strongest:

1. Mithril certificate (recommended first target). Mithril is Cardano's stake-based
   BLS threshold multi-signature that certifies a snapshot of chain state - built exactly
   so a light client can trust "≥X% of stake signed this snapshot root" *without* replaying
   Ouroboros Praos. A CKB script verifies:
   - the BLS12-381 aggregate/threshold signature over the snapshot message, against the
     certified stake-key set (advanced epoch to epoch);
   - a Merkle inclusion proof that the anchor UTxO / its spend is in the certified
     snapshot.
   Trust = a large, economically-staked Mithril quorum. Trust-minimized, not fully
   trustless. In-script cost is realistic: CKB RISC-V already does ML-DSA-44 verify at
   ~4.39M cycles (`primitives/ckb/mldsa.rs`); BLS pairing + Merkle checks are in the same
   ballpark of "heavy but feasible."

2. ZK proof of Praos (north star). A SNARK proving the Cardano header sequence + VRF
   leader proofs + KES signatures are valid and the event is buried N-deep, verified
   in-script on CKB. Fully trustless, but research-grade: a Praos circuit is a large
   undertaking. Adopt later, behind the same cell interface as Mithril so it's a
   drop-in upgrade.

The light-client cell advances a trusted Cardano state root (epoch by epoch for
Mithril; block by block for ZK). The replay accumulator (`primitives/ckb/smt_replay.rs`)
prevents re-processing the same anchor spend (O(1), as in the sibling).

### 3.4 "Leap" - moving value between sides

- Cardano → CKB (bind / leap-in): lock value under the binding lock with a commitment
  to an initial CKB cell state. Once the lock tx is Mithril-certified, the bound cell
  becomes live on CKB; the asset now transacts on CKB with full ownership anchored to
  Cardano.
- CKB → Cardano (unbind / leap-out): the final CKB cell state authorizes spending the
  anchor on Cardano back to a plain UTxO, releasing the value. (This direction needs Cardano
  to act on a CKB outcome - but without verifying CKB: the binding lock releases on the
  anchor owner's own signature, and the CKB side is where the asset's transfer history was
  enforced. The anchor never needs a CKB light client; it only needs its own spend
  conditions. This is the asymmetry paying off.)
- CKB-internal transfers: pure CKB cell transitions, anchored but not touching Cardano
  per transfer (RGB++-style off-anchor moves with periodic settlement) - a throughput win
  to design carefully (see §5).

## 4. Trust model

- Ownership / double-spend: inherited from Cardano (the anchor). No bonded
  committee in this path.
- State-transition validity: enforced by CKB scripts.
- Cross-chain soundness: reduces to the soundness of the Cardano-light-client cell
  on CKB - i.e. (Mithril) the honest-stake-majority assumption of the Mithril quorum, or
  (ZK) the soundness of the proof system. This is the single assumption to scrutinize, and
  it is a *cryptographic/economic* assumption, not "trust these N named operators."
- Liveness: a relayer posts Mithril certs / proofs and CKB transitions. A stalled
  relayer delays, it cannot steal (anyone can relay; the proofs are public).

Compared to the sibling: this replaces "a bonded committee asserts + a governor adjudicates"
with "Cardano secures ownership + a stake-threshold (or ZK) certificate is checked
in-script." Strictly fewer trusted humans in the safety path.

## 5. Open research questions / risks - and how each was resolved

These were the open questions when this was a design. Status as of 2026-06:

1. Mithril sufficiency. RESOLVED (interface). Stake-threshold trust is the live
   assumption; the trustless ZK-of-Praos path fits behind the same `cardano_tx_is_certified`
   interface, and an SP1 STARK-Mithril proof of the same statement is already proven+composed
   (`spike/cardano-to-ckb-zk/`) as the succinct/PQ drop-in.
2. Mithril certificate format + cadence. RESOLVED. Real preview certs
   (`k=1944, m=16948, phi_f=0.2`); `compute_hash` reproduced bit-for-bit; epoch rotation handled
   by `AdvanceCert` (live, epoch 320→321). Certification latency is real (minutes/leg) and treated
   as settlement-style UX (`HARDENING.md §3`).
3. In-script BLS budget on CKB. RESOLVED (measured). A full Mithril verify is ~134–146M
   cycles (~4–5% of a 3.5e9 block); the stake-lottery cost driver was cut 2,368M→39.7M via the
   SNARK-lottery integer target (`spike/phase2/`). Runs live in `AdvanceCert`/`TxSetCert`.
4. Anchor spend proof. RESOLVED. Two-level Mithril `MKMapProof` (MMR master +
   per-range sub-proofs) verified in CKB-VM (`spike/cross-chain/`, 139K cycles); the binding lock's
   datum commitment is covered by the certified tx hash. Wired into the live `BoundAsset`.
5. Leap-out authorization. RESOLVED. The CKB `BoundAsset` FINALIZE mode destroys the
   bound cell when the certified Cardano Unbind consumed the seal and did not recreate it at the
   binding lock - Cardano never verifies CKB. Proven in CKB-VM and closed live (`0x795f4bb9`).
6. Off-anchor transfers + settlement (throughput): still open / future. Per-transfer
   settlement is what's built; RGB++-style off-anchor batching is not yet designed.
7. Reorgs on both chains. ANALYZED (`HARDENING.md §2`): the bridge only acts on
   Mithril-certified *immutable* Cardano history, so tip reorgs are invisible by construction; CKB
   transitions are idempotent under the same seal + commitment.

## 6. Relationship to the sibling repo

- Reused as-is (primitives): the in-script verification pattern (`mldsa.rs` → template
  for the BLS/Mithril verifier), the O(1) SMT replay accumulator (`smt_replay.rs`), the
  Cardano MPF replay-root machinery (`replay_smt_tests.ak`, `mpf-proof.mjs`), and the CKB
  script + Aiken toolchains and test harnesses (lift at implementation time - see
  `PRIMITIVES.md`).
- Dropped: lock-and-mint value flow (`bridge_lock` mint/release, `wckb_mint`,
  `cardano_lock`), the bonded committee (election/registry/auth), the optimistic
  challenge machinery, and the relayer/sidecar operators. None of it is in the
  isomorphic-binding trust path.
- Comparison axis (decide later "which bridge is better"): trust assumptions (bonded
  humans vs. stake-threshold/ZK), asset semantics (wrapped vs. anchored), latency
  (challenge window vs. Mithril cert cadence), throughput, and implementation/audit cost.
