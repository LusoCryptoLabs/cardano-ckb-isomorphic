# Spec - bound cell + binding lock (the isomorphic-binding layer)

> This is the layer that makes the project *actually* isomorphic binding, built on the proven
> Cardano-verification oracle (cert verify + tx-membership, in CKB-VM). Everything here consumes
> `cardano_tx_is_certified(tx_hash) -> bool` (Mithril cert verify ⇒ certified tx-set root ⇒
> MKMapProof membership), demonstrated in-script on real preview data.
>
> Status (2026-06): BUILT AND LIVE - this spec is implemented. The CKB `BoundAsset` type
> script (genesis/transition/finalize), the Cardano binding lock + seal NFT (Aiken, 91 checks /
> 6 tests), the witness-driven verifier, and the relayer all exist and ran the full lifecycle on
> Pudge - genesis `0x0318d35f` → transition `0x94d0620f` → leap-out finalize `0x795f4bb9`, against
> the real Cardano seal lifecycle `83dd51d2`/`a98b6636`/`6c729ea6`. The §6 work breakdown below is
> done; see `LIVE_STATUS.md`, `spike/phase1/`, `cardano/binding/`, `deployed/pudge/`.

## 0. The idea in one paragraph

An asset's ownership is a single-use seal = a Cardano UTxO; its state lives in a CKB cell.
To move the asset you spend the seal on Cardano, embedding a commitment to the next CKB
state in that transaction. On CKB, the bound cell only transitions if a script can prove - via the
verification oracle - that the seal was spent in a Mithril-certified Cardano tx whose
commitment matches the new state. Cardano provides ownership/double-spend security and never has
to know about CKB; CKB provides programmable state and is the only side that verifies Cardano.
(This is RGB++'s construction with Cardano as the anchor instead of Bitcoin.)

## 1. Objects

```
# CKB: the bound cell (type script = BoundAsset)
BoundCell.data = BoundState {
    seal: OutPoint{ tx_id: Bytes32, index: u32 }, # the Cardano UTxO that owns this cell now
    asset: AssetState { ... } # owner-tag, amount, token data - app-defined
}
BoundCell.type = BoundAsset(params) # params: light_client_type_hash, genesis rule
BoundCell.lock = <anyone-can-relay> # authorization is via the seal, not the CKB lock

# Cardano: the binding lock (Plutus) holds the seal
SealUTxO at binding_lock:
    value: the seal NFT (policy = unique, 1 token) [+ optional anchored native value]
    datum: SealDatum { ckb_cell_id: Bytes32, owner: VKH } # owner = current Cardano-side owner

# The commitment that binds a Cardano spend to the next CKB state
commitment = blake2b256( serialise(next_BoundState) || seal_next.tx_id || seal_next.index )
```

The seal NFT makes the bijection explicit and survivable: exactly one seal token ↔ one bound
cell. Cardano consensus guarantees the seal is spent at most once (no double-move).

## 2. The transfer ("leap") - the heart of it

To transfer/transition the bound asset (state `S` → `S'`):

Step A (Cardano): the current owner spends `SealUTxO` (the seal `OP`) in tx `T`, which:
- recreates the seal NFT at `binding_lock` as a new `SealUTxO'` at outpoint `OP'` with the new owner;
- includes an inline datum / output carrying `commitment = blake2b256(S' || OP')`.
The binding lock validates `T` (see §4). After `T` is on-chain, wait for Mithril certification.

Step B (CKB): spend `BoundCell{seal=OP, asset=S}` → produce `BoundCell{seal=OP', asset=S'}`.
The `BoundAsset` type script requires, from the witness:
- the Cardano tx body of `T` (bytes), and `tx_hash = blake2b256(T_body)`;
- a Mithril `CardanoTransactions` cert + MKMapProof that `tx_hash` ∈ certified tx-set root
  (← the verifier we built); the cert's root must chain to the referenced light-client cell;
and checks all of:
1. `cardano_tx_is_certified(tx_hash)` - `T` is real + final on Cardano (trust-minimized, Mithril).
2. Seal consumed: `T`'s inputs contain `OP` (the cell's current `seal`). *(parse `T` body)*
3. Seal recreated: `T`'s outputs contain the seal NFT at `binding_lock`, defining `OP'`.
4. Commitment matches: the committed value in `T` equals `blake2b256(serialise(S') || OP')`,
   where `S'` is the output bound cell's state. *(binds the new CKB state to the Cardano spend)*
5. Single transition: the output cell's `seal == OP'` and exactly one bound cell continues.

Because the commitment is in `T`'s body, it is covered by `tx_hash`, which the MKMapProof certifies
- so a relayer cannot forge `S'`: only the `S'` that the real owner committed to on Cardano passes.

## 3. Leap-in / leap-out

- Leap-in (Cardano → CKB, bind): mint the seal NFT on Cardano under `binding_lock`, datum
  committing to the genesis state `S0` (commitment `= blake2b256(S0 || OP0)`). Once that mint tx is
  Mithril-certified, mint the bound cell on CKB: the `BoundAsset` genesis rule requires a
  certified seal-creation tx whose commitment matches `S0` (same check as §2, with no prior cell).
- Leap-out (CKB → Cardano, unbind): the owner spends the seal on Cardano to a plain UTxO
  (no seal recreated) - the binding lock permits this on owner signature, releasing any anchored
  value. The bound cell is then finalized/burned on CKB (its transition script accepts a spend
  that proves the seal was consumed without recreation). *Cardano never verifies CKB here* - the
  owner controls the seal; CKB just observes the unbind. This is the asymmetry paying off.

## 4. The binding lock (Plutus) - exact checks

On spend of `SealUTxO`, the binding lock requires:
- Owner auth: `T` is signed by `datum.owner` (the current Cardano-side owner).
- Seal continuity (transfer): exactly one output recreates the seal NFT at `binding_lock` with
  a fresh `SealDatum`, or (unbind) no output carries the seal NFT (burn) - a redeemer selects.
- Commitment present (transfer): an output/inline-datum carries a 32-byte `commitment` field.
- Value conservation: any anchored native value is preserved into `SealUTxO'` (transfer) or
  released (unbind). The lock does not check the CKB state - that binding is enforced on CKB.

The binding lock is intentionally thin: it guarantees *seal uniqueness + commitment emission +
ownership*. The semantic binding (commitment ↔ CKB state) is enforced by the CKB type script (§2.4),
because only CKB verifies the cross-chain relationship.

## 5. Security invariants (what an attacker must beat)

| Invariant | Enforced by |
|---|---|
| One seal ↔ one bound cell (no duplication) | seal NFT uniqueness (Cardano) + cell names its seal (CKB) |
| No double-move | Cardano consensus: the seal UTxO spent at most once |
| New CKB state is the one the owner authorized | commitment in `T` (covered by `tx_hash`) == `hash(S')`, MKMapProof-certified |
| Spend is real + final on Cardano | Mithril cert verify + tx-membership (the oracle), chained to the light-client checkpoint |
| Ownership | seal spend requires owner signature (Cardano) |
| Replay | seal outpoint consumed once; cell advances to the new outpoint; certified tx-set is monotone |

Trust = Cardano consensus (ownership/double-spend) + Mithril honest-stake-majority (the oracle).
No committee, no governor. Trustless endgame: swap Mithril for a ZK-of-Praos proof behind the same
`cardano_tx_is_certified` interface.

## 6. Buildable work breakdown

1. `cardano_tx_is_certified(tx_body) -> bool` entrypoint - wire the two proven halves into one:
   `tx_hash = blake2b256(tx_body)`; run the cert verify (→ authenticated tx-set root, chained to
   the light-client cell); run the MKMapProof membership of `tx_hash`. *(Mechanical: both halves
   exist; needs the witness-driven plumbing + the root-from-protocol-message binding.)*
2. Cardano tx-body parsing in-script *(the one genuinely new hard piece)* - minimal CBOR
   decode of a Conway tx body to extract inputs (to find `OP`) and the outputs / inline
   datums (to find the seal NFT recreation `OP'` + the `commitment`). Bounded, deterministic; no
   crypto. ~the size of the molecule/Merkle work already done.
3. `BoundAsset` CKB type script - the §2 transition + the §3 genesis/burn rules; the
   commitment recomputation `blake2b256(serialise(S') || OP')`.
4. `binding_lock` Plutus validator + the seal NFT minting policy - §4.
5. Molecule/CBOR schemas for `BoundState`, the witness (`tx_body + cert + MKMapProof`), and the
   commitment; type-id uniqueness for the light-client checkpoint cell.
6. Relayer - watches Cardano seal spends, fetches the Mithril cert + tx proof, transcodes, and
   submits the CKB bound-cell transition. (Liveness only; cannot forge.)
7. End-to-end test - devnet then preview↔Pudge: leap-in, a transfer, leap-out, driven by real
   Mithril certs + tx proofs.

## 7. Honest open questions / risks

- Cardano tx CBOR parsing in-script is the new surface - needs to track the Conway tx-body
  layout (input set + outputs + inline datums) precisely; the commitment placement must be inside
  the hashed body (inline datum or output, not auxiliary metadata that some eras hash separately).
- Latency: a bound-cell transition can only happen after the seal-spend tx is Mithril-certified
  (the lag we measured). Fine for settlement; a real UX parameter. The CKB cell trails Cardano by
  the certification delay.
- Genesis trust: the light-client checkpoint's genesis avk is a social checkpoint (as for all
  Mithril clients).
- AdvanceCert cost (~70% of a block, naive lottery) - needs the SNARK-lottery target before
  frequent checkpoint advances are cheap.
- Reorg/finality below the certified tip; Mithril liveness/availability of certs + tx proofs.

## 8. What this changes about the claim

§1–§5 are built and live, so the project *is* isomorphic binding: a Cardano-anchored asset
whose ownership is a Cardano seal and whose programmable state lives on CKB, with every transition
trust-minimally verified on CKB against real Cardano Mithril certification. The verification oracle
(cert + tx-membership) and the binding (seal NFT + binding lock + `BoundAsset` cell) both ran the
full bind→transition→leap-out lifecycle on preview↔Pudge. What remains is productionization
(`CHIRAL_READINESS.md`), not the binding itself.
