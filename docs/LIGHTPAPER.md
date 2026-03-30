# Chiral

### Symmetric isomorphic binding — a committee-free, anchor-agnostic protocol where each chain verifies the other with a succinct on-chain light client

*Light paper · 2026-06*

> **On the name.** *Chirality* is the property of a structure whose mirror image cannot be
> superimposed on it — two forms, oppositely handed, irreducibly distinct yet built from the same
> parts. Chiral's two legs are exactly that: one binding construction, mirrored into two
> oppositely-oriented oracles (Mithril-in-CKB-VM and Groth16-in-Plutus), neither reducible to the
> other.

> In the lineage of *RGB++* (Cipher / Nervos). RGB++ bound a CKB cell to a **Bitcoin**
> UTxO and let CKB follow Bitcoin via an SPV light client. This paper generalizes that
> construction: the anchor is no longer forced to be a chain that can only be *watched* — it
> can be a chain that **also verifies back** — and verification in **both** directions is
> done by a *succinct, in-script* light client rather than a committee, a multisig, or a
> custodian. Instantiated between **Cardano** and **CKB**, the result is a fully
> bidirectional isomorphic-binding protocol with no bonded authority anywhere in the safety
> path. Both directions have run their full lifecycle on testnet.

---

## Abstract

We describe a cross-chain construction in which an asset's **ownership** is a *single-use
seal* on one chain and its **programmable state** is a *cell/UTxO* on another, exactly as in
RGB++. RGB++ realizes this with Bitcoin as the anchor: Bitcoin holds ownership, CKB holds
state, and CKB verifies Bitcoin through an on-chain SPV light client. Because Bitcoin cannot
run a verifier of CKB, RGB++ binding is intrinsically **asymmetric in capability**: CKB can
verify Bitcoin, never the reverse.

We observe that the binding itself is symmetric — *only the oracle each side runs is
direction-specific* — and that two recent capabilities make the symmetric instantiation
practical: **Mithril**, Cardano's stake-based BLS threshold certificate of settled history,
which a CKB-VM script can verify for a few percent of a block; and **BLS12-381 builtins on
Cardano**, which let a Plutus script verify a constant-size **Groth16** proof, and therefore
verify a SNARK that attests CKB's Eaglesong PoW consensus, well within a transaction's
budget.

Plugging one oracle into each direction yields **Chiral**: a symmetric isomorphic-binding
protocol in which Cardano verifies CKB and CKB verifies Cardano, each by a single succinct proof
checked *on-chain*, with the binding construction unchanged on both sides and **no committee in
either**. Both legs have been built and run end-to-end on Cardano preview ↔ CKB Pudge.

---

## 1. Background: RGB and RGB++

RGB moves asset state off-chain and uses Bitcoin only as a commitment and double-spend layer:
ownership is tied to the right to spend a particular Bitcoin UTxO (a *single-use seal*), and
each transfer commits the new state into the spending transaction. This is powerful but
client-heavy: there is no shared, programmable, globally-validated state.

**RGB++** (Cipher) gives that off-chain state a *home*: a **CKB cell**. CKB is a UTXO-model
chain whose cells carry arbitrary data and whose RISC-V scripts ("CKB-VM") perform arbitrary
verification. RGB++ binds a CKB cell *isomorphically* to a Bitcoin UTxO:

- the **Bitcoin UTxO holds ownership** — spending it authorizes a state transition;
- the **CKB cell holds the rich state and the transition script**;
- each transition is **committed into the Bitcoin transaction**, and a **Bitcoin SPV light
  client maintained on CKB** lets CKB scripts verify, in-script, that the commitment was
  really made on Bitcoin.

The enabling primitive is precisely *CKB as a verification layer that runs a light client of
the anchor chain*. RGB++ also introduced **Leap**: because the binding is structure
preserving, value can move ("leap") between the Bitcoin-anchored and purely-CKB
representations without wrapping or custody.

### 1.1 The limit we remove

RGB++ binding is **one-directional in capability**, and this is forced by Bitcoin, not chosen:

> CKB can verify Bitcoin (SPV is cheap on CKB-VM), but **Bitcoin cannot verify CKB** — it has
> no facility to check Eaglesong PoW, an MMR proof, or a SNARK in-script.

So the anchor is permanently the *watched* chain and CKB is permanently the *watcher*. Leap
between Bitcoin and CKB is still bidirectional — moving the anchor back to Bitcoin is just an
ordinary Bitcoin spend that CKB observes, and **never requires Bitcoin to verify CKB** — but
the *trust topology* is fixed: one chain dictates, one chain follows.

We ask: what if the anchor is a chain that can *also* verify back? Then the *same* binding
runs in both directions, each side cryptographically checking the other, and neither side is
privileged.

### 1.2 Relationship to RGB and RGB++ — and why a new name

RGB and RGB++ are, at their core, **Bitcoin** constructions — Bitcoin is the anchor in each.
Chiral keeps the *binding idea* but uses **no Bitcoin at all**:

| | **RGB** | **RGB++** (Cipher / Nervos) | **Chiral** |
|---|---|---|---|
| Anchor chain | Bitcoin | Bitcoin | **Cardano** (no Bitcoin) |
| Where state lives | **off-chain** (client-side validation) | **on-chain**: a CKB cell | on-chain: a CKB cell / a Cardano UTxO |
| Who verifies whom | clients validate; Bitcoin = commitment layer | CKB verifies Bitcoin (SPV) | **both**: CKB verifies Cardano *and* Cardano verifies CKB |
| Direction of capability | n/a | **one-way** (Bitcoin can't verify CKB) | **two-way / symmetric** |
| Committee / custodian | none | none | none |

So the honest framing, in one paragraph:

> The **isomorphic-binding primitive is Cipher's** (RGB++), and that lineage is Bitcoin-rooted
> (RGB itself is a Bitcoin client-side-validation protocol). Chiral does **not** invent the
> binding. What Chiral contributes is **(i)** removing Bitcoin and substituting a *programmable*
> partner (Cardano) so the anchor can verify *back*, **(ii)** the resulting **symmetric,
> bidirectional** trust topology, and **(iii)** the in-script verification machinery the reverse
> leg requires — a **Groth16 SNARK of CKB's Eaglesong PoW consensus** checked inside Plutus, which
> Bitcoin structurally cannot host. The binding is unchanged; the anchor and the directionality are
> new.

Why this warrants a distinct name rather than "RGB++":

- RGB and RGB++ are **defined by Bitcoin's anchoring role**; Chiral has no Bitcoin and is
  bidirectional, so calling it "RGB++" would be inaccurate (and would misappropriate Cipher's
  term). Calling it RGB would be doubly wrong — RGB keeps state *off-chain*, which RGB++ already
  left behind and Chiral does not use.
- Conversely, in CKB circles "RGB++" is sometimes used **loosely** for "isomorphic binding on
  CKB" in general; under that loose usage one could say Chiral is *RGB++-style*. We prefer to be
  precise: **Chiral is in the RGB++ lineage, credited to Cipher, and is its symmetric
  generalization off Bitcoin** — not RGB++ itself, and not a new cryptographic primitive.

**Honest scope of the "trustless / no-committee" claim.** Both legs are committee-free *by
construction* and have run their full lifecycle on testnet. But the CKB→Cardano leg's soundness
rests on a Groth16 **trusted setup**, which today is a development ceremony (rogue-resistant, but
not a real multi-party run), and the whole system has not had a third-party audit. So "each chain
verifies the other, no committee" is true at the **cryptographic / design** level; it is **not
yet** a deployed, value-bearing guarantee. See `CHIRAL_READINESS.md` and `SECURITY_AUDIT.md`.

---

## 2. The core idea: the binding is symmetric, only the oracle differs

Strip isomorphic binding to its essence:

> **Ownership** = a *single-use seal* on the **anchor** chain.
> **State** = a *cell/UTxO* on the **follower** chain.
> The follower transitions its state **iff** it can prove, via an **oracle**, that the seal
> moved in the authorized way and committed to the new state.

Nothing there names a particular chain, nor even a particular *direction*. The only
direction-specific component is the **oracle** — the in-script procedure by which the follower
convinces itself the anchor's seal really moved. RGB++ instantiates it as *Bitcoin SPV in
CKB-VM*. Swap the oracle and you re-point the binding at any pair of chains, in either
direction.

| | anchor (ownership = seal) | follower (state = cell) | oracle the follower runs in-script |
|---|---|---|---|
| **RGB++** | Bitcoin UTxO | CKB cell | Bitcoin SPV light client |
| **Cardano-anchored leg** | Cardano UTxO under a Plutus *binding lock* | CKB *bound cell* | **Mithril** stake-BLS cert + tx-membership proof, in CKB-VM |
| **CKB-anchored leg** | CKB *seal cell* (single-use by construction) | Cardano UTxO under a Plutus *binding lock* | **Groth16 proof of CKB consensus** (Eaglesong + header-MMR + inclusion), in Plutus |

These are *the same construction with two oracles*. We did not build two protocols; we built one
binding and gave each direction its oracle. Run both at once and the protocol is symmetric:
**each chain verifies the other, on-chain, with one succinct proof**, and there is **no
committee, custodian, or governor** on either side. That is the whole contribution.

---

## 3. The binding, precisely

We use *seal* for the single-use ownership token and *bound cell* for the follower state. The
construction is symmetric, so we state it once.

### 3.1 Objects

```
SEAL  (anchor chain): a single-use UTxO/cell whose spend authorizes one transition.
                      - On Cardano: a unique NFT at a Plutus "binding lock", datum = owner.
                      - On CKB: a cell (CKB cells are consumed exactly once by construction).

BOUND (follower chain): the asset's programmable state.
                      - data  = { seal: <anchor seal outpoint>, asset: <app state> }
                      - script = the transition rule (a CKB type script, or a Plutus lock)
                      - "owner" ≡ whoever can spend the current SEAL with a matching commitment.

COMMITMENT: H( serialise(next BOUND state) ‖ next seal outpoint )      [H = Blake2b-256]
            embedded inside the body of the anchor transaction that spends the seal,
            so it is covered by that transaction's hash.
```

The seal makes the bijection explicit and survivable: **exactly one seal ↔ one bound cell**.
Anchor-chain consensus guarantees the seal is spent at most once — that supplies double-spend
safety, inherited rather than re-implemented.

### 3.2 A transition (the "leap")

To move the asset from state `S` to `S'`:

**Step A — on the anchor.** The current owner spends the seal in transaction `T`, which (i)
recreates the seal for the next owner (transfer) *or* destroys it (leap-out), and (ii) embeds
`commitment = H(S' ‖ OP')`, where `OP'` is the next seal's outpoint. A thin *binding lock* on
the anchor enforces only seal-uniqueness, commitment-emission, and owner authorization — **it
never inspects the follower's state.**

**Step B — on the follower.** The relayer presents the body of `T`, an **oracle proof** that
`T` is real and final on the anchor, and the new state `S'`. The transition script accepts
**iff** all of:

1. **`T` is certified** by the oracle (real + final on the anchor);
2. **seal consumed** — `T`'s inputs contain the current seal `OP`;
3. **seal recreated / destroyed** as the redeemer claims, defining `OP'` (or none);
4. **commitment matches** — the value committed inside `T` equals `H(S' ‖ OP')`;
5. **single transition** — exactly one bound cell continues, naming `OP'`.

Because the commitment lives inside `T`'s hashed body, and the oracle certifies that hash, a
relayer **cannot forge `S'`**: only the `S'` the real owner committed to on the anchor can
satisfy check (4). The relayer is pure liveness — it can stall, never steal.

### 3.3 Leap-in / leap-out

- **Leap-in (anchor → follower):** create the seal committing to a genesis state `S0`; once
  the creation tx is oracle-certified, mint the bound cell (genesis rule = checks (1),(4) with
  no prior cell).
- **Leap-out (follower → anchor):** the owner spends the seal back to a plain output *without*
  recreating it; the bound cell is then finalized/burned, its script accepting a proof of the
  seal's consumption-without-recreation. **The anchor never verifies the follower here** — the
  owner simply controls the seal; the follower merely observes the unbind. This is what lets
  even a "dumb" anchor participate in leap-out.

---

## 4. Oracle A — verifying Cardano on CKB (Mithril, in CKB-VM)

When **Cardano is the anchor**, CKB must convince itself, in-script, that a Cardano
transaction spending the seal is real and settled. Cardano offers a gift for exactly this:
**Mithril** — a stake-based **BLS12-381 threshold multi-signature** that certifies snapshots
of settled chain state, designed so a light client can trust "≥ a stake threshold signed this
snapshot" *without* replaying Ouroboros Praos.

The CKB-VM oracle `cardano_tx_is_certified(tx_body) → bool` does two things:

1. **Verify the Mithril certificate** — the threshold BLS signature over the certified
   message, against the stake-key set, which is *advanced epoch to epoch* by a light-client
   checkpoint cell (each cert carries the next epoch's verification key).
2. **Prove tx-membership** — a two-level Mithril proof showing `tx_hash = H(tx_body)` is in
   the certified transaction-set root.

Together they certify *this specific transaction*, and therefore the commitment inside it. A
replay accumulator (an O(1) sparse-Merkle-tree of consumed seal outpoints) prevents
re-processing the same spend.

A full Mithril verify costs a **few percent of a CKB block**, comfortably within budget; the
**bind → transition → leap-out** lifecycle, plus continuous epoch rotation of the light-client
checkpoint, has run live on CKB Pudge against real Cardano preview certificates.

**Trust:** Cardano consensus (ownership/double-spend) + Mithril honest-stake-majority (the
oracle). No committee. A *fully trustless* upgrade — a ZK proof of Ouroboros Praos behind the
same `cardano_tx_is_certified` interface — is prototyped as a hash-based STARK proof of the
Mithril statement (see §8), a drop-in for the BLS check.

---

## 5. Oracle B — verifying CKB on Cardano (Groth16 of consensus, in Plutus)

This is the direction RGB++ cannot have, because its anchor is Bitcoin. Here the anchor is
**CKB**: a CKB seal cell holds ownership, and **Cardano follows** — a bound UTxO at a Plutus
binding lock transitions only when convinced the CKB seal was spent in a confirmed CKB block
with the matching commitment.

CKB has no Mithril. Its light-client story is consensus-native: **Eaglesong PoW** + a **header
MMR** (every header commits to an MMR of all prior headers) + heaviest-chain cumulative work.
Verifying *that* natively in Plutus is infeasible — the per-script budget is two-to-three
orders of magnitude smaller than CKB-VM's, and Eaglesong is not a builtin. So we verify it
**succinctly**: an off-chain prover produces a constant-size **Groth16** proof that CKB
consensus holds, and Plutus verifies that single proof using Cardano's **BLS12-381 builtins**
(Miller loops + final exponentiation + a small public-input MSM).

The off-chain circuit proves four relations on a real CKB block:

- **PoW** — `ckbhash(eaglesong(pow_hash ‖ nonce)) ≤ target`, target decoded in-circuit, header
  hash recomputed from scratch;
- **chain root** — the header is a member of the checkpoint's header-MMR;
- **inclusion** — the seal-spend tx is bound to the header's transactions root via a CBMT path;
- **commitment** — the spend committed `H(next Cardano state)`.

A separate **checkpoint-advance** proof moves a Cardano-side `{chain_root, total_difficulty}`
UTxO forward trustlessly: it proves a new header has valid PoW *and* a verified difficulty,
computes the new MMR root **in-circuit**, and the validator enforces heaviest-chain
(`new_total > old_total`).

On-chain, the Groth16 verify costs roughly **a quarter of a Cardano transaction's budget**,
leaving ample headroom for the binding logic; a tampered public input is rejected. The full
**lock → verify → mint → burn → unlock** round trip has run live on testnet, with every
gadget (Eaglesong, Blake2b/ckbhash, MMR/CBMT membership, target-compare, 256-bit add)
differential-tested against native CKB on real data.

**Trust:** CKB PoW honest-majority + Groth16 soundness. Groth16 needs a per-circuit **trusted
setup** (see §7); a transparent PLONK with a universal SRS retires it.

---

## 6. The symmetric protocol

Run both oracles and the protocol is genuinely symmetric:

```
        CARDANO  ⇄  CKB

  Cardano-anchored leg:  ownership on Cardano (seal)   ·  state on CKB (bound cell)
                         CKB verifies Cardano  ──  Mithril cert + tx-proof, in CKB-VM

  CKB-anchored leg:      ownership on CKB (seal cell)   ·  state on Cardano (bound UTxO)
                         Cardano verifies CKB  ──  Groth16 of Eaglesong consensus, in Plutus
```

Neither chain is privileged. Neither wraps the other's asset into a custodial IOU — value is
*anchored*, not *wrapped*, so there is no peg, no redemption queue, no custody pool. Neither
trusts a named set of operators: the only trusted things are the two chains' own consensus and
the soundness of two cryptographic objects (a stake-threshold signature and a SNARK), both
checked *on-chain*. A relayer in either direction is pure liveness.

This is what RGB++ could not be, for a precise reason: RGB++'s anchor (Bitcoin) can be
*watched* but cannot *watch back*. Give the follower a succinct in-script verifier of the
other chain — Mithril (Cardano→CKB) and Groth16-of-Eaglesong (CKB→Cardano) — and the binding
becomes two-way.

---

## 7. Security

| Invariant | Enforced by |
|---|---|
| One seal ↔ one bound cell | seal uniqueness on the anchor + the bound cell naming its seal |
| No double-move | anchor consensus: the seal is spent at most once |
| New follower state is the one the owner authorized | commitment inside the anchor tx (covered by its hash) `== H(S')`, oracle-certified |
| Spend is real + final | the oracle: Mithril cert+membership (→CKB), or Groth16 of PoW+MMR+inclusion (→Cardano) |
| Ownership | seal spend requires owner authorization on the anchor |
| Replay | seal consumed once; cell advances to the new outpoint; certified state is monotone (epoch root / heaviest chain) |

**The trust surface is one oracle per direction.** Cross-chain soundness reduces to the
soundness of that oracle — a *cryptographic/economic* assumption (honest stake majority, or
SNARK soundness), not "trust these N operators." Beyond that reduction, four points an
implementer must weigh honestly:

- **Relayers cannot forge, only stall.** The authorizing commitment is inside the anchor
  transaction the oracle certifies; anyone may relay, and a wrong `S'` fails check (4). Liveness
  degrades under a censored relay; safety does not.
- **Genesis is a social checkpoint.** Each light client starts from an initial trusted anchor
  (the first Mithril verification key on CKB; the first CKB chain-root on Cardano), as every
  light client must. This is a one-time, publicly-auditable parameter, not an ongoing trusted
  party.
- **The Groth16 leg carries a trusted-setup assumption.** A compromised setup ceremony could
  forge proofs for the CKB→Cardano oracle. It is a one-time risk, mitigated by a
  multi-party ceremony and removable entirely by a transparent (PLONK/universal-SRS) verifier.
  The Mithril leg has no setup.
- **Finality, not the tip.** Both oracles act only on *settled* history — Mithril-certified
  snapshots / sufficiently-deep CKB headers — so tip reorgs are invisible by construction, at
  the cost of a settlement-style latency: the follower trails the anchor by the certification
  or confirmation delay, by design.

A relayer can be run by anyone, including the asset holder, so liveness need not be trusted to
a third party at all.

---

## 8. Post-quantum posture

We state this honestly, because a protocol can be no more post-quantum than the chains it
connects, and overclaiming helps no one.

- **The binding core is already quantum-resistant.** Seals, commitments, the header MMR, the
  CBMT inclusion proofs, and the replay accumulator are all **hash-based** (Blake2b / SHA-2
  family), which Grover only weakens quadratically — addressed by hash width, not by a new
  scheme.
- **Both oracles, today, rest on pre-quantum assumptions** — Mithril's BLS12-381 threshold
  signature and the Groth16 BLS12-381 pairing — exactly as the endpoint chains' own signatures
  do (Cardano Ed25519, CKB secp256k1). The protocol is therefore *not* post-quantum at the
  signature/pairing layer, and *says so*.
- **The Cardano→CKB oracle has a clean PQ upgrade path that is already prototyped.** A
  **STARK** proof of the *same* Mithril statement uses **FRI — hashes only — so it is
  plausibly post-quantum and needs no trusted setup**. All four Mithril relations have been
  composed into a single STARK on a real certificate; verified as a FRI verifier in CKB-VM, it
  is a drop-in behind `cardano_tx_is_certified`. Mithril itself is moving toward STARK-based
  certificates for the same reason.
- **The CKB→Cardano oracle's PQ upgrade is genuinely harder, and we do not pretend
  otherwise.** Groth16 is pairing-based; a post-quantum replacement would mean verifying a
  hash-based (FRI/STARK) proof *on Cardano*, which today has BLS12-381 builtins but no
  efficient FRI verifier in its script budget. Until such a primitive exists (or recursion
  wraps the STARK into something Cardano can check cheaply), this leg's quantum resistance
  tracks the underlying pairing assumption.

**Summary:** the data structures are PQ; one oracle has a ready PQ path; the other's PQ path
is open research; and the endpoint signatures bound the whole — *a protocol cannot be more
post-quantum than its two chains.*

---

## 9. On Bitcoin (reconciling with RGB++)

Does this subsume RGB++ — can BTC leap to CKB here too? **Yes, in exactly the RGB++ sense, and
only in that sense.** Bitcoin can serve as an anchor: CKB runs a Bitcoin SPV light client as
its oracle, and value can leap **BTC ⇄ CKB** bidirectionally — because leap-out to Bitcoin
(§3.3) is just an ordinary Bitcoin spend the follower observes, and **never asks Bitcoin to
verify CKB**.

What Bitcoin *cannot* do is host **Oracle B** — it cannot verify CKB consensus in-script, so
the *CKB-anchored, Bitcoin-follows* leg is impossible. Bitcoin is therefore a **one-way
anchor**: it can anchor (CKB follows), but it can never *follow*. The same property makes
other PoW UTXO chains (LTC, DOGE) anchor-only. The symmetric, verify-each-other topology of §6
requires a follower that can check a succinct proof on-chain — which is why we built first on
Cardano (Plutus + BLS12-381) rather than Bitcoin.

So BTC↔CKB leap is *inherited* from RGB++ as a degenerate (anchor-only) case; the new thing
this protocol adds is the *symmetric* case, impossible with Bitcoin, demonstrated with Cardano.

---

## 10. Generalization: anchor-agnostic binding

Because only the oracle is direction-specific, adding a chain `X` reduces to writing the
relevant oracle(s):

- **`X` as anchor, CKB follows** — needs an `X`-light-client oracle *in CKB-VM*. Cheap for SPV
  chains (Bitcoin family); a Mithril/ZK verifier for Cardano.
- **CKB as anchor, `X` follows** — needs a *CKB-consensus verifier on `X`*. Trivial where `X`
  has a native Groth16 builtin, tractable where `X` has BLS12-381 primitives (Cardano), and
  *impossible* where `X` has no in-script verification (Bitcoin → anchor-only).

The binding construction (§3) never changes. A chain that can both be watched and verify back
becomes a **first-class, symmetric** counterparty; a chain that can only be watched becomes an
**anchor-only** counterparty in the RGB++ tradition.

---

## 11. Endgame: symmetric and both succinct

Today the two oracles differ in *kind*: a stake-threshold signature one way, a SNARK the
other. The trust-minimized endgame swaps Mithril for a **ZK proof of Ouroboros Praos** behind
the same interface (prototyped as a STARK of the Mithril statement) and retires the Groth16
trusted setup with a **universal-SRS PLONK** verifier. The destination:

> a fully bidirectional, **anchor-agnostic, committee-free** protocol in which **each chain
> verifies the other by a single succinct proof**, the isomorphic-binding construction
> unchanged on both sides — same binding, two oracles, both succinct.

RGB++ showed that a chain can be a verification layer for another by running its light client
in-script. This work shows that when *both* chains can do so, the binding becomes symmetric,
and the protocol needs no one to trust but the two chains themselves.

---

## Appendix · Where the protocol lives

| Component | Path |
|---|---|
| Cardano seal NFT + binding lock (Aiken) | `cardano/binding/` |
| CKB `BoundAsset` type script (genesis/transition/finalize) | `spike/phase1/` |
| Mithril cert verify + tx-membership oracle (CKB-VM) | `spike/light-client-cell/`, `spike/cross-chain/` |
| ZK-of-Mithril (STARK, the PQ / trustless drop-in) | `spike/cardano-to-ckb-zk/` |
| Groth16 verifier in Plutus (CKB→Cardano on-chain half) | `spike/ckb-to-cardano/groth16/` |
| CKB consensus circuit + prover (off-chain half) | `spike/ckb-to-cardano/circuit/` |
| Relayer (liveness only) | `relayer/` |
| Architecture, specs, and measured/live status | `docs/DESIGN.md`, `docs/BINDING_SPEC.md`, `docs/CKB_TO_CARDANO.md`, `docs/CHIRAL_STATUS.md`, `docs/LIVE_STATUS.md` |

*Measured cycle/CPU figures and live transaction artifacts are kept in the status docs above,
which track the running testnet deployments.*
