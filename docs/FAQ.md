# Chiral - Community FAQ

> Plain-language answers to the questions people will actually ask. Chiral is a
> trust-minimized Cardano ⇄ CKB protocol built on the isomorphic binding idea pioneered
> by RGB++ (Cipher / Nervos). This FAQ is written to be quoted directly. For the full
> technical story see `LIGHTPAPER.md`; for live status see `CHIRAL_STATUS.md` / `LIVE_STATUS.md`.

---

## The one-liner

Chiral is RGB++'s core idea - isomorphic binding - made symmetric. RGB++ lets CKB verify
Bitcoin. Chiral lets *each chain verify the other*, on-chain, with a single succinct proof and
no committee, multisig, or custodian anywhere.

---

## "Is this just RGB++?"

No - and we credit RGB++ openly; it's the foundation.

What we keep from RGB++: the *isomorphic binding* construction. Ownership of an asset is a
single-use seal on one chain; the asset's programmable state lives as a cell/UTxO on
another; every move is committed into the seal's transaction, and the other chain verifies that
commitment *in-script* against a light client it runs of the first chain. That's Cipher's
insight, and it's the heart of Chiral too.

What's new in Chiral: RGB++'s anchor is Bitcoin, and Bitcoin can be *watched* but can't
*watch back* - it has no way to verify CKB consensus on-chain. So RGB++ binding is
one-directional in capability: CKB verifies Bitcoin, never the reverse.

Chiral observes that the binding itself is symmetric - *only the oracle each side runs is
direction-specific* - and instantiates both directions:

- CKB verifies Cardano using Mithril (Cardano's stake-based BLS certificate), checked
  inside CKB-VM.
- Cardano verifies CKB using a Groth16 SNARK of CKB's Eaglesong PoW consensus, checked
  inside a Plutus script (via Cardano's BLS12-381 builtins).

Result: a protocol where each chain cryptographically verifies the other. RGB++ couldn't do this
with Bitcoin; Chiral does it with Cardano.

---

## "So what's the actual difference?" (the table)

| | RGB++ | Chiral |
|---|---|---|
| Core idea | Isomorphic binding | Isomorphic binding *(same)* |
| Anchor / partner chain | Bitcoin ↔ CKB | Cardano ↔ CKB |
| Who verifies whom | CKB verifies Bitcoin (SPV) | Both: CKB verifies Cardano *and* Cardano verifies CKB |
| Bitcoin verifying CKB? | Impossible (no smart contracts) | N/A - Cardano *can*, via a SNARK |
| Trust topology | One chain anchors, one follows | Symmetric - neither chain is privileged |
| Committee / multisig | None (true for both) | None |
| Asset model | Anchored, not wrapped | Anchored, not wrapped *(same)* |

Short version: RGB++ = one-way verification (Bitcoin anchors). Chiral = two-way verification
(each chain checks the other). Same binding, two oracles.

---

## "Is Chiral a bridge?"

We don't call it one - and the distinction is real, not cosmetic. "Bridge" in crypto almost
always means lock-and-mint: lock an asset in a contract on chain A, have a custodian or
committee mint a wrapped IOU on chain B, and leave a honeypot of locked funds sitting there to be
drained. That design is behind most of the largest hacks in the space.

Chiral is isomorphic binding, not lock-and-mint:

- No custody pool - there's no pile of locked funds to steal.
- No wrapped IOUs - your asset is *anchored*, not re-issued as a synthetic.
- No committee or custodian - verification is a cryptographic proof checked on-chain.

So when someone asks "is this a bridge?", the honest answer is: it does what people wish
bridges did - move value across chains - without the lock-and-mint machinery that makes bridges
dangerous. Chiral is a binding protocol, not a custodial bridge.

---

## "Why Cardano instead of Bitcoin?"

Because Bitcoin can't verify anything complex on-chain. For the *symmetric* trick - having the
partner chain verify CKB - you need a chain that can check a succinct proof in its scripts.
Cardano can: it has BLS12-381 builtins that make a Groth16 verify cheap (~a quarter of a
transaction's budget). Bitcoin has no such capability, which is exactly why RGB++ binding stops
at one direction.

This isn't a knock on Bitcoin - it's the whole reason Chiral picks a programmable partner.

---

## "Can BTC still leap to CKB, then?"

Yes - exactly as it does in RGB++. Bitcoin can be an anchor: CKB runs a Bitcoin light
client, value leaps BTC ⇄ CKB in both directions, and leaping *back* to Bitcoin is just an
ordinary Bitcoin spend CKB observes - it never asks Bitcoin to verify CKB.

What Bitcoin *can't* be is a follower (the chain that verifies CKB). So Bitcoin is an
anchor-only chain. Chiral's new, symmetric mode needs a verifying partner, which is why it's
demonstrated with Cardano. BTC↔CKB leap is inherited from RGB++; the symmetric Cardano↔CKB mode
is the new part.

---

## "Is it trustless? Who do I have to trust?"

There is no committee, no multisig, no custodian, no governor in the safety path. The trust
surface is small and *cryptographic/economic*, not "trust these named operators":

- Ownership & double-spend come from each chain's own consensus.
- Cross-chain soundness reduces to one assumption per direction:
  - Cardano → CKB: Mithril's honest-stake-majority (a large, economically-staked quorum).
  - CKB → Cardano: the SNARK's soundness (plus a one-time Groth16 trusted setup, removable
    with a transparent PLONK verifier).
- Relayers are liveness-only. Anyone can relay; a relayer can *delay* a transfer but can
  never forge or steal one - the authorizing commitment is baked into the source-chain
  transaction the proof certifies.

It's "trust-minimized," not magically "trustless" - we say so plainly. But there are no trusted
humans in the path.

---

## "Are my assets wrapped? Is there a custody pool?"

No. Assets are anchored, not wrapped. There's no wADA/wCKB IOU, no custody pool, no peg,
no redemption queue. Ownership is anchored to a seal on one chain while the asset transacts on
the other - the same non-custodial model as RGB++.

---

## "Is it live? Is this on mainnet?"

Both directions have run their full lifecycle on testnets (Cardano preview ↔ CKB Pudge):
bind → transfer → leap-out one way, and lock → verify → mint → burn → unlock the other, with
real Mithril certificates and a real Groth16 proof of CKB consensus accepted on-chain.

There's now a self-serve dApp and a guided, invite-only testnet pilot you can try - see
[`TRY_IT.md`](TRY_IT.md). It remains a prototype: testnet-only, unaudited, no mainnet, no liquidity yet.
What remains is productionization and audit, not the core mechanism. Don't put real funds in it yet.

---

## "How do I actually try it?"

Ask the operator for an access link (`http://<host>:8799/?t=<token>`) and follow
[`TRY_IT.md`](TRY_IT.md): two wallets (JoyID on CKB Pudge, Lace/Eternl on Cardano preview), two faucets,
fund the CKB lock from a single cell ≥ ~365 CKB, then `lock → prove → mint χCKB → burn → release` (and the
mirror χADA direction). Testnet only - nothing has real value.

---

## "How fast is it?"

It's settlement-style, not instant. A transfer completes only after the source-chain spend
is *certified* - Mithril's certification cadence one way, CKB confirmation depth + proving time
the other (minutes-scale per leg). This is deliberate: the protocol only ever acts on *settled*
history, which is also why chain reorgs can't break it.

Concretely on the pilot: the forward proof is ~2 minutes cold (a Groth16 prove on a 2-vCPU box), and the
Mithril-gated legs (release / χADA return) take ~7–10 minutes (waiting for the aggregator to certify the
burn). Those are normal latency floors, not hangs.

---

## "Is it post-quantum?"

Honestly: partly, and we don't overstate it.

- The binding core (commitments, Merkle/MMR proofs, seals - all hash-based) is already
  quantum-resistant.
- The two oracles today use BLS12-381 (Mithril's signature; the Groth16 pairing) - not
  post-quantum, the same as the chains' own signatures (Ed25519, secp256k1).
- The Cardano→CKB leg has a ready PQ upgrade: a hash-based STARK proof of the same
  Mithril statement (already prototyped). The CKB→Cardano leg's PQ path is open research.

Bottom line: a protocol can't be more post-quantum than the two chains it connects. We match
them, with a clear upgrade path on one leg.

---

## "Does this compete with RGB++ / Nervos?"

No - it extends their idea to a new chain pair and a new (symmetric) capability. RGB++ and
isomorphic binding are Cipher's; Chiral stands on that work and says so. If anything it's
evidence that isomorphic binding generalizes well beyond Bitcoin.

---

## "What can I actually do with it?"

Move an asset's *home* between Cardano and CKB without wrapping it: anchor ownership on one chain
while gaining the other chain's programmability for the asset - and leap back when you want. No
custodian holds your funds at any point.

---

## "What's with the name?"

Chirality = a structure whose mirror image can't be superimposed on it: two forms, oppositely
handed, built from the same parts. That's Chiral's architecture - one binding, mirrored into two
oppositely-oriented verification paths (Mithril-in-CKB-VM and Groth16-in-Plutus).

---

## Credits

Chiral builds directly on RGB++ and isomorphic binding by Cipher and the Nervos /
CKB community, on Mithril by IOG / the Cardano community, and on the arkworks and
Aiken ecosystems. The contribution here is making the binding *symmetric* - each chain
verifying the other - not the binding itself.
