# Next anchors — generalizing the binding to Sui, Polkadot, and Tezos

> Design note (no code yet). The isomorphic binding is **oracle-swappable** — "both legs are the
> same binding; only the oracle differs" (`CKB_TO_CARDANO.md §0`). Adding a chain = writing the
> verification oracle for it; the seal + bound-cell machinery is unchanged. This note scopes the
> next three smart-contract anchors and the fast-ship order. Companion: `DESIGN.md`,
> `CKB_TO_CARDANO.md` (the CKB→Cardano leg this generalizes), `CHIRAL_READINESS.md`.

## The framing: CKB as a multi-anchor binding hub

Today: a symmetric Cardano ⇄ CKB binding (Mithril verifies Cardano in CKB-VM; a Groth16 proof of
CKB consensus verifies CKB in Plutus). The natural extension is **many anchors, one CKB state
layer** — each new chain plugs in via its own oracle.

### The rule that decides what's possible per chain
A chain can be a **symmetric** anchor (both legs: it-follows-CKB *and* CKB-follows-it) only if it
can **verify a proof of CKB consensus on-chain within budget** — in practice, verify a SNARK/STARK
(native Eaglesong verification is infeasible). Smart-contract chains can; PoW UTXO chains (BTC/LTC/
DOGE) cannot, so those get RGB++-style **one-way** binding only (they anchor, CKB follows).

All three chosen anchors are smart-contract chains with **on-chain BLS12-381 Groth16 verification**,
so they reuse the **existing live CKB-consensus Groth16 proof with no curve swap** (it is already
BLS12-381, 3 public inputs). What differs is verifier effort and ownership-model fit.

## The three anchors (verified capabilities, 2026-06)

| | Sui | Polkadot (Substrate parachain) | Tezos |
|---|---|---|---|
| On-chain proof verify | **Native builtin** `sui::groth16::verify_groth16_proof(bls12381(), …)` | Host functions `sp_crypto_ec_utils::bls12_381` (multi-Miller + final-exp); `zkmega`/`megaclite` expose Groth16 verify | BLS12-381 + `PAIRING_CHECK` **primitives only** (since Edo/008) |
| Curve | BLS12-381 (and BN254) — **reuse our proof** | BLS12-381 (also bn254/bls12-377/bw6-761) — **reuse our proof** | BLS12-381 — **reuse our proof** |
| Public-input limit | up to **8** (we use 3 ✓) | circuit-defined (no fixed cap) | circuit-defined |
| Verifier effort | **Lowest** — stdlib call, nothing to hand-roll | **Low–medium** — a pallet / ink! chain-extension over the host fns | **Highest** — hand-write the Groth16 verifier in Michelson |
| Ownership model | **Object model = native single-use seal** (best fit) | Account-based → **emulate** the seal in contract storage | Account-based → **emulate** the seal |
| Ecosystem / liquidity | Strong | Strong (parachain-dependent) | Smaller |
| Note | API needs a trusted setup per circuit (we have a 3-party ceremony); mind Groth16 proof malleability | "Polkadot" = pick a parachain (ink!/pallet-contracts, or a runtime pallet); relay chain runs no contracts | Tooling sparse; ZoKrates can target BLS12-381 |

## Fast-ship order (priority: fastest to ship)

**1. Sui — build first.** The native Groth16 builtin removes the verifier entirely; BLS12-381 is
supported so the existing proof drops in; the object model gives a native seal; 3 inputs are within
the 8-input cap. Fastest *and* cleanest. The only tax is writing one Move module + learning Move.

**2. Polkadot — second.** The Substrate EC host functions + `zkmega`/`megaclite` give a low-effort
Groth16 verify over BLS12-381 (a pallet or an ink! chain-extension). Pick the parachain first
(ink!/pallet-contracts on a contracts parachain, or a custom runtime pallet). Seal is emulated.

**3. Tezos — third.** Same curve (reuse the proof), but you hand-write the verifier in Michelson —
the most verifier code and audit surface of the three. Do it when a same-curve, you-control-the-
verifier target is worth the effort, or for Tezos-ecosystem reach.

## What each "anchor" delivery includes — and what to defer

The **fast** deliverable per chain is the leg **where the new chain verifies CKB** (the mirror of
the live CKB→Cardano round trip): CKB holds the seal, chain X verifies our CKB-consensus Groth16
proof and holds the bound state. This reuses everything already built (the consensus circuit, the
prover, the proof, the AdvanceCKBCert checkpoint pattern).

**Deferred (the slow part, same for any chain):** the reverse oracle — **CKB verifying chain X's
finality in-script** (so X can be the *ownership anchor*, like Cardano via Mithril). Each needs its
own in-CKB-VM verifier:
- **Sui / Polkadot:** BFT/PoS consensus → verify a validator quorum / GRANDPA-style finality proof
  (closer to the Mithril cert verify than to a PoW SPV).
- **Tezos:** Tenderbake (BFT) finality → verify the block's quorum certificate.

A full **symmetric** binding for a new chain = the fast leg **+** its reverse oracle. "One fast
anchor" = just the fast leg.

## Per-chain build checklist (the fast leg)
1. Re-encode the existing BLS12-381 vk + proof to the chain's expected serialization
   (Sui: `prepare_verifying_key` 4-array form; Polkadot: ark-scale; Tezos: Michelson BLS encoding).
2. Implement the binding lock on the chain (mirror of `cardano_bound.ak`): verify the proof, bind
   public inputs to `(ckb_checkpoint_root, seal, commitment(new_state))`, enforce continuity.
   - Sui: a Move module (object = seal). Polkadot: a pallet/ink! contract (emulated seal).
     Tezos: a Michelson/LIGO/SmartPy contract with a hand-rolled Groth16 verifier (emulated seal).
3. The AdvanceCKBCert checkpoint on the chain (advance the proven CKB header-MMR root), reusing the
   existing `advance_prove` circuit + proofs.
4. A relayer that proves from live Pudge data → submits to chain X. (Liveness only; X re-verifies.)
5. End-to-end on chain X's testnet, mirroring the preview↔Pudge runs.

## Shared caveats
- **Trusted setup:** the Groth16 verifier inherits the existing 3-party ceremony; a universal-SRS
  (Plonk) verifier per chain would retire it. Phase-5 / audit item.
- **Seal emulation (Polkadot/Tezos):** account-based chains track "spent once" in contract storage
  — a small extra trust/logic surface vs. Sui's/Cardano's native single-use ownership.
- **Nothing here is built yet** — this is the same *pattern* as the live Cardano legs, a new oracle
  + lock per chain. Effort is real (a verifier/lock + tooling + testnet bring-up each).

## Sources (capability verification, 2026-06)
- Sui Groth16 (BLS12-381/BN254, ≤8 inputs, prepared VK): <https://docs.sui.io/guides/developer/cryptography/groth16>, <https://docs.sui.io/references/framework/sui_sui/groth16>
- Tezos BLS12-381 + `PAIRING_CHECK` primitives (Edo), verifier built at contract level: ZoKraTez <https://www.dailambda.jp/blog/2021-02-21-zokratez/>
- Substrate/Polkadot EC host functions + Groth16 verify: <https://paritytech.github.io/polkadot-sdk/master/sp_crypto_ec_utils/bls12_381/host_calls/index.html>, `zkmega`/`megaclite` <https://github.com/Polkadex-Substrate/megaclite>
