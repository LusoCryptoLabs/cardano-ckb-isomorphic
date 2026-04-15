# STARK-Mithril: a succinct proof of a Mithril certificate, verified in CKB-VM (the ZK reverse leg)

Goal: make Cardano→CKB ZK without (a) porting BLS-STM to a CKB-VM script, or (b) the heavy/ fragile
mithril-client in the on-chain path. The relayer proves "a valid Mithril certificate certifies the burn"
once; CKB-VM verifies a small proof. Both legs become "destination verifies a succinct proof" — symmetric.

## The statement (public outputs bind the unlock)
Public: `(burn_tx_hash, epoch, cardano_tx_merkle_root, genesis_vk_digest)`.
Private witness: the certificate's `protocol_message` parts, the STM `multi_signature`, the `avk`,
the tx-inclusion proof, and the certificate-chain hand-offs.
Relations:
- **M1 — signed message.** `signed_message = Sha256( Σ key‖value over protocol_message parts )`.
  ✅ REPRODUCED on the real preview cert 7356eaa1.. (= 60efc02a..); see `mithril_verify/signed_message.py`.
  Arithmetization: Sha256 (well-trodden in STARKs/SNARKs) over a few hundred bytes.
- **M2 — STM verify (the crux).** the BLS12-381 STM aggregate `multi_signature` is valid for `avk`
  (the Merkle commitment to the stake distribution) and the epoch protocol params, over `signed_message`
  — i.e. > threshold stake signed. This is a set of BLS pairing checks + the per-signer eligibility
  (lottery) checks + the Merkle-stake openings. The dominant proving cost.
- **M3 — inclusion.** `burn_tx_hash` is under `cardano_tx_merkle_root` (Mithril's tx Merkle tree; blake2b
  merges — the same shape as the CBMT gadget we already built).
- **M4 — chain.** `avk` is certified by the prior epoch's `next_aggregate_verification_key`, terminating
  at the genesis cert under `genesis_vk_digest`. (Cert-chain hashing — cheap.)

## Why STARK (vs Groth16) here
- Destination is **CKB-VM (RISC-V)** — it can run a **FRI verifier** directly, no pairing builtins needed.
- **Post-quantum** (hash-based) and **no trusted setup** — unlike the forward Groth16 leg. Aligns with
  Mithril's own STARK-certificate roadmap (when that ships, M2 becomes verifying a hash-based cert — even cheaper).

## Cost shape
M1 Sha256 + M3/M4 Merkle/hash = small. **M2 (BLS12-381 pairings + STM eligibility) dominates** — pairing
verification in a circuit is the known-hard piece (hundreds of k–millions of constraints depending on the
number of signers / aggregation). This is the real remaining build; it is bounded and well-defined (a fixed
signature-verification statement), unlike full ZK-of-Ouroboros.

## Status (honest)
- ✅ Trust anchor real: burn is Mithril-certified; cert + 26-cert chain inspected on testnet.
- ✅ M1 reproduced exactly on the real cert (the in-circuit Sha256 statement).
- ✅ off-chain STM verify now WORKS on real data: the BLS-STM multisig of our burn's cert verifies
     (epoch 1321, k=1944/m=16948/phi_f=0.2) — see mithril_verify/ (git tag 2617.0 + rustls). M2's
     prerequisite is done; what remains is ARITHMETIZING this STM/BLS verification in the STARK.
- ⏳ M2 STM-in-STARK: arithmetize the (now-running) BLS12-381 pairing + eligibility check.
- ⏳ Wrap M1–M4 in a FRI proof; deploy the FRI verifier as the CKB `reverse_unlock` script.
=> Once M2 lands, both directions are ZK and the bridge is fully symmetric (and the reverse leg is PQ).
