# Cardano→CKB as ZK (making the reverse leg ZK too) — spec + honest staging

The reverse leg today uses **Mithril** (BLS threshold cert of Cardano state) verified in **CKB-VM**.
This spec is the path to replace that trust assumption ("honest majority of the Mithril signer set")
with **cryptographic soundness** — a succinct proof of Cardano consensus verified in CKB-VM. It mirrors
the forward leg (ZK-of-CKB-in-Plutus) but is materially harder, so this is staged, not "done."

## Why it's harder than the forward direction
- CKB is **Nakamoto PoW** → verifying it = hashes + Merkle (what we built). Cheap in a circuit.
- Cardano is **Ouroboros Praos** → verifying it means, per block: a **VRF** leader-eligibility proof
  (the slot leader was elected with prob ∝ stake), a **KES** signature (forward-secure, evolving key),
  the **operational certificate**, and the **stake distribution / epoch nonce** the VRF is checked
  against. That's ECVRF (curve25519) + KES (sum-composition of Ed25519) + the leader-value threshold
  comparison — all in-circuit, across an epoch's worth of blocks.

## Key architectural advantage on the destination side
CKB-VM is **RISC-V** — it can run *any* verifier as a program, with **no pairing/curve builtins
required**. So unlike Plutus (which forced us to Groth16/BLS12-381), the reverse direction can verify a
**hash-based STARK** directly in CKB-VM. STARKs are:
- **quantum-resistant** (FRI = hashes only) — answers the earlier quantum question for this leg,
- **no trusted setup** (no ceremony needed),
- a natural fit for the ARX/hash-heavy work of consensus verification.

## The statement (what the reverse proof attests)
Public inputs: `(ckb_checkpoint, cardano_tip_or_root, burn_event)`.
Relations:
- **C1 — chain validity.** A sequence of Cardano headers from the trusted checkpoint to `cardano_tip`,
  each with a valid VRF leader proof + KES signature under the epoch's stake distribution & nonce, and
  correct epoch transitions. (The "heaviest/longest valid chain" analogue of the CKB advance.)
- **C2 — inclusion.** The lock/burn tx is in a block under that tip (Cardano's tx Merkle structure).
- **C3 — binding.** The tx burns/locks the bound asset and carries the commitment (mirror of R4).

## Realistic staging (each a shippable milestone)
1. **STARK-Mithril (recommended first step).** Mithril is itself moving to **STARK-based certificates**
   for post-quantum security. Adopting that = a hash-based proof of the *same* Mithril statement, giving
   PQ + no-ceremony **without** building ZK-Ouroboros. Verified in CKB-VM as a FRI verifier. This is the
   high-value, tractable upgrade and the recommended path.
2. **ZK-of-Praos, incremental.** Build the consensus gadgets in stages: (a) the tx-inclusion Merkle
   (C2) — easy, like CBMT; (b) KES/Ed25519 signature verification; (c) ECVRF leader proof + threshold;
   (d) stake-distribution & epoch-nonce handling; (e) the chain-extension/recursion (one STARK per
   epoch, recursively folded), the analogue of AdvanceCKBCert.
3. **Recursion.** Use a recursive STARK (or a STARK→Groth16 wrap if a Plutus-side check is ever wanted)
   so the per-leap proof is O(1) regardless of chain length — same checkpoint-amortization idea as the
   forward leg's AdvanceCKBCert.

## Honest status
Not built. The forward leg (CKB→Cardano) is complete and on-chain-verified; this reverse-ZK leg is a
scoped research track. The pragmatic near-term is **Mithril now → STARK-Mithril** (PQ + ceremony-free),
with full ZK-Ouroboros as the long-horizon symmetric endgame. CKB-VM's ability to run a STARK verifier
natively is what makes this leg's destination side straightforward once the proof exists.
