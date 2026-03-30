# Reverse leg: trustless unlock on CKB (Cardano→CKB), status + design

The forward leg is fully trustless on-chain (CKB→Cardano: ZK proof of PoW verified in Plutus). The
reverse unlock today is key-authorized (LEAP.md). Making it trustless = CKB must be cryptographically
convinced of the Cardano burn. Production primitive: **Mithril** (BLS threshold multisig of Cardano stake).

## What is REAL now (verified on testnets)
- Our burn `6608c4c8…` is **Mithril-certified** (preview aggregator, cert `7356eaa1…`, epoch 1321).
- The cert is real: 27.5 KB BLS STM multisig + AVK + signed Merkle root; chain links verified (26 certs).
  Evidence: `mithril_verify/{proof,cert}.example.json`.

## The CKB `reverse_unlock` script (design)
A CKB-VM lock script on the bound cell that releases it iff a Mithril-certified burn is shown:
- **Args:** the bridge config — the Mithril genesis verification key (anchors the cert chain), and the
  bound asset's `seal`/`commitment`.
- **Witness:** `(certificate, multi_signature, avk, protocol_message, tx_inclusion_proof)`.
- **Checks (all on-chain in CKB-VM, RISC-V):**
  1. `tx_inclusion_proof` proves `burn_tx` is under `protocol_message.cardano_transactions_merkle_root`.
  2. `signed_message == hash(protocol_message)` (Mithril's canonical message hashing).
  3. **STM verify**: the BLS aggregate `multi_signature` is valid for `avk` + epoch stake/params over
     `signed_message` (the trustless core — Cardano stake signed it).
  4. cert chain: `avk` is certified by the prior epoch cert (`next_aggregate_verification_key` hand-off),
     terminating at the genesis cert signed by the genesis VK in args.
  5. **binding**: `burn_tx` burns the ckCKB whose policy/asset encodes THIS bound cell's seal/commitment,
     for the right amount (conservation) — so this specific unlock matches this specific burn.
- Feasibility: blake2b + secp/Merkle are cheap in CKB-VM; **BLS12-381 STM** compiles to CKB-VM riscv64
  via a `no_std` bls12_381 (the same curve as the forward leg). This is the heavy remaining build.

## Honest status
- ✅ trust anchor real (burn is Mithril-certified; cert + chain inspected on real data).
- ⏳ STM aggregate-signature verification: not executed here (mithril-client dep drift); it is the
  crux of both the off-chain check and the CKB-VM script.
- ⏳ CKB-VM deployment of the STM verifier + the binding script.
The quantum-resistant variant (per SPEC.md): once Mithril ships STARK certificates, the CKB-VM verifier
becomes a FRI verifier (hash-based, no pairings) — preferable long-term.
