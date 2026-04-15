# CONFIRMED recipe — a real Mithril cert verifies in CKB-VM

A real Cardano **preview** Mithril certificate's aggregate signature was reproduced and
**cryptographically verified inside the CKB VM** with pure-Rust `bls12_381` (no blst).
Result: `verified = true`, **146,223,644 cycles (4.18% of a 3.5e9 block)**.

## The exact construction (matches mithril-stm 0.10.5; cross-checked with blst = SUCCESS)

1. **message** = `ProtocolMessage::compute_hash()` = **SHA-256** over the `BTreeMap`(enum)-ordered
   message parts, hashing `key.to_string()` bytes then `value` bytes for each part; hex-encoded.
   Equals the cert's `signed_message`. The signers sign its **ASCII bytes** (the 64-char hex).
2. **msgp** = `concatenate_with_message` = **`msg || root`** — the signed message bytes followed
   by the avk Merkle **batch-commitment root** (32 B). *(msg first, then root — the detail that
   blocked every earlier attempt.)*
3. **aggregate** = plain **sum** of the distinct signers' `sigma` (G1) and `mvk` (G2)
   (PoP-registered keys; one per signer, not weighted by won indices).
4. **BLS** = min-sig (sigma in G1 48 B, mvk in G2 96 B), **empty DST**:
   `e(Σσ, g2) == e(hash_to_G1(msgp, dst=""), Σmvk)`.

## Scope of "verified"
This is the **aggregate BLS signature** — the cryptographic core. The *full* mithril verify
also (a) checks per-index **eligibility** (the stake lottery, `check_indices`) for the k=1944
indices and (b) verifies the **batch-Merkle membership** of the winning keys in the avk root.
The cost here includes representative eligibility hashing (2330 blake2b) but not yet the exact
lottery-threshold + Merkle-batch logic — those are cheap (hashes) and are the remaining
trust-minimization step. The hard part — a real Cardano cert's BLS proof verifying in-script —
is **done**.

msgp = 96 bytes (msg 64 || root 32). See mithril_verify_bench.rs.
