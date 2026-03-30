# Acceptance investigation (ground-truth oracle)

Goal: make a REAL preview certificate's aggregate signature actually verify, to turn the
P2 acceptance from 🔴 to 🟢. Used **blst** (the exact C library mithril-stm uses) on the host
as ground truth, plus an attempt with mithril-stm's own types.

## Tried (all against real preview cert points)
- single `sigma0` vs `mvk0` (reg[0]) — 6 message reps × 5 DSTs × {no-aug, aug=pk} = 60 combos.
  Messages: raw-32B, ascii-hex-64B (lower/upper), blake2b-256 and sha-256 of each.
  DSTs: empty (from source), the SSWU G1 suites (NUL/AUG/POP), bare suite.
- plain aggregate `Σσ` vs `Σmvk` over the same message set.
- **multiplicity** aggregate `Σ countᵢ·σᵢ` vs `Σ countᵢ·mvkᵢ` (counts 1127, 1203) — the
  "counted per winning index" hypothesis.

**Result: none verified.** (`blst_sweep.rs`.) An attempt to deserialize the cert directly
into `mithril-stm`'s `AggregateSignature<D>` / `AggregateVerificationKey<D>` and call its own
`verify(msg, avk, params)` hit a serde bound on the digest type (`mithril_stm_oracle.rs`,
v0.10.5) — solvable but version-fiddly.

## Conclusion
The certificate is valid (mithril's own client verifies it); what black-box reconstruction
**cannot** recover is the exact byte string mithril's protocol layer feeds blst as `msg`
(and/or how the aggregate VK is formed for the batch-compat path). The `signed_message` field
is not directly the signed bytes under any simple transform we tried.

**Acceptance therefore requires a faithful source-port**, not reverse-engineering:
1. read `mithril-stm`'s `protocol` module: how `SingleSignature`/`AggregateSignature` build
   the message handed to blst, and how `verify`/`verify_aggregate` form the aggregate VK;
2. reimplement that exactly over `bls12_381` (no blst);
3. differential-test against `mithril-stm` on the host, pinning a real preview cert as a
   fixture, until `verify` returns Ok in-script.

This does **not** affect the feasibility verdict: the **cost** (≈135M cycles ≈ 3.85% of a
block, measured on real data) and structure are independent of matching the exact message.
What this investigation sharpens is the Phase-2 estimate — the reimpl is a faithful protocol
port (message construction + STM semantics), not just a BLS-backend swap.
