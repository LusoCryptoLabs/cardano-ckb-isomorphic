# Forward-leg circuit restructure — shrink the per-leap proof out of 2²³ (design + IMPLEMENTED)

Follows `CIRCUIT_SIZING.md`. **Status: signed off; per-leap circuit IMPLEMENTED + proven**
(`prover/src/bin/leap_windowed.rs`). The CKB/Aiken side (AdvanceCKBCert maintaining the window root;
`cardano_bound` reading `window_root` instead of `chain_root`) is the remaining piece. It changes a
security-relevant part of R2 (how chain membership is proven) — design + measurements below.

## Implemented & measured (`leap_windowed.rs`, real block 21,341,101)
R2's ~25-deep 120-byte MMR membership is replaced by a `merkle_gadget::merkle_root` over the proven
header's block-hash against a depth-`log2(W)` **window root** (32-byte nodes). End-to-end Groth16
setup+prove+verify passes (`arkworks verify = true`). Measured R1CS:

| circuit | constraints | domain |
|---|---|---|
| full chain-MMR (today, depth ~25) | ~4,861,314 | 2²³ |
| **windowed, W=64 (depth 6)** | **1,227,901** | **2²¹** |
| windowed, W=256 (depth 8) | 1,329,663 | 2²¹ |

A ~4× cut, **two SRS tiers down (2²³ → 2²¹)** — better than the conservative estimate below (the real
32-byte window Merkle is ~½ the 120-byte MMR per-node cost). Even a 256-block staleness window fits 2²¹,
with headroom for D2-A (~+0.5 M). The estimate/derivation that follows is retained for context.

## Problem
The per-leap circuit is **~4.9 M constraints (2²³)** at production MMR depth, and **MMR membership is
~75–80 % of it** (~155 K per merge × ~25 merges for a ~21 M-block chain). The membership depth is
`log2(chain_size) ≈ 25` **regardless of how recent the header is** — you cannot make it shallow just by
referencing a fresh block, because the leaf sits ~25 deep on its mountain. So every leap pays the full
chain-MMR cost, blowing the proving domain to 2²³ (for which no public BLS12-381 SRS exists) and the
prover key/RAM with it.

## Design: amortize membership into the checkpoint, prove shallow per-leap
Split the work the way the protocol already splits it for `AdvanceCKBCert`:

- **`AdvanceCKBCert` (amortized, run by the relayer per header/range — already validates PoW + difficulty +
  parent-linkage + appends to the chain-MMR):** *additionally* maintain a **rolling window root** `W_root`
  over the last `W` validated header hashes (a small Merkle/ring-buffer accumulator, depth `log2(W)`). This
  is cheap and paid once per block, not per leap.
- **Per-leap proof:** instead of proving `header ∈ full-chain-MMR` (depth ~25), prove
  `header ∈ window(W_root)` (depth `log2(W)`), where `W_root` is read from the (authenticated) checkpoint
  cell — exactly as the leap already reads `chain_root` today. R1 (PoW), R3 (CBMT), R4 (commitment) are
  unchanged.

**Security argument (trust unchanged).** A header in the window is one that `AdvanceCKBCert` already
validated (PoW ≤ target, difficulty, parent linkage) and that sits on the heaviest chain it tracks. The
checkpoint is anchored exactly as today (genesis trust + cumulative-work monotonicity). So membership in
`W_root` ⇒ "a PoW-valid header on the canonical chain as tracked by the trustless advance proof" — the
same guarantee R2 gives now, with the deep-MMR check *moved* into the amortized advance step rather than
*removed*. Trust assumptions are unchanged: CKB PoW honest-majority + advance-proof soundness.

**Operational cost (the real trade-off).** The per-leap can only reference a header within the last `W`
blocks of the checkpoint, so the relayer must keep the checkpoint advanced to within `W` of any leap.
That is already the cadence model (the relayer advances continuously; leaps reference fresh spends), and
`W` sets the max staleness window. Pick `W` to cover the settlement-latency the protocol already accepts.

## Measured payoff (from `CIRCUIT_SIZING.md`'s depth sweep)
Per-leap cost ≈ `1.29 M + (depth − 2) × 155 K` (155 K/merge is the **MMR-gadget** cost over 120-byte
leaves — a *conservative upper bound*; a purpose-built window Merkle over 32-byte header hashes is ~½ that
per merge):

| membership | depth | constraints | domain |
|---|---|---|---|
| full chain-MMR (today) | ~25 | ~4.9 M | **2²³** |
| window `W = 4096` | 12 | ~2.8 M | 2²² |
| window `W = 256` | 8 | ~2.2 M | 2²² |
| **window `W = 64`** | **6** | **~1.9 M** | **2²¹** |
| window `W = 16` | 4 | ~1.6 M | 2²¹ |

So bounding membership depth to **≤ 6 (a recent window ≤ 64 blocks)** brings the per-leap circuit to
**~2²¹** — a ~2.5× constraint cut, **down two SRS tiers** (2²³ → 2²¹), where the existing public ~2²¹
BLS12-381 Powers-of-Tau becomes reusable and prover key/RAM/time drop accordingly. A bespoke 32-byte
window Merkle would land comfortably inside 2²¹ even at `W = 256`.

## Open questions for review (before implementation)
1. **`W` choice** — tie to the accepted settlement latency; `W = 64` (~5–10 min at CKB block time) is a
   reasonable default and gives 2²¹.
2. **Window accumulator form** — ring-buffer Merkle vs a small MMR-of-window; must be cheap to update
   in `AdvanceCKBCert` and give `log2(W)` membership.
3. **Reorgs** — the window only admits settled/confirmed headers (the advance proof already acts on
   sufficiently-deep headers), so short tip reorgs never enter the window; confirm the depth margin.
4. **Do we still want a periodic full-MMR cross-anchor?** Optional belt-and-suspenders: occasionally bind
   `W_root` back to the full chain-MMR root in an advance step.
5. **D2-A interaction** — per-outpoint membership (~+0.5 M) still fits 2²¹ here with room to spare.

## Recommendation
Adopt the windowed-membership restructure with `W = 64` (target 2²¹), keep D2-A, and freeze the circuit
*after* this lands. This is the single highest-leverage production change — it decides the SRS tier and
the prover footprint — and it should be the first thing built once the design is signed off.
