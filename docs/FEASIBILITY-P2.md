# FEASIBILITY — Phase 2 (real aggregate-verify in CKB-VM, true end-to-end cost)

> **✅ RESOLVED (2026-06) — kept as the audit trail.** This doc honestly recorded that the cost was
> measured (~135M cycles, ~3.85% of a block) but cryptographic *acceptance* had **not** yet landed
> (the `🔴 bit-exact acceptance` row). **That is now GREEN:** the missing detail was
> `msgp = signed_message ‖ avk_root` (message first); a real preview cert now verifies in-script
> (`verified = true`, 146,223,644 cycles). See `DEV_LOG.md` ("ACCEPTANCE GREEN"),
> `spike/mithril-verify/VERIFIED_RECIPE.md`, and the live `AdvanceCert`/`TxSetCert` on Pudge.
>
> Follow-up to `FEASIBILITY.md` / `FEASIBILITY-P1.5.md`. Phase 2 builds an
> actual in-script aggregate-signature verifier over `bls12_381` and runs it on a **genuine
> Cardano preview certificate**, for a true end-to-end cycle count.
>
> **Cost verdict: confirmed GO — now empirical.** Cryptographic *acceptance* of the real cert
> was **not** achieved this session; it is a bounded correctness task (below), not a
> feasibility blocker.

## What was built

1. **Relayer transcode** (`spike/mithril-verify/transcode.py`) — parses a real cert's ~27 KB
   serde_json `StmAggrSig`, extracts the **distinct winning signers'** sigmas (G1, 48 B) and
   mvks (G2, 96 B), the signed message, and the total winning-index count. (Preview: **2**
   distinct signers, **2330** total indices ≥ `k=1944`.) This is the off-chain step that
   hands the CKB script a compact form instead of the JSON blob.
2. **In-script verifier** (`spike/mithril-verify/mithril_verify_bench.rs`) — over `bls12_381`
   (no blst): decode 2×G1 + 2×G2, aggregate by sum (same-message, PoP-registered), hash the
   message to G1 with **empty DST**, and check the aggregate pairing equality
   `e(Σσ, g2) == e(H(msg), Σmvk)`; plus 2330 eligibility `blake2b` hashes (representative of
   the lottery checks). Built for `riscv64imac-unknown-none-elf` and run under `ckb-testtool`.

## Result — true end-to-end cost (real cert)

```
full-shape verify on CKB-VM = 134,834,769 cycles  (3.85% of the 3.5e9 block budget)
  = decode 2xG1 + 2xG2 + aggregate + hash-to-curve(msg) + 2 pairings + 2330 blake2b
cryptographically VERIFIED in-script = FALSE  (this session)
```

The **cost** is a real measurement on real certificate data and lands almost exactly on the
Phase-1 model (~134M). So the feasibility headline is now empirical, not estimated: **a full
Mithril-style aggregate verify costs ≈ 3.85 % of a CKB block.**

## What did not land, and why (honest)

The aggregate **pairing equality did not hold**, so the real certificate did **not**
cryptographically verify in-script this session. Cross-checked two ways:

- in-script with `bls12_381`'s IETF hash-to-curve (rigorous), empty DST, msg = `signed_message`;
- offline with `py_ecc` over a single real signature, sweeping msg ∈ {raw-32B, ascii-hex-64B}
  × DST ∈ {empty, standard SSWU suites}.

None verified. The DST is confirmed **empty** from source (`signature_scheme/
bls_multi_signature/signature.rs`: `verify(false, msg, &[], &[], &mvk, false)`), so the gap
is **the exact bytes mithril-stm feeds blst as `msg`** (and/or any internal domain framing of
the message before hashing) — a convention this spike did not reverse-engineer bit-for-bit.

This is a **correctness** task, cleanly bounded:
- port the message construction directly from `mithril-stm` (`StmAggrSig::verify` →
  `Signature::verify_aggregate` → blst), or
- differential-test the pure-Rust verifier against `blst` on the host until a real cert
  verifies, then lock it with that cert as a fixture.

It does **not** move the feasibility verdict: the verdict rests on (a) granularity, (b)
latency, and (c) cost/structure — all answered — and the per-op + full-shape costs are
identical whether or not the equality holds.

## Net status of the load-bearing assumption

| Dimension | State |
|---|---|
| (a) granularity (prove a specific spend) | 🟢 Mithril certifies the Cardano tx set w/ Merkle membership |
| (b) freshness | 🟡 ~10-min cadence; near-tip work in progress |
| (c) cost | 🟢 **measured: full verify ≈ 135M cycles ≈ 3.85% of a block** on a real cert |
| real points usable in-script | 🟢 real mvk decodes + pairs (P1.5); real cert parsed + verify *shape* run (P2) |
| toolchain | ⚠️ `mithril-stm`/blst can't target CKB → pure-Rust reimpl over `bls12_381` (proven to compile + run) |
| bit-exact acceptance | 🔴 not yet — match mithril's exact signed-message bytes (bounded Phase-2 correctness) |

**GO stands.** Phase 2 turned the cost from a model into a measurement on real data and built
the verifier skeleton; the one open item is reproducing mithril's exact message convention so
the equality holds — engineering, not research risk.

## Sources
- Empty DST: mithril-stm `signature_scheme/bls_multi_signature/signature.rs`
  (`verify(false, msg, &[], &[], …)`), docs.rs source, v0.10.5.
- Real cert: `aggregator.testing-preview.api.mithril.network` `/certificate/{hash}`.
- Measurement + transcode: `spike/mithril-verify/` (this branch).
