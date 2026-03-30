# FEASIBILITY — Phase 1.5 (real preview data + real point in-script)

> **✅ RESOLVED (2026-06) — kept as the audit trail.** The two findings here (use a pure-Rust
> `bls12_381` reimpl; real Mithril points decode + pair in-script) drove the working verifier that
> now runs live. The "remaining before merge" items were all completed. Current state:
> `CHIRAL_STATUS.md` / `LIVE_STATUS.md`.
>
> Follow-up to `FEASIBILITY.md`. Phase 1.5 replaces synthetic inputs
> with **real data from the Cardano preview Mithril aggregator** and answers two questions
> the spike left open: *can `mithril-stm` itself run in a CKB script?* and *do real Mithril
> BLS points work in-script?*
>
> **Verdict unchanged: GO.** Two concrete new findings sharpen the implementation plan.

## Finding 1 — `mithril-stm` cannot run in a CKB script; reimplement over `bls12_381`

`mithril-stm` (v0.10.5) was added to a scratch crate and built for
`riscv64imac-unknown-none-elf`. It **fails to compile**: it pulls

```
mithril-stm → blst (C + asm), rayon, crossbeam-utils, getrandom
error[E0463]: can't find crate for `std`   (the CKB target is no_std)
```

`blst` is a C/assembly library and the dependency tree hard-requires `std`. **There is no
path to using `mithril-stm` as-is on the CKB VM.** The in-script verifier must be a
**pure-Rust reimplementation of the STM aggregate-verify over `bls12_381`** (zkcrypto), which
*does* compile to the CKB target (proven in `FEASIBILITY.md`).

Implication for the architecture: a relayer (off-chain, std, can use `mithril-stm`) fetches
and **validates** the certificate, then **transcodes** it into a compact molecule the CKB
script re-verifies independently. The CKB side never trusts the relayer — it re-runs the
crypto — but it parses a compact form, not the ~27 KB JSON `multi_signature`.

## Finding 2 — real Mithril BLS points decode and pair in-script

A real signer **`mvk` (compressed G2, 96 bytes)** was fetched from the preview aggregator and
embedded in a CKB script (`spike/mithril-real-point/mithril_real_bench.rs`). On CKB-VM:

```
G2Affine::from_compressed(real mvk)  -> Some (decode SUCCEEDS in-script)
N=1  (decode + 1 pairing): 51,432,895 cycles
N=11 (decode + 11 pairings): 469,517,345 cycles
  => real-point pairing      ~= 41,808,445 cycles   (matches the synthetic 42.7M)
  => G2 decompress + checks   ~= 9.6M cycles (one-time)
```

So **real Mithril BLS keys are byte-compatible** with the pure-Rust `bls12_381` crate
(standard ZCash/IETF compressed encoding; first byte `0x89` carries the compression flag),
and they pair at the same cost as synthetic points. The encoding-interop risk is retired.

## Real preview certificate structure (grounds the relayer transcode)

From `aggregator.testing-preview.api.mithril.network`:

| Field | Value / size | Note |
|---|---|---|
| protocol params | `k=1944, m=16948, phi_f=0.2` | same as mainnet |
| `cardano_transactions_signing_config` | `security_parameter=0, step=15` | preview **does** certify Cardano transactions |
| `signed_message` | 32 bytes | the message the STM multi-sig covers |
| `aggregate_verification_key` | ~202 bytes | the avk (Merkle batch commitment + total stake) |
| `multi_signature` (StmAggrSig) | **~27 KB** (serde_json, byte arrays) | 1944 winning indices + distinct signers' sigs + batch-Merkle proof |
| `verification_key` | `{"vk":[G2 96B], "pop":{…}}` | JSON-wrapped, not raw blst bytes |
| current signers (preview) | 3 | distinct winning signers ≤ pools |

This refines the cost model from `FEASIBILITY.md`: the heavy G1 work scales with the number
of **distinct winning signers** (≤ #pools), **not** with `k`; `k=1944` only contributes cheap
per-index eligibility hashes. So the earlier "2 pairings + k G1-adds ≈ 134M cycles" is a
**conservative upper bound** — the realistic figure is lower.

## Updated verdict

| Sub-question | Verdict | Change from Phase 1 |
|---|---|---|
| (a) granularity | 🟢 GREEN | preview confirmed to sign Cardano transactions (`step=15`) |
| (b) freshness | 🟡 YELLOW | unchanged (latency-bound; improving) |
| (c) cost | 🟢 GREEN | strengthened: real points verified in-script; cost ≤ conservative 134M model |
| toolchain | ⚠️ KNOWN | `mithril-stm` unusable on CKB ⇒ pure-Rust reimpl over `bls12_381` (relayer transcodes the cert) |

## Remaining before merge to `main` (Phase 2 — real implementation)

1. **Implement the STM aggregate-verify over `bls12_381`** (no blst): parse the transcoded
   `StmAggrSig` (winning indices + per-signer sigs + batch-Merkle paths + avk), check
   eligibility for the `k` indices, verify the aggregate BLS signature against the summed
   winning keys, and verify the batched Merkle membership against the avk. Run it against a
   **real preview certificate** end-to-end and read back the true cycle count.
2. **Define the relayer transcode** (cert JSON → compact molecule) and the CKB-side parser.
3. **Confirm the tx-membership proof** binds to a specific anchor-UTxO spend (close the (a)
   protocol-glue caveat).
4. Track Mithril low-latency tx certification (#1701) for (b).

None changes the GO; they turn the proven primitives into a working verifier.

## Sources
- Preview aggregator: `aggregator.testing-preview.api.mithril.network/aggregator`
  (`/epoch-settings`, `/certificates`, `/certificate/{hash}`).
- `mithril-stm` v0.10.5 dep tree (blst/rayon/std) — scratch cross-compile to
  `riscv64imac-unknown-none-elf` fails with `can't find crate for std`.
- Real-point measurement: `spike/mithril-real-point/` (this branch).
