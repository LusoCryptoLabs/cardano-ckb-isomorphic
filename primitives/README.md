# Reused primitives (lifted from `cardano-ckb-bridge`)

Self-contained, proven building blocks copied verbatim from the sibling repo. See
`../docs/PRIMITIVES.md` for provenance and the full reuse manifest (including the larger
toolchain dirs to lift at implementation time).

**These are the original reference copies, lifted as-is** - they don't build standalone here.
They were the starting material; the realized, built-and-tested versions now live in `../spike/`
(the Mithril BLS verifier generalizes the `mldsa.rs` in-script-verify pattern; the binding/Conway
logic is in `../spike/phase1/`). Kept for provenance and as reference patterns. See
`../docs/CHIRAL_STATUS.md` for what shipped.

- `ckb/mldsa.rs` - in-script signature verification in CKB RISC-V (ML-DSA-44). The template
  for the Mithril/BLS verifier in the Cardano light-client cell.
- `ckb/smt_replay.rs` - O(1) Sparse-Merkle-Tree replay accumulator for CKB scripts.
- `cardano/replay_smt_tests.ak` - Aiken MPF replay-root verification (absence + insertion).
- `cardano/mpf-proof.mjs` - off-chain Merkle-Patricia-Forestry proof helper.
