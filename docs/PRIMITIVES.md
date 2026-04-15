# Primitives — what's reused from `cardano-ckb-bridge`, and what to lift later

> **Status (2026-06):** this was the seed manifest. The reuse approach paid off — the isomorphic
> binding was built and run live using the sibling's CKB RISC-V build profile (`opt-level="z"` +
> LTO + strip) and `ckb-testtool` harness pattern, with the in-script-verify shape from `mldsa.rs`
> generalized to the Mithril BLS verifier. The `primitives/` files below remain as the original
> reference copies; the realized, built versions live in `spike/` (e.g. the verifier in
> `spike/mithril-verify/` + `spike/light-client-cell/`, the Conway parser + `BoundAsset` in
> `spike/phase1/`). See `CHIRAL_STATUS.md`/`LIVE_STATUS.md` for what shipped.

This repo was seeded with the **reuse-the-primitives, fresh-design** approach: carry over
the proven, self-contained building blocks; drop everything specific to the bonded-committee
lock-and-mint architecture; design the isomorphic-binding logic clean.

The two repos are siblings under the same owner, so provenance is given as paths in
`cardano-ckb-bridge`. Anything not copied here should be lifted from there at implementation
time rather than rewritten.

## Copied into this repo (self-contained source)

| Path here | From `cardano-ckb-bridge` | Why it's reusable |
|---|---|---|
| `primitives/ckb/mldsa.rs` | `ckb/scripts/src/mldsa.rs` | In-script signature verification in CKB RISC-V (ML-DSA-44, ~4.39M cycles). **The template** for the Mithril/BLS verifier in the Cardano light-client cell — same shape: parse, verify, fail-closed. |
| `primitives/ckb/smt_replay.rs` | `ckb/scripts/src/smt_replay.rs` | O(1) replay accumulator (Sparse Merkle Tree) for CKB scripts. Prevents re-processing the same anchor spend. Reused verbatim. |
| `primitives/cardano/replay_smt_tests.ak` | `lib/bridge/replay_smt_tests.ak` | Aiken verification of an MPF replay root (absence + insertion). Useful if the binding lock co-validates commitments on the Cardano side. |
| `primitives/cardano/mpf-proof.mjs` | `scripts/mpf-proof.mjs` | Off-chain Merkle-Patricia-Forestry proof helper (same `@aiken-lang/merkle-patricia-forestry` lib the on-chain verifier is proven against). Reused for Cardano-side inclusion proofs. |

> These are **lifted as-is**. They do **not** yet build as a standalone project — wiring
> them into fresh Cargo/Aiken projects is **Task 0** in `ROADMAP.md`. The bench/`no_std`
> attributes and module paths assume the sibling's workspace.

## Lift later (don't rewrite — pull from the sibling at implementation time)

| Component | From `cardano-ckb-bridge` | Notes |
|---|---|---|
| CKB script workspace + RISC-V target config | `ckb/scripts/`, `ckb/Cargo.*`, target `riscv64imac-unknown-none-elf`, `opt-level="z"` + strip profile | The proven build profile (binaries fit capacity). Reuse the Cargo skeleton, drop `bridge_lock`/`challenge`/`committee_*` modules. |
| CKB VM test harness | `ckb/tests-vm/` (source only — exclude `target/`, `*.bin`) | `ckb-testtool` harness; adapt for binding-cell + light-client-cell tests. |
| Molecule schema tooling | `ckb/schemas/` (`bridge.mol` → `generated.rs` via moleculec 0.7.5) | Define new molecule tables (BindingCommitment, MithrilCert, AnchorSpendProof). |
| blake2b shim / SMT proof helper | `ckb/blake2b-rs-shim/`, `ckb/smt-proof-helper/` (source only) | Host-side helpers for the replay accumulator. |
| Aiken project skeleton | `aiken.toml`, `aiken.lock`, `lib/bridge/types.ak` (trim to the few reusable types) | For the binding lock validator + co-validation. |
| Docker build wrappers | `docker-build.sh`, `docker-aiken.sh` | Reproducible CKB/Aiken builds without host toolchain drift. |

## Explicitly NOT carried over (not in the isomorphic-binding trust path)

- Lock-and-mint value flow: `ckb/scripts/src/bridge_lock.rs` (mint/release), `validators/wckb_mint.ak`, `validators/cardano_lock.ak`.
- Bonded committee: `lib/bridge/{election,registry,auth}.ak`, `ckb/scripts/src/committee_registry.rs`, `ckb/election/`, `validators/committee_registry.ak`, `sim/` (committee/economics/election models).
- Optimistic challenge machinery: `validators/challenge.ak`, `ckb/scripts/src/challenge.rs`, `validators/bridge_state.ak`, `validators/state_nft.ak`.
- Operators / app: `bridge-app/`, `cardano-scripts/`, `ckb-sidecar/`, `deployed/`.

If a comparison later shows part of the optimistic machinery is worth keeping as a
*fallback* path alongside the light client, it can be pulled back in — but the default is a
clean slate.
