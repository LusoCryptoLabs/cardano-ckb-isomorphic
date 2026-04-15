# Roadmap

Phased, each phase ending in something runnable/measurable. The risky long poles
(in-script BLS budget; Mithril cert format) are pulled forward as spikes so they fail fast.

> **Status (2026-06): Phases 0–4 are DONE and proven live on testnets; Phase 5 (audit + mainnet)
> is the external remainder.** This roadmap is the original plan; the achieved state is in
> `BUILD_PLAN.md`, `LIVE_STATUS.md`, `CHIRAL_STATUS.md`, and `CHIRAL_READINESS.md`. Phase markers
> below are annotated with where each landed. (The risky long poles failed-fast green: in-script
> BLS budget ~4–5% of a block; Mithril cert format reproduced bit-for-bit.)

## Phase 0 — Toolchain + primitives wired (foundation) ✅ DONE
- Stand up fresh CKB script workspace (RISC-V target, the sibling's size-tuned profile) and
  an Aiken project. Wire in the copied primitives (`primitives/`) so they build + test.
- Port the SMT replay accumulator and an MPF/Aiken test as smoke tests.
- **Done when:** `mldsa.rs` + `smt_replay.rs` compile to a RISC-V binary and the Aiken
  replay test passes — proving the build path, not new logic.

## Phase 1 — Spike: Mithril verification in a CKB script (the load-bearing risk) ✅ DONE — LIVE
- Obtain a real Mithril certificate from a Cardano testnet (preview) Mithril aggregator.
- Implement a **BLS12-381** threshold/aggregate signature verify in CKB RISC-V (use
  `mldsa.rs` as the in-script-verify template) over the certificate message.
- **Measure cycles** against the VM limit. Baseline: ML-DSA-44 ≈ 4.39M cycles.
- **Done when:** a CKB script verifies a real Mithril cert within budget (or we have hard
  numbers proving we need the ZK path instead). This decides §5.1/§5.3 in `DESIGN.md`.

## Phase 2 — Cardano light-client cell ✅ DONE — LIVE (`AdvanceCert`/`TxSetCert` on Pudge)
- A CKB cell that holds the current certified Cardano root + stake-key set, and advances it
  by consuming a newer Mithril cert (epoch rotation handled).
- Inclusion-proof checker: "this Cardano UTxO / spend is in the certified snapshot."
- **Done when:** a light-client cell tracks preview's Mithril snapshots and can prove a
  chosen UTxO's presence, on a CKB devnet.

## Phase 3 — Binding lock + bound cell (the isomorphic core) ✅ DONE — LIVE (leap-in `0x0318d35f`)
- Cardano **binding lock** (Plutus): holds anchored value, datum carries the commitment,
  enforces commitment format + binding invariant.
- CKB **bound cell** transition script: checks `commitment == hash(new state ‖ metadata)`
  and that the anchor spend is final via the Phase-2 light-client cell; replay-guarded.
- **Done when:** leap-in works on testnet — lock value on preview with a commitment →
  Mithril-certified → bound cell live on CKB Pudge.

## Phase 4 — Leap-out + transfers ✅ DONE — LIVE (transition `0x94d0620f`, leap-out finalize `0x795f4bb9`)
- CKB final state authorizes the anchor spend on Cardano (no CKB light client on Cardano —
  formalize the invariant from `DESIGN.md §5.5`).
- CKB-internal transfers of the bound asset; settlement model for throughput.
- **Done when:** a full round-trip (Cardano → CKB → transfer on CKB → back to Cardano)
  runs on testnets, mirroring the sibling's round-trip proof.

## Phase 5 — Hardening + the trustless upgrade path 🟡 PARTIAL (hardening done; audit + mainnet external)
> Hardening landed (`HARDENING.md`, the CI difftest/drift gate). The ZK-of-Praos drop-in is
> prototyped as the SP1 STARK-Mithril proof (`spike/cardano-to-ckb-zk/`, all four relations
> composed). Audit + mainnet remain external (`CHIRAL_READINESS.md`).
- Reorg/finality analysis both chains; adversarial tests (forged cert, stale snapshot,
  replay, equivocation).
- Define the **ZK-of-Praos** drop-in behind the same light-client-cell interface, so the
  trust assumption can be upgraded from stake-threshold (Mithril) to fully trustless without
  reworking the binding.

## Cross-cutting
- The comparison vs `cardano-ckb-bridge` (trust, asset semantics, latency, throughput, cost) lives
  in `COSTS.md` (the "Versus the committee bridge" table) — the artifact for "decide later which
  bridge is better." Trust axis: bonded committee + governor vs. Mithril stake-threshold / Groth16
  soundness, no humans in the safety path.
