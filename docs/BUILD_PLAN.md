# Build plan — from proven PoC to a production isomorphic-binding bridge

> You've chosen to build this. This is the ordered path from where we are (mechanism proven +
> a full live lifecycle on testnets) to a shippable bridge. Each item marks: ✅ done/de-risked,
> 🔧 engineering (clear, no unknowns), 🔬 research (bounded but open), 🌐 external (not code).

## Where you're starting (already done — don't redo)
- ✅ Full Mithril **certificate verify** in CKB-VM (BLS aggregate + stake lottery + Merkle) — real data.
- ✅ **Cross-chain tx oracle** (`cardano_tx_is_certified` via MKMapProof) — real data.
- ✅ **Conway tx parsing** in-script (seal detect + commitment).
- ✅ **Binding lock + seal NFT** (Aiken, tested) — all 3 paths (mint/Transfer/Unbind) **ran live**.
- ✅ **Live lifecycle on testnets**: leap-in → CKB bind, transfer → CKB transition, leap-out — real
  Mithril certs, verified in-script on the live Pudge node. (`deployed/`.)

The crypto and the mechanism are **not** the risk anymore. The risk is now productionization.

## Phase 1 — The unified, witness-driven verifier  ✅ DONE (the keystone) — proven in CKB-VM AND live on Pudge
> Live: ONE verifier deployed (`0x42f74fbc…`, tx `0xf8644bd3…`); genesis bound cell `0x0318d35f…`
> (block 21,339,914); **transition** `0x94d0620f…` (block 21,339,956) **consumed** the genesis cell
> and created v2, proof-in-witness, root from a checkpoint cell. See `deployed/pudge/unified-instance.json`.

Build **one** `BoundAsset` script that reads the proof from the **witness** (not embedded), deployed
**once** and referenced by every bound cell. It must fold together, in one entrypoint:
`cardano_tx_is_certified(tx)` (cert verify → certified root, chained to the light-client cell) +
MKMapProof membership + Conway parse + commitment binding + the genesis/transition/finalize modes.
- **Why first:** this is what makes per-transfer cost ~0.05 CKB and kills the "45k per step" demo
  artifact. Every sub-piece is already proven in CKB-VM; this is **assembly + a molecule schema for
  the witness**. No unknowns.
- Also: the **light-client checkpoint cell** (AdvanceCert) as a real type-id cell that advances per
  epoch from witness-supplied certs.
- Reconcile the two small design points: commitment = `blake2b256(next_state)` (seal identified
  structurally, no self-reference); CKB extracts the `commitment` field from `SealDatum`.

## Phase 2 — Lottery cost: the SNARK-lottery target  ✅ DONE (measured + exact)
The naive per-index lottery was ~68% of a block (the boundary-verify optimization is *worse* — we
measured it). Replaced with mithril's verifiable target (`compute_target_value_for_snark_lottery`):
per-party target derived ONCE via a fixed-point integer Taylor for `(1-φf)^w` (scale 2^768, no
num-rational/gcd — that's what blew the budget), then `ev < T` per index (a 512-bit integer compare).
**Measured on CKB-VM (same harness):** eligibility **2,368M → 39.7M cycles (59.6×)**; full AdvanceCert
**~70% → ~5% of a block**. **Exact:** `(ev<T) == is_lottery_won(ev)` on all 2330 real preview indices
(0 disagreements). See `spike/phase2/` (target, naive baseline, host differential test) and
`spike/light-client-cell/light_client_advance.rs` (folded in).

## Phase 3 — Relayer + flows  ✅ DONE
- A **permissionless relayer** (`relayer/`): watch binding-lock spends, wait for the Mithril cert,
  fetch cert + MKMapProof + tx CBOR, transcode to the compact witness, classify TRANSITION vs
  FINALIZE, submit. **Liveness only — cannot forge.** Transcode **validated byte-for-byte** against
  the on-chain-accepted live transition witness; full pipeline exercised on real preview data.
- **CKB finalize of leap-out** (the symmetric leg): added a FINALIZE mode to the unified BoundAsset
  (consume cell, no output, certified Unbind consumed the seal + did NOT recreate it at the lock).
  **Proven in CKB-VM on the real certified Unbind** (`6c729ea6`, 205,581 cycles). **Closed LIVE on
  Pudge:** the finalize spend `0x795f4bb9` (block 21,358,183) ran on the live node, consumed the
  bound cell, and produced only plain cells — the asset is unbound. (The earlier finalize-capable
  deploy `0xbeaff4d3`/`0xc40d4a39` was gas-dust-blocked and superseded; the closure used a fresh
  faucet-funded key per the committed `close-leapout-fresh.mjs`.) See `relayer/`, `spike/phase3/`,
  `LIVE_STATUS.md`.

## Phase 4 — Hardening + correctness  ✅ DONE (gate built + in CI)
- **Differential / tamper gate** (`spike/phase4/difftest`, in CI): the exact in-script verifier run
  on a real preview-cert fixture — **accepts** the genuine cert (and our compute_hash == mithril's
  own `signed_message`), **rejects** every single-component tamper (sigma/mvk/message/avk-root/
  message-part/Merkle-leaf/stake). 11/11. Plus a **live drift watch** that already caught mithril
  evolving the message-part set while our generic construction still matched.
- **Reorg/finality, Mithril liveness/latency, replay/monotonicity invariants, verifier size** —
  analyzed in `docs/HARDENING.md` (the bridge only acts on Mithril-certified *immutable* history, so
  tip reorgs are invisible; relayer is permissionless + cannot forge; sizes measured + shrink levers).

## Phase 5 — Audit + mainnet  🌐
- **Security audit** — mandatory. This is novel crypto-in-script (BLS/STM/MMR reimplemented over
  `bls12_381`); the lottery + MKMapProof + Conway parser all need review.
- Mainnet Mithril + CKB mainnet; **genesis checkpoint** selection (a social root, as for all Mithril
  clients); ops/monitoring; the real bond/parameter choices.

## Dependencies & risks to watch
- **Mithril roadmap**: low-latency tx certification (#1701) directly improves bridge UX.
- **Certification latency** is inherent (we lived it: minutes per leg) — design for settlement-style
  UX, not instant.
- **Trust assumption** is Mithril honest-stake-majority; the trustless endgame swaps it for a
  ZK-of-Praos proof behind the same `cardano_tx_is_certified` interface (long-term).

## The first concrete milestone ✅ ACHIEVED
**Phase 1's unified witness-driven `BoundAsset` + a real on-chain transfer that consumes the old
bound cell and creates the new one** (not create-only), referencing one deployed script with the
proof in the witness — **done live on Pudge** (transition `0x94d0620f…`, block 21,339,956, consumed
genesis `0x0318d35f…`). The live demo is the real per-transfer model.

## Where it stands now
Phases 1–4 are done and live (see the ✅ markers above); the full lifecycle — leap-in → transition →
leap-out finalize — ran on preview↔Pudge, and the mirror CKB→Cardano Groth16 leg ran a full round
trip. The work is preserved in this repo (`github.com/tecmeup123/cardano-ckb-isomorphic`). What's
left is Phase 5 + the external items (mainnet, audit, liquidity, a hosted relayer daemon) catalogued
in `CHIRAL_READINESS.md`.
