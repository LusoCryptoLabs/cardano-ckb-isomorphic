# Chiral — path to production

Living tracker for taking Chiral from research prototype to a value-safe, mainnet protocol.
Companion to `CHIRAL_READINESS.md` (gap map) and `SECURITY_AUDIT.md` (findings).

## Governing constraint (locked)
**No mainnet value until BOTH an independent third-party audit and a real (or universal) trusted
setup land.** Until then: harden, freeze, prepare. Mainnet contracts may be deployed for staging,
but they hold zero value. Rationale: the verdict is "research-grade, not value-safe"; the original
code's central no-unbacked-mint guarantee did not hold as written (8 Criticals found+fixed). Pre-gate
value is the canonical way bridges lose money.

## Locked decisions
| # | Decision | Choice | Rationale | Gate |
|---|---|---|---|---|
| D-1 | Mainnet posture (now) | Harden + prep, **no value** | Responsible path; gates not yet met | — |
| D-2 | Forward-leg setup | **Target universal-SRS PLONK/KZG** (fallback Groth16 + real ceremony) | Escapes the per-circuit-ceremony treadmill; reusable across circuit revisions; thesis-consistent. Fully-transparent STARK-in-Plutus is the further endgame, infeasible in budget for v1. | **S1** budget spike |
| D-3 | Seal model | **Target per-outpoint membership (D2-A)** (fallback per-leap-tx, documented) | Strictly more rigorous: proves the specific anchor cell was consumed, not just block inclusion. | **S2** circuit-cost spike |
| D-4 | Light-client governance | **Recommend immutable (no upgrade key)** — TBC | An upgrade key is a governor in the safety path, the exact thing the design exists to avoid. If kept, document loudly. | decision |

## Gating spikes (must complete BEFORE circuit freeze + ceremony)
- **S1 — PLONK/KZG verifier in Plutus, budget check.** Implement a minimal PLONK (or Halo2-KZG)
  verifier in Aiken over the BLS12-381 builtins; measure CPU/mem vs a tx budget (Groth16 baseline:
  22.7% CPU). PASS => adopt PLONK; FAIL => Groth16 + real ceremony.
  - **SRS finding (2026-06):** the largest battle-tested public BLS12-381 SRS is Ethereum's KZG
    ceremony (~95k contributors) but it only reaches 2^12-2^15 — far below our needs. A BLS12-381
    Powers-of-Tau to ~2^21 (~2.1M) exists but is less battle-tested and is *just under* the current
    ~2.7M-constraint circuit. So S1 also owns: (a) measure the real constraint count and try to get it
    <= 2^21 so the existing BLS12-381 SRS suffices; (b) validate that SRS's provenance/reusability;
    else (c) scope running a large universal PoT (reusable forever, unlike a per-circuit Groth16 run).
- **S2 — in-circuit outpoint/molecule membership, cost.** Prototype the CKB-tx molecule parse +
  outpoint-membership gadget; measure constraint growth and proving time/RAM. ACCEPTABLE => adopt
  D2-A; else keep per-leap-tx with rationale.

## Spike results (2026-06) — measured, see `spike/ckb-to-cardano/circuit/CIRCUIT_SIZING.md`
- **S1 (sizing) — RESOLVED.** Real R1CS = **1.29 M (demo, 2-merge MMR)**; **~4.9–6.3 M at production
  MMR depth (~25–34) → a 2²³ proving domain** (per-merge ≈ 155 K; MMR membership is ~75–80 % of it).
  The docs' "~2.7 M" understates it. **No public BLS12-381 SRS exists at 2²³**, so a custom 2²³
  universal Powers-of-Tau is required for *either* Groth16 or PLONK — PLONK's "ride a public ceremony"
  perk does not apply at this size; its real benefit is reuse across circuit revisions.
  **Action:** the dominant lever is **circuit reduction** — move MMR membership out of the per-leap
  proof into the amortized `AdvanceCKBCert` / a recursion step (`spike/pq-recursion`) so the per-leap
  circuit drops ~4–5× toward 2²⁰–2²¹. Decide this **before** the freeze; it changes the SRS tier and
  prover cost more than the Groth16-vs-PLONK choice does.
- **S2 (D2-A) — RESOLVED: adopt.** Per-outpoint membership adds only ~0.4–0.5 M constraints (one
  full-tx blake2b + molecule parse), which does not change the 2²³ tier — essentially free relative to
  the MMR cost. Adopt it as the rigorous seal model (more headroom still if the circuit is restructured
  per S1).

## Critical path
```
Phase 0  Freeze + finish in-scope engineering        [me]      weeks
   - close residuals: D5 (in-circuit DAA conformance), forward-leg redeploy + seal-nullifier genesis
   - run S1, S2  -> finalize circuit + setup choice (D-2, D-3)
   - reproducible builds for CKB scripts, Aiken validators, circuit
   - freeze BINDING_SPEC + THREAT_MODEL; reconcile doc inconsistencies (e.g. ceremony wording)
   - assemble the audit-readiness package
Phase 1  Independent security work                    [external + me prep]   2-4 months
   - ZK circuit soundness review (specialist; completeness != soundness)  -> audit circuit FIRST
   - pairing/BLS + Mithril review
   - CBOR/molecule parser + CKB-script + Aiken-validator audit (where the Criticals lived)
   - public testnet soak + bug bounty
Phase 2  Trusted setup                                [external + me tooling]   weeks
   - universal SRS sourced/run (PLONK)  OR  real >=3-party Phase-2 (Groth16 fallback), on FROZEN circuit
Phase 3  Mainnet bring-up                             [me + decisions]    weeks
   - genesis checkpoints (first Mithril VK on CKB; first CKB chain-root on Cardano)
   - immutability vs upgradability (D-4); mainnet params (finality depths, cadence, min-capacity, fees)
Phase 4  Production ops & liveness                    [me]   concurrent
   - hosted+monitored relayer daemon (liveness SLAs); reliable forward-leg proving infra
   - deploy-key custody discipline (HSM/escrow); reorg + cert-latency watchtowers
Phase 5  Ecosystem                                    [external]   gates usage, not safety
   - liquidity, wallet integration, DEX listing, CIP-68 / xUDT representations
```

## Owner split
- **Drivable here:** all of Phase 0; S1/S2; audit-readiness package; ceremony tooling + dry-run;
  ops/relayer/proving hardening; Phase 3 mechanics.
- **Requires you / external:** engaging an audit firm (budget), recruiting ceremony participants or
  sourcing a universal SRS, the mainnet-value go/no-go, liquidity/ecosystem.

## Sequencing note
S1 and S2 change the circuit; the circuit must be frozen before the ceremony (ceremony is per-circuit
for Groth16; for PLONK the universal SRS is reusable but the verifier+circuit still freeze for audit).
Audit the circuit design+code FIRST, fix, re-freeze, THEN setup — so audit findings don't force a
re-setup.
