# D5 — in-circuit DAA / epoch-schedule conformance (scope, RFC-0020-grounded)

The last circuit-affecting item before freeze (`PRODUCTION_PLAN.md`, `AUDIT_SCOPE.md` D5). **Scope only —
not yet implemented**: CKB's difficulty-adjustment algorithm is intricate consensus logic where a wrong
constant/clamp is a Critical, so it needs a fresh, spec-driven build + differential testing, not a rushed
pass. Documented here so it can be implemented and reviewed against the exact spec.

## What's enforced today vs the gap
`advance_prove` (`difficulty_gadget::difficulty_verify`) enforces `diff == floor((2²⁵⁶−1)/target)` and sums
cumulative work — so **economic security holds** (heaviest-chain via real work). What is *not* enforced:
that a header's `compact_target` is the value CKB's **DAA** dictates for its epoch. D5 closes that
schedule-conformance gap.

## CKB DAA (RFC 0020) — constants + formulas to implement
- Constants: ideal orphan rate `o_ideal = 2.5%`; ideal epoch duration `L_ideal = 4h`; dampening factors
  `τ₁ = τ₂ = 2`; epoch-length bounds `C_m^min = 300`, `C_m^max = 1800` blocks. `HSpace = 2²⁵⁶`.
- Per last epoch `i`: actual duration `L_i`, main-chain blocks `C_{i,m}`, uncle/orphan blocks `C_{i,o}`,
  target `T_i`, orphan rate `o_i = C_{i,o}/C_{i,m}`.
- **Hash-rate estimate (Eq.4):** `Ĥ_i = (HSpace/T_i)·(C_{i,m}+C_{i,o})/L_i`, then **dampened** to
  `[Ĥ_{i-1}/τ₁, Ĥ_{i-1}·τ₁]`.
- **Next block count (Eq.8-9):** `C'_{i+1,m} = o_ideal(1+o_i)·L_ideal·C_{i,m} / (o_i(1+o_ideal)·L_i)`,
  clamped to `[300,1800]` and τ₂-bounded vs `C_{i,m}`.
- **Next target (Eq.10):** `T_{i+1} = HSpace / (Ĥ_i·L_ideal/((1+o'_{i+1})·C_{i+1,m}))`, with `o'_{i+1}`
  the bound-adjusted orphan rate.

## What the circuit must add
1. **Carry epoch-boundary witnesses** in the advance: last epoch `(T_i, C_{i,m}, C_{i,o}, L_i)` and
   `Ĥ_{i-1}` (for the τ₁ clamp). The header already exposes `number`, `epoch` (`raw[16..24]`, `raw[24..32]`).
2. **Within-epoch constancy:** every header in epoch `i` must carry exactly `T_i` (cheap equality).
3. **Epoch-boundary recompute:** at the first block of epoch `i+1`, recompute `Ĥ_i → dampen →
   C_{i+1,m} (clamp+bound) → T_{i+1}` and enforce the header's decoded target equals `T_{i+1}`.
4. **Arithmetic gadgets:** 256-bit multiply/add exist (`mul256`, `add256`); D5 additionally needs a
   **floor-division / ratio gadget** (witness-and-verify `q,r` with `q·d + r = n`, `r < d`) and the
   clamp comparisons. The two divisions (Ĥ and the Eq.8/Eq.10 ratios) dominate the added constraints.
   Rough order: ~a few hundred K constraints (well within the 2²¹ budget headroom after the restructure).

## Hard requirements (non-negotiable)
- **Differential test against CKB's reference** (`ckb`'s `EpochExt`/`next_epoch_ext`) on real preview AND
  mainnet epoch transitions — the formula has edge cases (the `o'` bound-adjustment, the τ clamps, the
  300/1800 limits) that only a reference cross-check will catch. This is how every other gadget here was
  validated; D5 must meet the same bar.
- **All-or-nothing:** a *partial* DAA check (e.g. only the τ clamp, not the full recompute) gives **false
  assurance** — it would look enforced while still admitting non-conforming targets. Implement the full
  Eq.4/8/9/10 chain or leave it explicitly unenforced (as today, with economic security noted).

## Recommendation
Implement D5 as a dedicated, spec-driven build with the differential test, **after** the restructure
freeze decision — OR, if launch timing is tight, **document it as a known, scoped residual** (economic
security holds; schedule-conformance deferred) and let the third-party audit weigh it. Do **not** ship a
partial DAA. This scope + the exact RFC formula above is the spec to build against.

## DECISION (2026-06): ACCEPTED AS A DOCUMENTED RESIDUAL — not a freeze blocker.
Rationale: the heaviest-chain rule already binds each header's *work* to its *actual* target
(`difficulty_verify`) and sums it, so a chain built on non-conforming (e.g. artificially easy) targets has
**less cumulative work and loses** the comparison — an attacker gains nothing from a wrong target without
real PoW behind it. D5 is therefore exact consensus-rule conformance, **not** a safety property, and
deferring it does not weaken the value-safety argument. It is carried as a known residual for the
third-party audit to weigh, and the full RFC-0020 implementation above (with its differential test) is an
**optional post-audit hardening**, runnable in parallel with the external gates. It does **not** block the
circuit freeze.
