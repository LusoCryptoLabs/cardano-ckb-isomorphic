# CKB→Cardano leg: value-binding fix — design

**Goal.** Close the confirmed critical soundness gap (audit INFL-1/VERIF-1/DATUM-2): the leap circuit
witnesses `new_state = amount(16 LE) ‖ recipient(28)` as a **free witness** and never decodes the locked
capacity from the proven CKB tx, so a relayer can lock 1 CKB and mint arbitrary unbacked χCKB to any
recipient. This doc specifies the fix so the minted `(amount, recipient)` is provably equal to value
genuinely locked-for-bridging on CKB.

## 0. Where the gap is (precise)

- `circuit/prover/src/bin/leap_windowed.rs:102` — `new_state` is `UInt8::new_witness` (free).
- `:104` — `seal == leaf` binds the **tx hash** only; `leaf` is itself a witnessed CBMT leaf (`:85`), proven
  under the header's `transactions_root` (`:89-90`). **The tx body is never hashed in-circuit.**
- `:105-106` — `commitment = blake2b256(new_state ‖ seal)`; `new_state` unconstrained ⇒ commitment is an
  unconstrained value the Plutus guard then faithfully honours.
- `relayer/ckb_lock.py:29` — the demo even commits `ckbhash("ckb->cardano leap" ‖ seal)` (no amount/recipient
  at all), and `relay_prove.rs` hardcodes a *different* `new_state`. Nothing connects lock → mint.
- `groth16/validators/leap_mint_guard.ak:131-134` + `leap_guard.ak:16-24` — `minted == fact.amount`,
  `minted_to_recipient == fact.amount`, with `amount/recipient` sliced from `state`. **On-chain guards are
  correct; they validate an unconstrained value.** No Plutus change is needed for soundness.

## 1. Trust chain the fix must establish

> The Cardano mint of `amount` χCKB to `recipient` is sound **iff** a CKB transaction, **confirmed**
> (PoW + depth `K`, already proven by R1–R3), **ran the bridge script** and **locked exactly `amount`
> for `recipient`**, and that fact is bound into what the circuit exposes.

Two new in-circuit bindings are required (everything else is unchanged):

1. **Body authenticity** — bring the full `RawTransaction` body into the circuit, `ckbhash` it, and enforce
   it equals `seal` (the proven-confirmed tx hash, already public input #2). This is the *only* way the real
   outputs enter the circuit.
2. **Value extraction** — from that authenticated body, locate the **bridge output** (its type-script hash
   `== BRIDGE_TYPE`, a circuit constant), read its **capacity** (`= amount`) and its **recipient** (from
   cell data), and enforce `new_state.amount == capacity` and `new_state.recipient == recipient`.

The expensive, error-prone surface is #2 (in-circuit molecule access). We minimize it by pushing all
value-*correctness* to a cheap, auditable CKB type script and giving the circuit a **canonical** layout to
read.

## 2. The canonical bridge RECEIPT (CKB side) — BUILT + adversarially tested ✅

`bridge_lock_v1` (the CKB **type script** on a **RECEIPT cell**) makes a confirmed lock tx self-certifying.
A cell can carry only one type script, so for **xUDT** the bridge can't *be* the token's type — instead the
lock tx creates a separate receipt cell that *records the bridging intent* and ties it to the actually-locked
value (the **both/configurable** model). The receipt is the canonical blob the circuit reads:

```
RECEIPT cell:
  type = bridge_lock_v1  (args = bridge instance id; for kind=xUDT, args = the pinned xUDT type hash)
  data = MAGIC(4)="BRG1" ‖ kind(1) ‖ amount(16 LE) ‖ recipient(28)          # fixed 49-byte layout
  lock = a release lock (spendable only by the burn→unlock proof; see §6)
bridge_lock_v1 enforces on CREATE (receipt in GroupOutput):
  - data.len == 49 && data[0..4] == "BRG1" && amount != 0
  - exactly ONE receipt of this type in outputs, none in inputs (no create+consume mixing)
  - kind == 0 (CKB):  the receipt cell's own capacity == amount   (the locked CKB is the receipt capacity)
  - kind == 1 (xUDT): exactly one sibling OUTPUT with type-hash == args holds amount in data[0..16] LE
CONSUME path (receipt in GroupInput, no output) = the burn→unlock return trip; allowed here, the release
LOCK gates it on a Mithril-proven Cardano burn (§6).
Tests: spike/dex-integration/relayer/validation/v2vmtest/tests/bridge_lock.rs (8/8: CKB+xUDT accept; bad
magic/len/amount=0/capacity≠amount/two-receipts/xUDT-mismatch all rejected). Binary in burn-gated-unlock.
```

`recipient` is the 28-byte Cardano payment credential (opaque to CKB; the circuit binds it). `seal` = this
lock tx's own hash (unique, single-use; the Cardano side nullifies it — §5). The circuit reads `amount` and
`recipient` directly from the receipt's fixed 49-byte data; we keep `commitment = blake2b256(new_state ‖
seal)` as the circuit's public input #3 purely to preserve the existing Plutus interface, now over a
*constrained* `new_state`.

**Why a receipt type script:** it runs when the lock tx is included in a CKB block, so **any confirmed bridge
tx already satisfies the binding** — the circuit only has to prove the tx is confirmed and *carries* this
type at the canonical offset, not re-derive value correctness. The expensive ZK side stays minimal; the
correctness lives in this cheap, tested CKB-VM script.

## 3. Circuit changes (`leap_windowed.rs`)

Add, after the existing R1–R3/R2′ and before R4:

```
// body authenticity
let body = w(&self.tx_body, &cs)?;                 // full RawTransaction bytes (new witness, var-len)
let body_hash = blake2b256(&body, b"ckb-default-hash")?;   // ckbhash
for i in 0..32 { body_hash[i].enforce_equal(&seal[i])?; }  // body IS the proven-confirmed tx

// locate the single bridge output + read its fields (canonical layout, §4)
let (cap, typehash, recip) = molecule::read_bridge_output(&body, self.bridge_off)?;
for i in 0..32 { typehash[i].enforce_equal_const(BRIDGE_TYPE[i])?; }   // it ran the bridge script

// VALUE BINDING (the fix)
for i in 0..16 { ns[i].enforce_equal(&cap[i])?; }              // new_state.amount == capacity (16 LE)
for i in 0..28 { ns[16+i].enforce_equal(&recip[i])?; }         // new_state.recipient == cell recipient
```

`ns` (=`new_state`) stops being free: its bytes are now pinned to the body. The existing
`comm = blake2b256(ns ‖ seal)` and the three `pi_*` bindings stay as-is.

**Public inputs** unchanged: `(window_root, seal, commitment, tip, k)`. `BRIDGE_TYPE` is a compile-time
constant (build-overridable per deployment, like the Mithril verifier's `CHIRAL_*`). The bridge-output
offset(s) are witnessed and *verified* by the molecule reader (§4), not trusted.

## 4. The molecule reader (the delicate gadget)

Two implementation options; recommend **(A)** for v1.

**(A) Canonical fixed-shape (simplest, smallest circuit).** `bridge_lock_v1` additionally enforces a rigid tx
template: exactly 1 input, 1 cell_dep (dep_group), 0 header_deps, the bridge output at index 0. Then within
`RawTransaction` the byte offset of `outputs[0].capacity`, its `type` script, and `outputs_data[0]` are
**constants** the circuit reads directly — no offset arithmetic in-circuit. Restriction: the locker
pre-funds a single cell of the exact capacity (a `split` tx first, as we already do on the Cardano side).
Circuit delta ≈ just the body hash + a handful of constant-offset slices.

**(B) Pointer-following (general, allows fee inputs).** The circuit reads the molecule offset table of
`RawTransaction` (6 `u32` offsets at fixed header positions) to jump to `outputs`/`outputs_data`, then the
`outputs` dynvec header to jump to `outputs[i]`, verifying the located output's type hash `== BRIDGE_TYPE`.
~3 levels of `u32` offset reads + bounds checks. More robust, ~+30–60K constraints over (A).

Either way the reader is **differential-tested vs native molecule decoding on a real Pudge lock tx** before
wiring (the §"prototype" step), exactly as every existing gadget was.

**Cost.** Body hash dominates: a canonical lock tx is small (~300–400 B ⇒ 3–4 Blake2b blocks ⇒ ~150–200K
constraints); option (A) adds little else. New circuit total ≈ 1.4–1.6M (was ~1.2M), comfortably under 2²³.
Proving time rises modestly (tens of seconds → ~a minute). On-chain Plutus verify is unchanged (constant-size
proof).

## 5. Plutus / mint (`leap_mint_guard.ak`) — no soundness change

The guard already enforces `minted_total == fact.amount`, `minted_to_recipient == fact.amount`,
`fact.amount > 0`, `seal_consumed` (nullifier), and rate-tick. With `new_state` now circuit-constrained, the
guard's `amount/recipient` (sliced from `state`) are exactly the locked values. **One width check to add:**
`amount` is 16 LE in the circuit; ensure the Plutus slice + `bytearray_to_integer` agree (they read 16 bytes
LE — matches). The seal nullifier already gives one-mint-per-lock.

## 6. The return trip (burn → unlock) — for completeness

This fix secures **export mint** (CKB lock → Cardano mint). The full native-token bridge also needs **export
redemption** (burn χCKB on Cardano → release the CKB bridge cell), which runs on the **Mithril oracle** (CKB
verifies the Cardano burn): the bridge-output `lock` (§2) is a release lock that opens only on a
`bound_asset`-style proof that the matching χCKB was burned on Cardano for that `seal`. That reuses the
already-live Mithril verifier + nullifier registry — no new circuit. (Symmetrically, **import** = Cardano lock
→ CKB mint uses Mithril, and its CKB mint must bind the Cardano-locked value, which is easy in CKB-VM since it
already parses Cardano tx bodies.) Scoped here, built after the mint binding lands.

## 7. Soundness argument (why the attack dies)

Attack today: lock 1 CKB, set `new_state.amount = 10^9`, mint 10^9 unbacked χCKB to attacker.

After the fix: `new_state.amount` is `enforce_equal` to the **capacity of a bridge-typed output in the
proven-confirmed tx**, and `bridge_lock_v1` enforced `capacity == amount` and a single bridge output. To mint
`X`, the attacker must present a confirmed CKB tx that genuinely locked `X` at the bridge under the bridge
type script — i.e., actually lock `X`. The recipient is likewise pinned to the bridge cell's declared
recipient, owner-chosen at lock time. The relayer remains pure liveness: it can stall, not inflate or
redirect.

## 7.5 Reorg & full security model (same standard as the Mithril leg)

CKB is PoW, so the bridge's headline threat is a **reorg double-spend**: lock `N`, prove the lock K-deep,
mint `N` χCKB on Cardano, then reorg CKB to orphan the lock (refund `N`) while keeping the χCKB. The value
binding makes `N` *real* (the actual locked amount), so the reorg defenses must hold to the same standard as
the Mithril leg's finality/replay guarantees. Layered:

- **L1 — per-leap depth bound (in-circuit, present).** The proven header sits at `diff = tip − height ≥ K`
  (SEC D6, `leap_windowed.rs`). The value binding *inherits* this: the receipt is read from the tx body that
  hashes to the leaf in a K-deep block, so the bound amount is K-confirmed.
- **L1b — K FLOOR, pinned (in-circuit, NEW — fixes GOV-1).** `K` is now `≥ K_MIN`, a constant baked into the
  circuit (⇒ the VK), not a witness/governance value. This is the exact analogue of the Mithril quorum pin:
  a security parameter must be pinned, not supplied. Validated: `K=0` is now **unprovable**
  (`is_satisfied=false`); `K=12,kmin=12` proves. `K_MIN` is a deployment parameter (`CHIRAL_K_MIN`, default
  12) set to CKB's settlement guarantee.
- **L2 — aggregate reorg cap (on-chain Plutus, REQUIRED — currently DISABLED).** Even a rare K-deep reorg must
  not let unbounded value be stolen: the mint guard must cap the *total* χCKB mintable within a sliding reorg
  window. The audit found it ships `cap=0`/`max_amount=0` (off) in `d6_deploy.py` (RATELIMIT-1). **Enabling +
  deriving this cap is on the critical path to value-ready** (see §8); the cap bounds worst-case reorg loss
  to a governable amount.
- **L3 — heaviest-chain + genesis pin (checkpoint advance, present).** The window root advances only on
  `new_total > old_total` from the one pinned CKB genesis (`AdvanceCKBCert` + `ckbcert_thread.ak`), so the
  circuit's "confirmed" view follows the canonical chain and a fake-genesis fork is rejected.

Beyond reorgs, the value-binding fix preserves the leg's other guarantees:
- **Replay** — the seal (lock tx hash) is nullified on Cardano (`seal_consumed`); one mint per lock.
- **Recipient binding (B1-equivalent)** — the recipient is read from the owner-chosen receipt data and bound
  in-circuit; a permissionless relayer cannot redirect the mint. Validated by the gadget's redirect-reject.
- **Type binding** — the receipt output must carry `bridge_lock_v1` (its type code hash == the pinned
  constant), so the confirmed tx provably ran the bridge script (which enforced amount==locked value).

## 8. Other audit items on this leg (separate from value binding, needed for production)

- **Reorg aggregate cap ships disabled** (`d6_deploy.py`: `cap=0`/`max_amount=0`) — re-enable + make it
  governable, not compile-time-off (RATELIMIT-1).
- **Rate-limiter genesis not address-pinned**; `rate_ticked` address-blind (RLT-1). ~~`K=0` allowed (GOV-1)~~
  **FIXED** — the K floor `K ≥ K_MIN` is pinned in-circuit (§7.5 L1b); `K=0` is now unprovable.
- **`authz` (no-mint-without-leap) and `doublemint` (replay) dimensions are UNAUDITED** (finders died on
  socket errors) — re-run those adversarial dimensions.

These don't block the value-binding fix but are on the critical path to "value-ready."

## 9. Work plan

1. **Prototype the reader (de-risk first).** In-circuit: `body → ckbhash → == seal`, then read
   `(capacity, type_hash, recipient)` at canonical offsets; differential-test vs native molecule decode on a
   **real Pudge lock tx**. Standalone, before touching the full circuit. *(≈ the riskiest 20%.)*
2. ✅ **`bridge_lock_v1` CKB type script** — DONE: enforces the §2 invariants for both kinds (CKB capacity /
   xUDT sibling) + canonical 49-byte layout + singleton; adversarial tests 8/8 in ckb-testtool
   (`bridge_lock.rs`). Binary in `burn-gated-unlock`.
3. **Wire the binding into `leap_windowed.rs`** — IN PROGRESS:
   - ✅ The value-binding GADGET is validated (`value_bind_test`, full receipt): real ACCEPT; inflate /
     recipient-redirect / non-bridge-type / tampered-body all **REJECT**. (offsets: type@246, amount@332,
     recipient@348 in the canonical template.)
   - ✅ The **K floor** (§7.5 L1b) is wired into `leap_windowed.rs` + validated: `K=0` is now `is_satisfied=false`,
     `K≥K_MIN` proves (1.23M constraints).
   - ⏳ Thread the gadget into `leap_windowed.rs`'s FULL proof (tx_body witness + the §3 constraints) and
     re-prove **end-to-end** — needs a LIVE canonical bridge-receipt lock tx in a real K-deep CKB block (a
     real-PoW demo block can't contain a synthetic bridge tx), i.e. step 4.
4. **Prover/relayer** — IN PROGRESS (live):
   - ✅ `bridge_lock_v1` deployed on Pudge (`BRIDGE_CODE_HASH 0x1c2589e8…`); a canonical bridge-RECEIPT lock
     tx is **mined live**: `0xcfaaf177…` (200 CKB, recipient `2df44c71…`). Its exact RawTransaction body (522 B)
     is reconstructed + verified (`ckbhash(body)==tx_hash`) and the receipt offsets confirmed on the REAL tx
     (`type_code@287`, `amount@474`, `recipient@490`) — `relayer/onchain/bridge_deploy_lock.mjs` →
     `bridge_lock_live.json`.
   - ⏳ Prove end-to-end on its block (#21388341) once K_MIN(12)-deep: feed the real header + CBMT proof for
     `0xcfaaf177…` + the captured body into the value-bound leap circuit (bake `BRIDGE_CODE_HASH`), prove, and
     confirm the Aiken verifier accepts. (Window/checkpoint synthetic, as in the existing consensus demo.)
5. **Re-audit** the value binding (the 2 confirmed lenses) + the unaudited `authz`/`doublemint` dimensions.
6. (Then) the §6 burn→unlock release lock, and the §8 reorg-cap/rate-limiter hardening.

**Recommendation:** do step 1 (the reader prototype) next — it's the only part with real technical risk; once
the in-circuit `body → bridge capacity` extraction is differential-tested green, the rest is wiring.
