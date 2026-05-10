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

## 2. The canonical bridge-lock tx (CKB side)

A new CKB **type script** `bridge_lock_v1` makes a confirmed lock tx self-certifying. On the output it guards
it enforces (CKB-VM, cheap):

```
BRIDGE OUTPUT  (the locked cell):
  capacity   = amount                         (the full locked value = the bridged amount)
  type       = bridge_lock_v1  (args = bridge instance id)
  data       = MAGIC(4) ‖ amount(16 LE) ‖ recipient(28)        # fixed 48-byte layout
  lock       = a release lock (spendable only by the burn→unlock proof; see §6)
enforced by bridge_lock_v1 on creation:
  - data.len == 48 && data[0..4] == MAGIC
  - capacity == u128(data.amount)             (locked value == declared amount)
  - exactly ONE bridge output in the tx       (no ambiguity for the circuit)
  - (genesis/one-shot pinning as needed)
```

`recipient` is the 28-byte Cardano payment credential. `seal` = this lock tx's own hash (unique, single-use;
the Cardano side nullifies it — §5). The commitment is no longer needed as a separate binding (the circuit
reads `amount`/`recipient` directly); we keep `commitment = blake2b256(new_state ‖ seal)` as the circuit's
public input #3 purely to preserve the existing Plutus interface, now over a *constrained* `new_state`.

**Why a type script, not the lock:** type scripts validate cell data/creation and are the natural home for
"this cell encodes `amount‖recipient` and capacity matches." It runs when the lock tx is included in a CKB
block, so **any confirmed bridge tx already satisfies the binding** — the circuit only has to prove the tx is
confirmed and *carries* the bridge type, not re-derive correctness.

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

## 8. Other audit items on this leg (separate from value binding, needed for production)

- **Reorg aggregate cap ships disabled** (`d6_deploy.py`: `cap=0`/`max_amount=0`) — re-enable + make it
  governable, not compile-time-off (RATELIMIT-1).
- **Rate-limiter genesis not address-pinned**; `rate_ticked` address-blind (RLT-1). **`K=0` allowed** in the
  sane-K band (GOV-1).
- **`authz` (no-mint-without-leap) and `doublemint` (replay) dimensions are UNAUDITED** (finders died on
  socket errors) — re-run those adversarial dimensions.

These don't block the value-binding fix but are on the critical path to "value-ready."

## 9. Work plan

1. **Prototype the reader (de-risk first).** In-circuit: `body → ckbhash → == seal`, then read
   `(capacity, type_hash, recipient)` at canonical offsets; differential-test vs native molecule decode on a
   **real Pudge lock tx**. Standalone, before touching the full circuit. *(≈ the riskiest 20%.)*
2. **`bridge_lock_v1` CKB type script** — enforce the §2 invariants + canonical shape; unit + adversarial
   tests (wrong capacity, two bridge outputs, bad data) in ckb-testtool.
3. **Wire the binding into `leap_windowed.rs`** — add the §3 constraints; re-prove on a real block; confirm
   the Aiken verifier still accepts; add the **negative test** (lock 1 / mint big → unsatisfiable / rejected).
4. **Prover/relayer** — `ckb_lock.py` emits the canonical bridge cell; `relayer.py`/`relay_prove.rs` feed the
   real `tx_body` + read `amount/recipient` from the locked cell (drop the hardcodes).
5. **Re-audit** the value binding (the 2 confirmed lenses) + the unaudited `authz`/`doublemint` dimensions.
6. (Then) the §6 burn→unlock release lock, and the §8 reorg-cap/rate-limiter hardening.

**Recommendation:** do step 1 (the reader prototype) next — it's the only part with real technical risk; once
the in-circuit `body → bridge capacity` extraction is differential-tested green, the rest is wiring.
