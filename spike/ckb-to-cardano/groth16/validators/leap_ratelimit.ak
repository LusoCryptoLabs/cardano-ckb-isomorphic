//// leap_ratelimit.ak - SEC D6 AGGREGATE value cap. A thread-pinned SINGLETON UTxO that bounds the TOTAL
//// χCKB minted-but-not-yet-final per rolling time window, so a thief cannot split one large reorg-theft
//// into N sub-(per-leap-cap) leaps inside one reorg window. Every `LeapInMint` must spend+recreate this
//// cell (mints are already serialized through the seal-nullifier singleton, so this adds no new
//// serialization). `leap_mint_guard` cross-checks that the limiter's `Tick.amount` == the verified leap
//// fact, and that the spent limiter input CARRIES THE THREAD TOKEN (else a decoy at the same script hash
//// spoofs the tick and the real accumulator is never updated).
////
//// TIME SEMANTICS (the load-bearing, adversarially-reviewed part): the window reset is gated on the
//// CONSERVATIVE lower validity bound `now = lo`. The LOAD-BEARING defense against future-dating `lo` to
//// force an early reset is the LEDGER RULE itself: a tx is unminable until `current_slot >= lo`, so by the
//// time the reset-claiming tx is actually included, real time has genuinely reached `lo >= window_start +
//// window_len` - a real elapse, not a forged one. Using `lo` (never `hi`) is what makes this safe: a
//// smaller `now` only DELAYS resets (keeps the window closed longer), never opens one early. The Finite
//// upper bound + bounded width (`hi - lo <= max_width`) are DEFENSE-IN-DEPTH (they bound pre-signed
//// far-future-dated ticks); they do NOT enter the reset math (`elapsed = now >= window_start + window_len`)
//// and must not be mistaken for the primary defense. Governance must keep `window_len >= max_width`.
////
//// GOVERNANCE INVARIANT (off-chain, documented in D6_REORG.md): `window_len >= wall-clock of a depth-K
//// reorg` and `cap < cost-to-rent-CKB-majority-for-window_len`. The real throughput ceiling is therefore
//// `cap/window_len` - a deliberate global liveness chokepoint, the honest price of an aggregate cap.
use aiken/collection/list
use aiken/interval.{Finite}
use cardano/address.{Script}
use cardano/assets.{PolicyId, quantity_of}
use cardano/transaction.{Transaction, OutputReference, Output, InlineDatum}
use g16/ckbcert.{has_thread}

/// The rolling accumulator datum on the singleton limiter cell.
pub type RateState {
  window_start: Int,      // slot at which the current window opened
  minted_in_window: Int,  // total χCKB minted since window_start
}

/// Spend redeemer: the FT amount being minted this tx (pinned to the verified leap fact by leap_mint_guard).
pub type Tick {
  amount: Int,
}

/// Max validity-interval width in POSIXTime MILLISECONDS (the unit Plutus V3 reports `tx.validity_range` in
/// - NOT slots) - bounds future-dating of the lower bound. 600_000 ms = 10 min (at 1s slots that is 600 slots).
/// (Was 600, which would reject every real tx: the smallest non-empty interval is one slot = 1000 ms > 600.)
pub const max_width: Int = 600_000

validator leap_ratelimit(thread_policy: PolicyId, ft_policy: PolicyId, ft_name: ByteArray, cap: Int, window_len: Int) {
  spend(datum: Option<RateState>, r: Tick, own: OutputReference, tx: Transaction) {
    expect Some(st) = datum
    expect r.amount > 0
    // SEC D6 (MF-2): COUPLE the accumulator to a real mint. Without this, anyone could spend the singleton
    // standalone with Tick{amount: cap} (no mint, no proof) to fill the window and HALT all honest leap-ins
    // for free. Require the tx to mint exactly `r.amount` of the wrapped FT, so the accumulator can only ever
    // advance in lock-step with genuine bridged value (leap_mint_guard separately binds that mint to a
    // verified leap fact whose amount == this Tick.amount).
    let mint_ok = quantity_of(tx.mint, ft_policy, ft_name) == r.amount
    // SINGLETON: the spent limiter input must carry the one-shot thread token.
    expect Some(self_in) = list.find(tx.inputs, fn(i) { i.output_reference == own })
    let thread_in = has_thread(self_in.output.value, thread_policy)
    // TIME: require a finite, bounded validity interval (see header). now = conservative lower bound.
    expect Finite(lo) = tx.validity_range.lower_bound.bound_type
    expect Finite(hi) = tx.validity_range.upper_bound.bound_type
    let bounded = hi >= lo && hi - lo <= max_width
    let now = lo
    let elapsed = now >= st.window_start + window_len
    let new_start = if elapsed { now } else { st.window_start }
    let new_acc = if elapsed { r.amount } else { st.minted_in_window + r.amount }
    let within_cap = cap == 0 || new_acc <= cap   // cap == 0 => aggregate cap disabled (open)
    // exactly one continuing limiter output: same address, keeps the token, carries the updated accumulator.
    let addr = self_in.output.address
    let cont =
      when list.filter(tx.outputs, fn(o: Output) { o.address == addr }) is {
        [o] ->
          when o.datum is {
            InlineDatum(d) -> {
              expect ns: RateState = d
              has_thread(o.value, thread_policy)
                && ns.window_start == new_start
                && ns.minted_in_window == new_acc
            }
            _ -> False
          }
        _ -> False
      }
    thread_in && mint_ok && bounded && within_cap && cont
  }

  else(_) {
    fail
  }
}

// ---- tests ----
const t_policy: PolicyId = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a"
const t_name: ByteArray = #"636b62636572742d746872656164"
const t_script: ByteArray = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2b"
const t_ftpol: PolicyId = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2c"  // wrapped-FT policy
const t_ftnm: ByteArray = #"cf87434b42"                                                // "χCKB"
const t_oref: OutputReference =
  OutputReference { transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000", output_index: 0 }

fn at(with_token: Bool, st: RateState) -> Output {
  let v = if with_token { assets.from_asset(t_policy, t_name, 1) } else { assets.from_asset(t_policy, #"6465636f79", 1) }
  Output { address: address.Address { payment_credential: address.Script(t_script), stake_credential: None }, value: v, datum: InlineDatum(st), reference_script: None }
}

// mint_amt = the wrapped FT minted in this tx (must equal Tick.amount for the spend to pass - MF-2 coupling).
fn mk(in_tok: Bool, out_tok: Bool, st: RateState, ns: RateState, lo: Int, hi: Int, mint_amt: Int) -> Transaction {
  let self_in = transaction.Input { output_reference: t_oref, output: at(in_tok, st) }
  Transaction {
    ..transaction.placeholder,
    inputs: [self_in],
    outputs: [at(out_tok, ns)],
    validity_range: interval.between(lo, hi),
    mint: assets.from_asset(t_ftpol, t_ftnm, mint_amt),
  }
}

fn rl(cap: Int, window_len: Int, st: RateState, amount: Int, tx: Transaction) -> Bool {
  leap_ratelimit.spend(t_policy, t_ftpol, t_ftnm, cap, window_len, Some(st), Tick { amount }, t_oref, tx)
}

// fresh window: mint 100 against an empty accumulator opened at slot 1000.
test rl_fresh_within_cap_ok() {
  let st = RateState { window_start: 1000, minted_in_window: 0 }
  let ns = RateState { window_start: 1000, minted_in_window: 100 }
  rl(1000, 3600, st, 100, mk(True, True, st, ns, 1000, 1010, 100))
}

// accumulate within the same window: 700 + 200 = 900 <= cap 1000.
test rl_accumulate_within_cap_ok() {
  let st = RateState { window_start: 1000, minted_in_window: 700 }
  let ns = RateState { window_start: 1000, minted_in_window: 900 }
  rl(1000, 3600, st, 200, mk(True, True, st, ns, 1500, 1510, 200))
}

// over cap: 700 + 400 = 1100 > 1000 -> rejected.
test rl_over_cap_rejected() {
  let st = RateState { window_start: 1000, minted_in_window: 700 }
  let ns = RateState { window_start: 1000, minted_in_window: 1100 }
  !rl(1000, 3600, st, 400, mk(True, True, st, ns, 1500, 1510, 400))
}

// window elapsed (now=5000 >= 1000+3600): RESET, acc := amount, start := now.
test rl_reset_after_window_ok() {
  let st = RateState { window_start: 1000, minted_in_window: 950 }
  let ns = RateState { window_start: 5000, minted_in_window: 400 }
  rl(1000, 3600, st, 400, mk(True, True, st, ns, 5000, 5010, 400))
}

// a continuing datum that claims a reset WITHOUT the window having elapsed must fail (acc must accumulate).
test rl_premature_reset_rejected() {
  let st = RateState { window_start: 1000, minted_in_window: 950 }
  let ns = RateState { window_start: 1500, minted_in_window: 400 } // pretends a reset at slot 1500
  !rl(1000, 3600, st, 400, mk(True, True, st, ns, 1500, 1510, 400))
}

// defense-in-depth: an over-wide validity interval (a vehicle for pre-signed far-future ticks) is rejected.
// NOTE: the LOAD-BEARING early-reset defense is now=lo + the ledger rule (tx unminable until slot>=lo), which
// is a ledger property not expressible in a unit test; this only exercises the width bound.
test rl_wide_interval_rejected() {
  // width = 700_000 ms > max_width 600_000 -> rejected (ns matches a reset at now=lo so ONLY the width bound bites).
  let st = RateState { window_start: 1000, minted_in_window: 950 }
  let ns = RateState { window_start: 1000000, minted_in_window: 400 }
  !rl(1000, 3600, st, 400, mk(True, True, st, ns, 1000000, 1700000, 400))
}

// decoy input without the thread token must fail (the real singleton is what carries the accumulator).
test rl_missing_thread_rejected() {
  let st = RateState { window_start: 1000, minted_in_window: 0 }
  let ns = RateState { window_start: 1000, minted_in_window: 100 }
  !rl(1000, 3600, st, 100, mk(False, False, st, ns, 1000, 1010, 100))
}

// SEC D6 (MF-2): a standalone tick that does NOT mint the FT (mint 0 != Tick 500) must fail, so the
// accumulator cannot be pumped to the cap for free to DoS honest leap-ins.
test rl_standalone_no_mint_rejected() {
  let st = RateState { window_start: 1000, minted_in_window: 0 }
  let ns = RateState { window_start: 1000, minted_in_window: 500 }
  !rl(1000, 3600, st, 500, mk(True, True, st, ns, 1500, 1510, 0))
}

// and a tick whose mint UNDER-reports (mint 100 != Tick 500) must also fail.
test rl_mint_mismatch_rejected() {
  let st = RateState { window_start: 1000, minted_in_window: 0 }
  let ns = RateState { window_start: 1000, minted_in_window: 500 }
  !rl(1000, 3600, st, 500, mk(True, True, st, ns, 1500, 1510, 100))
}

// cap == 0 disables the aggregate cap (open).
test rl_cap_zero_open_ok() {
  let st = RateState { window_start: 1000, minted_in_window: 999999 }
  let ns = RateState { window_start: 1000, minted_in_window: 1999999 }
  rl(0, 3600, st, 1000000, mk(True, True, st, ns, 1500, 1510, 1000000))
}
