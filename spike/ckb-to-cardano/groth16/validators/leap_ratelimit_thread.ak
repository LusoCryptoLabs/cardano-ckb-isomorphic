//// leap_ratelimit_thread.ak - the one-shot GENESIS PIN for the SEC-D6 aggregate rate-limiter singleton.
//// Mirror of seal_thread / ckbcert_thread: parameterized by a unique `genesis_ref` (consumed at mint, so it
//// can fire at most once) and the leap_ratelimit script hash. Mints exactly one thread token onto a fresh
//// leap_ratelimit output whose datum is the ZERO accumulator (window_start: 0, minted_in_window: 0). Thereafter
//// leap_ratelimit requires this token on every spend, and leap_mint_guard requires the ticked input to carry
//// it - so there is exactly ONE canonical accumulator and a forged/zeroed limiter cannot reset the cap.
use aiken/collection/list
use cardano/address.{Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction, OutputReference, Output, InlineDatum}
use g16/ckbcert.{has_thread, is_thread_burn, mints_one_thread}
use leap_ratelimit.{RateState}

// NOTE: takes ONLY `genesis_ref` (not the leap_ratelimit script hash) to break the deploy-time parameter
// circularity (leap_ratelimit is parameterized by THIS policy id). The address binding is enforced on the
// consuming side: leap_ratelimit.spend only runs on the cell at its own address, and leap_mint_guard.rate_ticked
// finds the token-bearing input. This minter guarantees one-shot uniqueness + a zero-accumulator genesis datum.
validator leap_ratelimit_thread(genesis_ref: OutputReference) {
  mint(_redeemer: Data, policy_id: PolicyId, tx: Transaction) {
    let Transaction { inputs, outputs, mint, .. } = tx
    if is_thread_burn(mint, policy_id) {
      True
    } else {
      let unique = list.any(inputs, fn(i) { i.output_reference == genesis_ref })
      let one = mints_one_thread(mint, policy_id)
      let pinned_out = list.any(outputs, fn(o: Output) { is_zero_genesis(o, policy_id) })
      unique && one && pinned_out
    }
  }

  else(_) {
    fail
  }
}

/// The genesis limiter cell: carries the thread token, datum = zero accumulator.
fn is_zero_genesis(o: Output, policy: PolicyId) -> Bool {
  let datum_ok =
    when o.datum is {
      InlineDatum(d) -> {
        expect s: RateState = d
        s.window_start == 0 && s.minted_in_window == 0
      }
      _ -> False
    }
  has_thread(o.value, policy) && datum_ok
}

// ---- genesis mock-tx tests ----
const t_policy: PolicyId = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a"
const t_thread_name: ByteArray = #"636b62636572742d746872656164"
const t_rl: ByteArray = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2b"
const t_gref: OutputReference =
  OutputReference { transaction_id: #"1111111111111111111111111111111111111111111111111111111111111111", output_index: 3 }

fn dummy_in(oref: OutputReference) -> transaction.Input {
  transaction.Input {
    output_reference: oref,
    output: Output {
      address: address.Address { payment_credential: address.VerificationKey(#"00"), stake_credential: None },
      value: assets.from_lovelace(5000),
      datum: transaction.NoDatum,
      reference_script: None,
    },
  }
}

fn mk_mint_tx(with_gref: Bool, st: RateState, with_token: Bool) -> Transaction {
  let in_oref =
    if with_gref {
      t_gref
    } else {
      OutputReference { transaction_id: #"2222222222222222222222222222222222222222222222222222222222222222", output_index: 0 }
    }
  let mint_val =
    if with_token {
      assets.from_asset(t_policy, t_thread_name, 1)
    } else {
      assets.from_asset(t_policy, #"6465636f79", 1)
    }
  let gen_out =
    Output {
      address: address.Address { payment_credential: Script(t_rl), stake_credential: None },
      value: assets.from_asset(t_policy, t_thread_name, 1),
      datum: InlineDatum(st),
      reference_script: None,
    }
  Transaction { ..transaction.placeholder, inputs: [dummy_in(in_oref)], outputs: [gen_out], mint: mint_val }
}

test rlt_genesis_mint_ok() {
  leap_ratelimit_thread.mint(t_gref, Void, t_policy, mk_mint_tx(True, RateState { window_start: 0, minted_in_window: 0 }, True))
}
test rlt_without_unique_ref_rejected() {
  !leap_ratelimit_thread.mint(t_gref, Void, t_policy, mk_mint_tx(False, RateState { window_start: 0, minted_in_window: 0 }, True))
}
test rlt_nonzero_accumulator_rejected() {
  !leap_ratelimit_thread.mint(t_gref, Void, t_policy, mk_mint_tx(True, RateState { window_start: 0, minted_in_window: 5 }, True))
}
