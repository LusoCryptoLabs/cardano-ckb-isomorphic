//// leap_mint_guard.ak — Cardano-side leap-mint guard (the wrapped-FT mint policy), bound to the REAL
//// `cardano_bound` verifier. No mock: the leap fact is read from the ACTUAL `cardano_bound` output's
//// `BoundState { ckb_seal, state }` datum present in this tx — `cardano_bound`'s own validator verifies the
//// Groth16 proof of the CKB lock that authenticates it. For a financial token the `state` is
//// `amount(16 LE) ‖ recipient_credential(28)`. This policy enforces NO-INFLATION / EXACT-BURN of the FT
//// against that verified amount, via the unit-tested `leap_guard` logic. PoC wiring; tx-level tests + audit
//// before value. params: the (333) FT name and the deployed `cardano_bound` script hash.
use aiken/builtin
use aiken/collection/list
use aiken/collection/dict
use aiken/collection/pairs
use cardano/address.{Address, Script}
use cardano/assets.{quantity_of, tokens, Value, from_lovelace, from_asset}
use cardano/transaction.{Transaction, Output, Input, InlineDatum, NoDatum, Datum, OutputReference, ScriptPurpose, Spend, placeholder}
use g16/seal_set.{Insert}
use leap_guard.{
  LeapFact, GuardPolicy, Direction, LeapIn, LeapOut, authorize_mint, authorize_burn, enforce_policy,
}

pub type LeapRedeemer {
  LeapInMint
  LeapOutBurn
}

// mirrors cardano_bound.BoundState (structurally identical Plutus data — the REAL verified datum)
pub type BoundState {
  ckb_seal: ByteArray,
  state: ByteArray,
}

/// Read the admin policy from a REFERENCE INPUT at `policy_script_hash` (an open, no-cap default if no
/// such reference input is present). Reference, not spend, so one governance UTxO gates every leap tx.
fn read_policy(self: Transaction, policy_script_hash: ByteArray) -> GuardPolicy {
  when
    list.find(
      self.reference_inputs,
      fn(i: Input) {
        when i.output.address.payment_credential is {
          Script(h) -> h == policy_script_hash
          _ -> False
        }
      },
    )
  is {
    Some(i) -> {
      expect InlineDatum(d) = i.output.datum
      expect p: GuardPolicy = d
      p
    }
    None -> GuardPolicy { paused_global: False, paused_in: False, paused_out: False, min_amount: 0, max_amount: 0 }
  }
}

// SEC N-FIN-1 (one mint per leap): the leap's CKB seal must be CONSUMED in the global seal-nullifier
// registry in this tx — find the registry input by its script hash, read its Insert redeemer, and require
// the inserted key == this leap's `ckb_seal`. The seal_nullifier validator independently proves the insert
// is sound (non-membership ⇒ the seal was never consumed before). Since the genesis-pinned registry admits
// each seal at most once, a given CKB anchor can authorize at most ONE Cardano mint, across all txs — two
// BoundState UTxOs sharing a seal cannot both mint.
fn seal_consumed(self: Transaction, nullifier_hash: ByteArray, seal: ByteArray) -> Bool {
  when
    list.find(
      self.inputs,
      fn(i: Input) {
        when i.output.address.payment_credential is {
          Script(h) -> h == nullifier_hash
          _ -> False
        }
      },
    )
  is {
    Some(reg_in) ->
      when pairs.get_first(self.redeemers, Spend(reg_in.output_reference)) is {
        Some(rd) -> {
          expect ins: Insert = rd
          ins.key == seal
        }
        None -> False
      }
    None -> False
  }
}

validator leap_mint_guard(
  ft_name: ByteArray,
  bound_script_hash: ByteArray,
  policy_script_hash: ByteArray,
  seal_nullifier_hash: ByteArray,
) {
  mint(redeemer: LeapRedeemer, policy_id: ByteArray, self: Transaction) {
    let policy = read_policy(self, policy_script_hash)
    let minted = quantity_of(self.mint, policy_id, ft_name)
    let only_one_name = ( self.mint |> tokens(policy_id) |> dict.size ) == 1

    when redeemer is {
      LeapInMint -> {
        // SEC B3 (replay-once / no-mint-without-leap): bind the mint to an ACTUAL cardano_bound SPEND, not a
        // mere output. Spending a cardano_bound UTxO (a) forces its spend validator to verify the Groth16
        // leap proof, and (b) consumes a UNIQUE outpoint spendable only once — so a given leap cannot mint
        // twice, and a decoy bound-output (which triggers NO validator) can no longer authorize a mint.
        // Require EXACTLY ONE cardano_bound input so the bound (amount, recipient) is unambiguous.
        expect [bound_in] =
          list.filter(
            self.inputs,
            fn(i: Input) {
              when i.output.address.payment_credential is {
                Script(h) -> h == bound_script_hash
                _ -> False
              }
            },
          )
        // cardano_bound's own spend validator guarantees exactly one continuing output carrying the
        // leaped-in `new_state`; read the verified fact from that continuing output.
        expect [bound_out] =
          list.filter(self.outputs, fn(o: Output) { o.address == bound_in.output.address })
        expect InlineDatum(d) = bound_out.datum
        expect bs: BoundState = d
        // financial state layout: amount(16 LE) ‖ recipient_credential(28)
        let amount = builtin.bytearray_to_integer(False, builtin.slice_bytearray(0, 16, bs.state))
        let recipient = builtin.slice_bytearray(16, 28, bs.state)
        let fact = LeapFact { amount, recipient, nonce: bs.ckb_seal }
        let to_recipient =
          list.foldl(self.outputs, 0, fn(o: Output, acc: Int) {
            when o.address.payment_credential is {
              Script(h) -> if h == recipient { acc + quantity_of(o.value, policy_id, ft_name) } else { acc }
              _ -> acc
            }
          })
        // fact_consumed = True is now JUSTIFIED: the unique cardano_bound UTxO was spent in this tx.
        // SEC N-FIN-1: and the leap's seal must be nullified once in the registry (one mint per seal).
        only_one_name && enforce_policy(policy, LeapIn, fact.amount) && authorize_mint(fact, minted, 0, to_recipient, True) && seal_consumed(self, seal_nullifier_hash, bs.ckb_seal)
      }
      // LeapOutBurn is a pure burn (negative mint) — non-inflationary; the authoritative event is the CKB
      // release gated by burn_gated_unlock on the CKB side. The bound amount it must match is read from the
      // cardano_bound output present in this tx (a burn cannot create supply, so no spend-binding is needed).
      LeapOutBurn -> {
        expect Some(bound_out) =
          list.find(
            self.outputs,
            fn(o: Output) {
              when o.address.payment_credential is {
                Script(h) -> h == bound_script_hash
                _ -> False
              }
            },
          )
        expect InlineDatum(d) = bound_out.datum
        expect bs: BoundState = d
        let amount = builtin.bytearray_to_integer(False, builtin.slice_bytearray(0, 16, bs.state))
        only_one_name && enforce_policy(policy, LeapOut, amount) && authorize_burn(amount, 0, -minted, True)
      }
    }
  }

  else(_) {
    fail
  }
}



// ---- mock-tx tests for the N-FIN-1 seal-consumption wiring ----
const m_policy: ByteArray = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a"
const m_ft: ByteArray = #"636b434b42"
const m_bound: ByteArray = #"11111111111111111111111111111111111111111111111111111111"
const m_null: ByteArray = #"22222222222222222222222222222222222222222222222222222222"
const m_recip: ByteArray = #"33333333333333333333333333333333333333333333333333333333"
const m_seal: ByteArray = #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"
const m_state: ByteArray = #"6400000000000000000000000000000033333333333333333333333333333333333333333333333333333333"
const m_bound_oref: OutputReference =
  OutputReference { transaction_id: #"00000000000000000000000000000000000000000000000000000000000000aa", output_index: 0 }
const m_null_oref: OutputReference =
  OutputReference { transaction_id: #"00000000000000000000000000000000000000000000000000000000000000bb", output_index: 0 }

fn mk_out(h: ByteArray, val: Value, datum: Datum) -> Output {
  Output { address: Address { payment_credential: Script(h), stake_credential: None }, value: val, datum, reference_script: None }
}

fn base(with_nullifier: Bool, reds: Pairs<ScriptPurpose, Data>) -> Transaction {
  let bs = BoundState { ckb_seal: m_seal, state: m_state }
  let bound_in = Input { output_reference: m_bound_oref, output: mk_out(m_bound, from_lovelace(2), InlineDatum(bs)) }
  let reg_in = Input { output_reference: m_null_oref, output: mk_out(m_null, from_lovelace(2), NoDatum) }
  let bound_out = mk_out(m_bound, from_lovelace(2), InlineDatum(bs))
  let recip_out = mk_out(m_recip, from_asset(m_policy, m_ft, 100), NoDatum)
  let inputs = if with_nullifier { [bound_in, reg_in] } else { [bound_in] }
  Transaction { ..placeholder, inputs: inputs, outputs: [bound_out, recip_out], mint: from_asset(m_policy, m_ft, 100), redeemers: reds }
}

test leapin_rejects_without_nullifier() {
  !leap_mint_guard.mint(m_ft, m_bound, #"00", m_null, LeapInMint, m_policy, base(False, []))
}

fn red(key: ByteArray) -> Pairs<ScriptPurpose, Data> {
  let ins: Data = Insert { key, sibs: [] }
  [Pair(Spend(m_null_oref), ins)]
}

test leapin_accepts_when_seal_consumed() {
  leap_mint_guard.mint(m_ft, m_bound, #"00", m_null, LeapInMint, m_policy, base(True, red(m_seal)))
}

test leapin_rejects_wrong_seal_key() {
  !leap_mint_guard.mint(m_ft, m_bound, #"00", m_null, LeapInMint, m_policy, base(True, red(#"dead0000000000000000000000000000000000000000000000000000000000ff")))
}

test seal_consumed_reads_redeemer() {
  seal_consumed(base(True, red(m_seal)), m_null, m_seal)
}
test seal_consumed_rejects_wrong_key() {
  !seal_consumed(base(True, red(#"dead0000000000000000000000000000000000000000000000000000000000ff")), m_null, m_seal)
}

