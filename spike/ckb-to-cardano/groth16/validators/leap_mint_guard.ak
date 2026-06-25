//// leap_mint_guard.ak - Cardano-side leap-mint guard (the wrapped-FT mint policy), bound to the REAL
//// `cardano_bound` verifier. No mock: the leap fact is read from the ACTUAL `cardano_bound` output's
//// `BoundState { ckb_seal, state }` datum present in this tx - `cardano_bound`'s own validator verifies the
//// Groth16 proof of the CKB lock that authenticates it. For a financial token the `state` is
//// `amount(16 LE) ‖ recipient_credential(28)`. This policy enforces NO-INFLATION / EXACT-BURN of the FT
//// against that verified amount, via the unit-tested `leap_guard` logic. PoC wiring; tx-level tests + audit
//// before value. params: the (333) FT name and the deployed `cardano_bound` script hash.
use aiken/builtin
use aiken/collection/list
use aiken/collection/dict
use aiken/collection/pairs
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, quantity_of, tokens, Value, from_lovelace, from_asset}
use cardano/transaction.{Transaction, Output, Input, InlineDatum, NoDatum, Datum, OutputReference, ScriptPurpose, Spend, placeholder}
use g16/seal_set.{Insert}
use g16/ckbcert.{has_thread}
use leap_ratelimit.{Tick}
use leap_guard.{
  LeapFact, GuardPolicy, PolicyState, Direction, LeapIn, LeapOut, authorize_mint, authorize_burn, enforce_policy,
}

pub type LeapRedeemer {
  LeapInMint
  LeapOutBurn
}

// mirrors cardano_bound.BoundState (structurally identical Plutus data - the REAL verified datum)
pub type BoundState {
  ckb_seal: ByteArray,
  state: ByteArray,
}

/// Read the admin policy from the governor-signed cell, matched by its ONE-SHOT NFT as a REFERENCE INPUT.
/// SEC D6 (MF-4): fail-CLOSED, exactly-one. Previously this matched by script hash with a first-match find
/// and an OPEN default on absence, so an attacker could omit the policy reference input (pauses/caps
/// unenforced) or front a decoy cell at the same script hash. The one-shot NFT makes the cell unforgeable
/// and exactly-one makes it unambiguous - the SAME cell cardano_bound.read_k reads, so caps/pause and K can
/// never disagree. Reference, not spend, so one governance UTxO gates every leap tx.
fn read_policy(self: Transaction, policy_nft: PolicyId, policy_name: ByteArray) -> GuardPolicy {
  expect [i] =
    list.filter(self.reference_inputs, fn(i: Input) { quantity_of(i.output.value, policy_nft, policy_name) == 1 })
  expect InlineDatum(d) = i.output.datum
  expect ps: PolicyState = d
  ps.policy
}

// SEC N-FIN-1 (one mint per leap): the leap's CKB seal must be CONSUMED in the global seal-nullifier
// registry in this tx. We find the registry by its GENESIS THREAD NFT (one-shot, unique) and require EXACTLY
// ONE - NOT by script hash. This is load-bearing now that seal_nullifier is CONTINUITY-pinned (it dropped its
// thread_policy param to break the seal_nullifier <-> seal_thread cycle): a decoy registry at the same script
// hash carrying a DIFFERENT token can still be spent (it inserts into its own tree), so identifying the
// canonical registry by SCRIPT HASH would let that decoy absorb the seal-insert and break replay-once. By the
// NFT, only the one genesis-pinned lineage qualifies. Its Insert redeemer's key must == this leap's ckb_seal;
// seal_nullifier independently proves the insert is sound (non-membership ⇒ never consumed before). So a given
// CKB anchor authorizes at most ONE Cardano mint across all txs.
fn seal_consumed(self: Transaction, registry_nft: PolicyId, seal: ByteArray) -> Bool {
  when list.filter(self.inputs, fn(i: Input) { has_thread(i.output.value, registry_nft) }) is {
    [reg_in] ->
      when pairs.get_first(self.redeemers, Spend(reg_in.output_reference)) is {
        Some(rd) -> {
          expect ins: Insert = rd
          ins.key == seal
        }
        None -> False
      }
    _ -> False
  }
}

// SEC D6 (aggregate cap): require the singleton rate-limiter to be ticked for exactly this leap's amount.
// Find the limiter input by its THREAD TOKEN (not merely script hash - a decoy at the same hash without the
// token must not satisfy this), require EXACTLY ONE, and read its Spend redeemer `Tick.amount == amount`.
// leap_ratelimit then verifies the accumulator math (acc += amount <= cap) against that same amount.
fn rate_ticked(self: Transaction, ratelimit_thread: PolicyId, amount: Int) -> Bool {
  when list.filter(self.inputs, fn(i: Input) { has_thread(i.output.value, ratelimit_thread) }) is {
    [rl_in] ->
      when pairs.get_first(self.redeemers, Spend(rl_in.output_reference)) is {
        Some(rd) -> {
          expect t: Tick = rd
          t.amount == amount
        }
        None -> False
      }
    _ -> False
  }
}

validator leap_mint_guard(
  ft_name: ByteArray,
  bound_script_hash: ByteArray,
  policy_nft: PolicyId,
  policy_name: ByteArray,
  seal_registry_nft: PolicyId,
  ratelimit_thread: PolicyId,
) {
  mint(redeemer: LeapRedeemer, policy_id: ByteArray, self: Transaction) {
    let policy = read_policy(self, policy_nft, policy_name)
    let minted = quantity_of(self.mint, policy_id, ft_name)
    let only_one_name = ( self.mint |> tokens(policy_id) |> dict.size ) == 1

    when redeemer is {
      LeapInMint -> {
        // SEC B3 (replay-once / no-mint-without-leap): bind the mint to an ACTUAL cardano_bound SPEND, not a
        // mere output. Spending a cardano_bound UTxO (a) forces its spend validator to verify the Groth16
        // leap proof, and (b) consumes a UNIQUE outpoint spendable only once - so a given leap cannot mint
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
        only_one_name && enforce_policy(policy, LeapIn, fact.amount) && authorize_mint(fact, minted, 0, to_recipient, True) && seal_consumed(self, seal_registry_nft, bs.ckb_seal) && rate_ticked(self, ratelimit_thread, fact.amount)
      }
      // LeapOutBurn is a pure burn (negative mint) - non-inflationary; the authoritative event is the CKB
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
const m_ft: ByteArray = #"cf87434b42"  // "χCKB"
const m_bound: ByteArray = #"11111111111111111111111111111111111111111111111111111111"
const m_null: ByteArray = #"22222222222222222222222222222222222222222222222222222222"
// the seal-registry GENESIS NFT (seal_thread policy id) - leap_mint_guard now finds the registry by THIS, not
// by script hash (continuity-pinned seal_nullifier; see seal_consumed).
const m_reg_nft: PolicyId = #"88888888888888888888888888888888888888888888888888888888"
const m_recip: ByteArray = #"33333333333333333333333333333333333333333333333333333333"
const m_seal: ByteArray = #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"
const m_state: ByteArray = #"6400000000000000000000000000000033333333333333333333333333333333333333333333333333333333"
const m_bound_oref: OutputReference =
  OutputReference { transaction_id: #"00000000000000000000000000000000000000000000000000000000000000aa", output_index: 0 }
const m_null_oref: OutputReference =
  OutputReference { transaction_id: #"00000000000000000000000000000000000000000000000000000000000000bb", output_index: 0 }
// SEC D6 aggregate cap: rate-limiter thread policy + its spent input.
const m_rl: PolicyId = #"44444444444444444444444444444444444444444444444444444444"
const m_rl_addr: ByteArray = #"55555555555555555555555555555555555555555555555555555555"
const thread_name: ByteArray = #"636b62636572742d746872656164"
const m_rl_oref: OutputReference =
  OutputReference { transaction_id: #"00000000000000000000000000000000000000000000000000000000000000cc", output_index: 0 }
// SEC D6 (MF-4): the governor-signed policy cell, matched by its one-shot NFT as a reference input.
const m_polnft: PolicyId = #"66666666666666666666666666666666666666666666666666666666"
const m_polname: ByteArray = #"706f6c696379"
const m_pol_addr: ByteArray = #"77777777777777777777777777777777777777777777777777777777"
const m_pol_oref: OutputReference =
  OutputReference { transaction_id: #"00000000000000000000000000000000000000000000000000000000000000ee", output_index: 0 }

fn mk_out(h: ByteArray, val: Value, datum: Datum) -> Output {
  Output { address: Address { payment_credential: Script(h), stake_credential: None }, value: val, datum, reference_script: None }
}

// an open (no-cap, unpaused) policy cell carrying the one-shot policy NFT.
fn pol_ref() -> Input {
  let st = PolicyState {
    governor: #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    policy: GuardPolicy { paused_global: False, paused_in: False, paused_out: False, min_amount: 0, max_amount: 0, min_confirmations: 12 },
  }
  Input { output_reference: m_pol_oref, output: mk_out(m_pol_addr, from_asset(m_polnft, m_polname, 1), InlineDatum(st)) }
}

fn base(with_nullifier: Bool, reds: Pairs<ScriptPurpose, Data>) -> Transaction {
  let bs = BoundState { ckb_seal: m_seal, state: m_state }
  let bound_in = Input { output_reference: m_bound_oref, output: mk_out(m_bound, from_lovelace(2), InlineDatum(bs)) }
  // the singleton registry input, carrying its GENESIS NFT (found by seal_consumed via has_thread, not by hash).
  let reg_in = Input { output_reference: m_null_oref, output: mk_out(m_null, from_asset(m_reg_nft, thread_name, 1), NoDatum) }
  // the singleton rate-limiter input, carrying the thread token (found by rate_ticked via has_thread).
  let rl_in = Input { output_reference: m_rl_oref, output: mk_out(m_rl_addr, from_asset(m_rl, thread_name, 1), NoDatum) }
  let bound_out = mk_out(m_bound, from_lovelace(2), InlineDatum(bs))
  let recip_out = mk_out(m_recip, from_asset(m_policy, m_ft, 100), NoDatum)
  let inputs = if with_nullifier { [bound_in, reg_in, rl_in] } else { [bound_in] }
  Transaction { ..placeholder, inputs: inputs, reference_inputs: [pol_ref()], outputs: [bound_out, recip_out], mint: from_asset(m_policy, m_ft, 100), redeemers: reds }
}

test leapin_rejects_without_nullifier() {
  !leap_mint_guard.mint(m_ft, m_bound, m_polnft, m_polname, m_reg_nft, m_rl, LeapInMint, m_policy, base(False, []))
}

// redeemers: the nullifier Insert + the rate-limiter Tick (amount must equal the leap fact amount = 100).
fn red(key: ByteArray, tick_amount: Int) -> Pairs<ScriptPurpose, Data> {
  let ins: Data = Insert { key, sibs: [] }
  let tick: Data = Tick { amount: tick_amount }
  [Pair(Spend(m_null_oref), ins), Pair(Spend(m_rl_oref), tick)]
}

test leapin_accepts_when_seal_consumed_and_ticked() {
  leap_mint_guard.mint(m_ft, m_bound, m_polnft, m_polname, m_reg_nft, m_rl, LeapInMint, m_policy, base(True, red(m_seal, 100)))
}

test leapin_rejects_wrong_seal_key() {
  !leap_mint_guard.mint(m_ft, m_bound, m_polnft, m_polname, m_reg_nft, m_rl, LeapInMint, m_policy, base(True, red(#"dead0000000000000000000000000000000000000000000000000000000000ff", 100)))
}

// SEC D6: a leap whose rate-limiter Tick under-reports the amount (99 != fact 100) must be rejected, so the
// accumulator can never be fed a smaller value than what is actually minted.
test leapin_rejects_when_rate_underreported() {
  !leap_mint_guard.mint(m_ft, m_bound, m_polnft, m_polname, m_reg_nft, m_rl, LeapInMint, m_policy, base(True, red(m_seal, 99)))
}

test seal_consumed_reads_redeemer() {
  seal_consumed(base(True, red(m_seal, 100)), m_reg_nft, m_seal)
}
test seal_consumed_rejects_wrong_key() {
  !seal_consumed(base(True, red(#"dead0000000000000000000000000000000000000000000000000000000000ff", 100)), m_reg_nft, m_seal)
}

// SEC N-FIN-1 (continuity defense): the registry is found by its GENESIS NFT - querying by an NFT that no input
// carries finds nothing and rejects. So a decoy registry at the SAME script hash but a DIFFERENT token (which a
// continuity-pinned seal_nullifier would still let spend) cannot be mistaken for the canonical registry, and
// cannot absorb the seal-insert to enable a double-mint.
test seal_consumed_rejects_decoy_registry_nft() {
  !seal_consumed(base(True, red(m_seal, 100)), #"99999999999999999999999999999999999999999999999999999999", m_seal)
}

// SEC D6 (RATELIMIT-1 / per-leap cap ENABLED): the policy reference input now carries a REAL max_amount.
// These exercise the cap through the FULL mint validator (not enforce_policy in isolation): a leap above the
// per-leap cap is rejected even with a valid seal + tick, and a leap exactly AT the cap still mints.
fn pol_ref_capped(max_amount: Int) -> Input {
  let st = PolicyState {
    governor: #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    policy: GuardPolicy { paused_global: False, paused_in: False, paused_out: False, min_amount: 0, max_amount: max_amount, min_confirmations: 12 },
  }
  Input { output_reference: m_pol_oref, output: mk_out(m_pol_addr, from_asset(m_polnft, m_polname, 1), InlineDatum(st)) }
}

// leap amount is 100 (m_state[0..16] LE). cap 50 < 100 -> rejected by the real guard.
test leapin_rejects_over_per_leap_cap() {
  let tx = Transaction { ..base(True, red(m_seal, 100)), reference_inputs: [pol_ref_capped(50)] }
  !leap_mint_guard.mint(m_ft, m_bound, m_polnft, m_polname, m_reg_nft, m_rl, LeapInMint, m_policy, tx)
}
// exactly at the cap (100 == 100) still mints.
test leapin_accepts_at_per_leap_cap() {
  let tx = Transaction { ..base(True, red(m_seal, 100)), reference_inputs: [pol_ref_capped(100)] }
  leap_mint_guard.mint(m_ft, m_bound, m_polnft, m_polname, m_reg_nft, m_rl, LeapInMint, m_policy, tx)
}

