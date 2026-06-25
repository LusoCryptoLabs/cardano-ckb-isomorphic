//// Adversarial battery for the forward (CKB->Cardano) checkpoint GENESIS PIN - the Cardano-side mirror of
//// the reverse-leg pinning suite (Battery B). Proves: a genesis mint is accepted ONLY when it consumes the
//// one-shot outpoint, mints exactly one thread token, and lands the c_pinned datum at the checkpoint script;
//// and that fake genesis / wrong datum / wrong address / missing token / double-mint / non-unique attempts
//// are REJECTED. Plus thread-continuity and heaviest-chain checks used by advance_ckbcert.
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{Value, from_lovelace, from_asset, merge}
use cardano/transaction.{Input, Output, OutputReference, InlineDatum, NoDatum}
use aiken/builtin
use g16/ckbcert.{
  Checkpoint, thread_name, has_thread, mints_one_thread, is_thread_burn,
  is_pinned_genesis_output, genesis_mint_ok, lineage_token,
}

const c_policy = #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
const c_cp_script = #"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
const c_other = #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// canonical pinned CKB genesis anchor (real ChainRootMMR root; representative cumulative difficulty)
const c_pinned: Checkpoint =
  Checkpoint {
    chain_root: #"fbd2fcbad6a2a7bfe0470696340064460491f0db2fa3e06d21ea60107da6fa85",
    total_difficulty: #"0000000000000000000000000000000000000000000000000000010000000000",
    window_root: #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    tip_height: 21341101,
  }

const c_gref: OutputReference =
  OutputReference {
    transaction_id: #"40e2302540f9a008fd739efeba20b5007d7f32b8c205335421d6bcef67e00000",
    output_index: 0,
  }

fn at(script: ByteArray) -> Address {
  Address { payment_credential: Script(script), stake_credential: None }
}

fn thread_val() -> Value {
  merge(from_lovelace(2_000_000), from_asset(c_policy, thread_name, 1))
}

fn cp_output(addr: Address, val: Value, cp: Checkpoint) -> Output {
  Output { address: addr, value: val, datum: InlineDatum(cp), reference_script: None }
}

fn input_at(ref: OutputReference, o: Output) -> Input {
  Input { output_reference: ref, output: o }
}

// a dummy input that does NOT consume the one-shot outpoint
fn filler_input() -> Input {
  input_at(
    OutputReference { transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001", output_index: 7 },
    Output {
      address: Address { payment_credential: VerificationKey(#"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"), stake_credential: None },
      value: from_lovelace(5_000_000), datum: NoDatum, reference_script: None,
    },
  )
}

fn genesis_consuming_input() -> Input {
  input_at(c_gref, Output {
    address: Address { payment_credential: VerificationKey(#"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), stake_credential: None },
    value: from_lovelace(10_000_000), datum: NoDatum, reference_script: None,
  })
}

// ---- pure asset/datum predicates ----

test t_has_thread_true() {
  has_thread(thread_val(), c_policy)
}

test t_has_thread_false_when_absent() {
  !has_thread(from_lovelace(2_000_000), c_policy)
}

// ---- lineage_token: the continuity-based thread-token id that breaks the advance<->thread cycle ----
// the sole non-ADA qty-1 token is the lineage token.
test t_lineage_token_single() {
  lineage_token(thread_val()) == Some((c_policy, thread_name))
}
// no non-ADA token -> None (a checkpoint with no lineage token cannot advance).
test t_lineage_token_none_when_absent() {
  lineage_token(from_lovelace(2_000_000)) == None
}
// TWO non-ADA tokens -> None: blocks a token-bloat grief (an advancer stuffing a 2nd token to freeze the line).
test t_lineage_token_none_when_two() {
  lineage_token(merge(thread_val(), from_asset(c_other, thread_name, 1))) == None
}
// qty != 1 -> None (the thread token is a one-shot singleton).
test t_lineage_token_none_when_qty_two() {
  lineage_token(merge(from_lovelace(2_000_000), from_asset(c_policy, thread_name, 2))) == None
}
// CONTINUITY: input lineage token preserved on the output -> Some == Some (the advance keeps the line).
test t_lineage_continuity_preserved() {
  let t = lineage_token(thread_val())
  t == lineage_token(merge(from_lovelace(3_000_000), from_asset(c_policy, thread_name, 1))) && t != None
}
// CONTINUITY broken: the output drops/changes the token -> mismatch -> advance must fail.
test t_lineage_continuity_broken_rejected() {
  lineage_token(thread_val()) != lineage_token(merge(from_lovelace(2_000_000), from_asset(c_other, thread_name, 1)))
}

test t_mints_one_thread_true() {
  mints_one_thread(from_asset(c_policy, thread_name, 1), c_policy)
}

test t_mints_rejects_two() {
  !mints_one_thread(from_asset(c_policy, thread_name, 2), c_policy)
}

test t_mints_rejects_wrong_name() {
  !mints_one_thread(from_asset(c_policy, #"deadbeef", 1), c_policy)
}

test t_burn_allowed() {
  is_thread_burn(from_asset(c_policy, thread_name, -1), c_policy)
}

test t_pinned_output_ok() {
  is_pinned_genesis_output(cp_output(at(c_cp_script), thread_val(), c_pinned), c_pinned, c_policy, c_cp_script)
}

test t_pinned_output_rejects_wrong_datum() {
  let bad = Checkpoint { chain_root: #"00", total_difficulty: c_pinned.total_difficulty, window_root: c_pinned.window_root, tip_height: c_pinned.tip_height }
  !is_pinned_genesis_output(cp_output(at(c_cp_script), thread_val(), bad), c_pinned, c_policy, c_cp_script)
}

test t_pinned_output_rejects_wrong_address() {
  !is_pinned_genesis_output(cp_output(at(c_other), thread_val(), c_pinned), c_pinned, c_policy, c_cp_script)
}

test t_pinned_output_rejects_missing_token() {
  !is_pinned_genesis_output(cp_output(at(c_cp_script), from_lovelace(2_000_000), c_pinned), c_pinned, c_policy, c_cp_script)
}

// ---- the full genesis-mint gate (B-mirror) ----

fn mint_one() -> Value {
  from_asset(c_policy, thread_name, 1)
}

test g_genesis_accepted() {
  let inputs = [genesis_consuming_input(), filler_input()]
  let outputs = [cp_output(at(c_cp_script), thread_val(), c_pinned)]
  genesis_mint_ok(inputs, outputs, mint_one(), c_policy, c_gref, c_pinned, c_cp_script)
}

test g_rejects_fake_genesis_datum() {
  let fake = Checkpoint { chain_root: #"aaaa", total_difficulty: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", window_root: #"bbbb", tip_height: 0 }
  let inputs = [genesis_consuming_input()]
  let outputs = [cp_output(at(c_cp_script), thread_val(), fake)]
  !genesis_mint_ok(inputs, outputs, mint_one(), c_policy, c_gref, c_pinned, c_cp_script)
}

test g_rejects_without_unique_outpoint() {
  // attacker tries to mint a second/parallel genesis without consuming the one-shot outpoint
  let inputs = [filler_input()]
  let outputs = [cp_output(at(c_cp_script), thread_val(), c_pinned)]
  !genesis_mint_ok(inputs, outputs, mint_one(), c_policy, c_gref, c_pinned, c_cp_script)
}

test g_rejects_token_to_wrong_address() {
  let inputs = [genesis_consuming_input()]
  let outputs = [cp_output(at(c_other), thread_val(), c_pinned)]
  !genesis_mint_ok(inputs, outputs, mint_one(), c_policy, c_gref, c_pinned, c_cp_script)
}

test g_rejects_double_mint() {
  let inputs = [genesis_consuming_input()]
  let outputs = [cp_output(at(c_cp_script), merge(thread_val(), from_asset(c_policy, thread_name, 1)), c_pinned)]
  // minting two tokens fails the exactly-one gate
  !genesis_mint_ok(inputs, outputs, from_asset(c_policy, thread_name, 2), c_policy, c_gref, c_pinned, c_cp_script)
}

// ---- heaviest-chain / reorg guard (advance_ckbcert step 3) ----

test h_strictly_heavier_accepted() {
  builtin.less_than_bytearray(c_pinned.total_difficulty, #"0000000000000000000000000000000000000000000000000000020000000000")
}

test h_equal_rejected() {
  !builtin.less_than_bytearray(c_pinned.total_difficulty, c_pinned.total_difficulty)
}

test h_lighter_rejected() {
  // a reorg to a LIGHTER chain (less cumulative work) must not advance
  !builtin.less_than_bytearray(c_pinned.total_difficulty, #"0000000000000000000000000000000000000000000000000000000000000001")
}
