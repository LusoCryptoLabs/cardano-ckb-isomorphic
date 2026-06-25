//// ada_escrow.ak - the χADA leg's CARDANO side (spike/cardano-to-ckb-zk/XADA_LEG.md). A user LOCKS lovelace
//// at this script with an inline `EscrowDatum` that commits the CKB recipient + amount; that escrow output is
//// the canonical lock receipt the CKB `xada_mint` type script reads (Mithril-certified) to mint χADA. This
//// validator governs the RETURN leg: it RELEASES the locked ADA iff a Groth16 proof attests that the matching
//// χADA was BURNED on CKB (deep enough, to the named Cardano recipient). It is the mirror of `cardano_bound`
//// (Cardano-verifies-CKB) - same g16 verifier, same genesis-pinned CKB-header checkpoint, same 5-input
//// binding, same governance-K - but the bound fact is a BURN→RELEASE (amount ‖ cardano_recipient) instead of
//// a lock→mint, and the released ADA must actually be paid to that recipient.
////
//// Replay-once: the CKB burn `seal` (a single-use CKB cell) must be nullified EXACTLY ONCE in the genesis-
//// pinned Cardano seal registry (found by its NFT), so one burn can drain at most one escrow across all txs -
//// the same defense `leap_mint_guard.seal_consumed` gives the forward mint.
use aiken/builtin
use aiken/collection/list
use aiken/collection/pairs
use cardano/address.{Script, VerificationKey}
use cardano/assets.{PolicyId, lovelace_of, quantity_of}
use cardano/transaction.{Transaction, OutputReference, Output, Input, InlineDatum, Spend}
use g16/verifier.{VerifyingKey, Proof, verify}
use g16/ckbcert.{Checkpoint, has_thread, fr_order}
use g16/seal_set.{Insert}
use leap_guard.{PolicyState}

// the FORWARD binding: what `xada_mint` reads off the certified escrow output.
//   ckb_recipient = the 32-byte CKB lock hash the χADA is minted to
//   amount        = lovelace locked (== the output coin; xada_mint cross-checks)
pub type EscrowDatum {
  ckb_recipient: ByteArray,
  amount: Int,
  nonce: Int,
}

// the RETURN action: release the locked ADA against a proven CKB χADA-burn.
//   cardano_recipient = 28-byte payment credential to receive the released ADA (bound into the proof)
//   burn_seal         = the single-use CKB burn cell (nullified once; folded into the commitment)
pub type Action {
  Release { proof: Proof, cardano_recipient: ByteArray, burn_seal: ByteArray, public_inputs: List<Int> }
}

// SEC: little-endian, no re-hash, reduced mod r - identical to cardano_bound.field_of (the circuit packing).
fn field_of(b: ByteArray) -> Int { builtin.bytearray_to_integer(False, b) % fr_order }

// the bound burn fact, mirror of leap_mint_guard's financial state: amount(16 LE) ‖ recipient(28) = 44 bytes.
fn burn_state(amount: Int, recipient: ByteArray) -> ByteArray {
  builtin.append_bytearray(builtin.integer_to_bytearray(False, 16, amount), recipient)
}
// commitment = blake2b256(state ‖ seal) - identical shape to cardano_bound.commitment(new_state, seal).
fn commitment(state: ByteArray, seal: ByteArray) -> ByteArray {
  builtin.blake2b_256(builtin.append_bytearray(state, seal))
}
// the 5 public inputs the burn circuit exposes: (window_root, seal, commitment, tip, K) - same order as
// cardano_bound.inputs_bind_w, so the deployed circuit/verifier stack is reused unchanged.
fn inputs_bind(pi: List<Int>, wroot: ByteArray, seal: ByteArray, comm: ByteArray, tip: Int, k: Int) -> Bool {
  pi == [field_of(wroot), field_of(seal), field_of(comm), tip, k]
}

// SEC B4 (verbatim from cardano_bound): the canonical CKB-header checkpoint, read as a REFERENCE INPUT located
// by the genesis thread NFT - never relayer-supplied. Fails closed if absent/duplicated.
fn canonical_cp(tx: Transaction, nft: PolicyId) -> Checkpoint {
  expect [cp_in] =
    list.filter(tx.reference_inputs, fn(i: Input) { has_thread(i.output.value, nft) })
  expect InlineDatum(d) = cp_in.output.datum
  expect c: Checkpoint = d
  c
}

// SEC D6 floor: k_min must equal the leap circuit's baked confirmation floor (leap_bound_windowed kmin=12).
const k_min: Int = 12
// SEC D6 (verbatim from cardano_bound): governance confirmation depth K from the NFT'd PolicyState pinned to
// the chiral_policy script hash, re-bounded to [k_min,32]. The CKB burn must be K-deep - the same reorg defense.
fn read_k(tx: Transaction, policy_nft: PolicyId, policy_name: ByteArray, policy_script: ByteArray) -> Int {
  expect [p_in] =
    list.filter(
      tx.reference_inputs,
      fn(i: Input) {
        quantity_of(i.output.value, policy_nft, policy_name) == 1 && when i.output.address.payment_credential is {
          Script(h) -> h == policy_script
          _ -> False
        }
      },
    )
  expect InlineDatum(d) = p_in.output.datum
  expect ps: PolicyState = d
  let k = ps.policy.min_confirmations
  expect k >= k_min && k <= 32
  k
}

// SEC N-FIN-1 (verbatim shape from leap_mint_guard): the burn seal must be CONSUMED once in the genesis-pinned
// seal registry, found by its NFT (not script hash), so one CKB burn releases at most one escrow across all txs.
fn seal_consumed(tx: Transaction, registry_nft: PolicyId, seal: ByteArray) -> Bool {
  when list.filter(tx.inputs, fn(i: Input) { has_thread(i.output.value, registry_nft) }) is {
    [reg_in] ->
      when pairs.get_first(tx.redeemers, Spend(reg_in.output_reference)) is {
        Some(rd) -> {
          expect ins: Insert = rd
          ins.key == seal
        }
        None -> False
      }
    _ -> False
  }
}

// the released ADA must actually be PAID to the bound recipient credential (key or script), ≥ amount.
fn pays(tx: Transaction, recipient: ByteArray, amount: Int) -> Bool {
  let total =
    list.foldl(tx.outputs, 0, fn(o: Output, acc: Int) {
      let h = when o.address.payment_credential is {
        Script(x) -> x
        VerificationKey(x) -> x
      }
      if h == recipient { acc + lovelace_of(o.value) } else { acc }
    })
  total >= amount
}

validator ada_escrow(
  vk: VerifyingKey,
  checkpoint_nft: PolicyId,
  seal_registry_nft: PolicyId,
  policy_nft: PolicyId,
  policy_name: ByteArray,
  policy_script: ByteArray,
) {
  spend(datum: Option<EscrowDatum>, action: Action, _own: OutputReference, tx: Transaction) {
    expect Some(esc) = datum
    expect esc.amount > 0
    when action is {
      Release { proof, cardano_recipient, burn_seal, public_inputs } -> {
        expect builtin.length_of_bytearray(burn_seal) == 32
        expect builtin.length_of_bytearray(cardano_recipient) == 28
        let cp = canonical_cp(tx, checkpoint_nft)
        let k = read_k(tx, policy_nft, policy_name, policy_script)
        let state = burn_state(esc.amount, cardano_recipient)
        let comm = commitment(state, burn_seal)
        // (1) the Groth16 proof attests a CKB burn of THIS amount to THIS recipient, K-deep under the checkpoint.
        let snark_ok = verify(vk, proof, public_inputs)
        let bound_ok = inputs_bind(public_inputs, cp.window_root, burn_seal, comm, cp.tip_height, k)
        // (2) replay-once: the burn seal nullified exactly once in the canonical registry.
        let once_ok = seal_consumed(tx, seal_registry_nft, burn_seal)
        // (3) the locked ADA is actually released to the bound recipient.
        let pay_ok = pays(tx, cardano_recipient, esc.amount)
        snark_ok && bound_ok && once_ok && pay_ok
      }
    }
  }
  else(_) { fail }
}

// ---- tests for the pure binding logic (the SNARK verify itself is exercised by the g16 verifier_test suites;
// here we pin the commitment/binding/payout/replay wiring the release depends on, mirroring cardano_bound). ----
const t_wr: ByteArray = #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const t_seal: ByteArray = #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"
const t_recip: ByteArray = #"33333333333333333333333333333333333333333333333333333333"   // 28B
const t_reg_nft: PolicyId = #"88888888888888888888888888888888888888888888888888888888"
const t_reg_addr: ByteArray = #"22222222222222222222222222222222222222222222222222222222"
const t_thread_name: ByteArray = #"636b62636572742d746872656164"
const t_reg_oref: OutputReference =
  OutputReference { transaction_id: #"00000000000000000000000000000000000000000000000000000000000000bb", output_index: 0 }

// burn_state packs amount little-endian into 16 bytes then appends the 28-byte recipient (44 total).
test burn_state_layout() {
  let s = burn_state(100, t_recip)
  builtin.length_of_bytearray(s) == 44 && builtin.slice_bytearray(16, 28, s) == t_recip && builtin.bytearray_to_integer(False, builtin.slice_bytearray(0, 16, s)) == 100
}

// the 5-input binding accepts the matching tuple and rejects a wrong amount (which changes the commitment)…
test inputs_bind_match_ok() {
  let comm = commitment(burn_state(100, t_recip), t_seal)
  inputs_bind([field_of(t_wr), field_of(t_seal), field_of(comm), 4371186, 12], t_wr, t_seal, comm, 4371186, 12)
}
test inputs_bind_amount_mismatch_rejected() {
  // proof claims amount 100, but a relayer tries to drain an escrow bound to 999 -> commitment differs -> reject.
  let comm_100 = commitment(burn_state(100, t_recip), t_seal)
  let comm_999 = commitment(burn_state(999, t_recip), t_seal)
  !inputs_bind([field_of(t_wr), field_of(t_seal), field_of(comm_100), 4371186, 12], t_wr, t_seal, comm_999, 4371186, 12)
}
// …and a wrong K (governance pinned) is rejected even with a matching commitment.
test inputs_bind_k_mismatch_rejected() {
  let comm = commitment(burn_state(100, t_recip), t_seal)
  !inputs_bind([field_of(t_wr), field_of(t_seal), field_of(comm), 4371186, 12], t_wr, t_seal, comm, 4371186, 11)
}

fn reg_input() -> Input {
  Input {
    output_reference: t_reg_oref,
    output: Output { address: address.Address { payment_credential: Script(t_reg_addr), stake_credential: None }, value: assets.from_asset(t_reg_nft, t_thread_name, 1), datum: transaction.NoDatum, reference_script: None },
  }
}
fn tx_consuming_seal(key: ByteArray) -> Transaction {
  let ins: Data = Insert { key, sibs: [] }
  Transaction { ..transaction.placeholder, inputs: [reg_input()], redeemers: [Pair(Spend(t_reg_oref), ins)] }
}

test seal_consumed_reads_redeemer() {
  seal_consumed(tx_consuming_seal(t_seal), t_reg_nft, t_seal)
}
test seal_consumed_rejects_wrong_key() {
  !seal_consumed(tx_consuming_seal(#"dead0000000000000000000000000000000000000000000000000000000000ff"), t_reg_nft, t_seal)
}
// continuity defense: querying by an NFT no input carries finds nothing -> reject (no decoy registry).
test seal_consumed_rejects_decoy_nft() {
  !seal_consumed(tx_consuming_seal(t_seal), #"99999999999999999999999999999999999999999999999999999999", t_seal)
}

fn pay_out(h: ByteArray, lov: Int) -> Output {
  Output { address: address.Address { payment_credential: VerificationKey(h), stake_credential: None }, value: assets.from_lovelace(lov), datum: transaction.NoDatum, reference_script: None }
}
test pays_exact_ok() {
  pays(Transaction { ..transaction.placeholder, outputs: [pay_out(t_recip, 100)] }, t_recip, 100)
}
test pays_underpay_rejected() {
  !pays(Transaction { ..transaction.placeholder, outputs: [pay_out(t_recip, 99)] }, t_recip, 100)
}
test pays_wrong_recipient_rejected() {
  !pays(Transaction { ..transaction.placeholder, outputs: [pay_out(#"44444444444444444444444444444444444444444444444444444444", 100)] }, t_recip, 100)
}
