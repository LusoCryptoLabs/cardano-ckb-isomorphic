//// advance_ckbcert.ak — the TRUSTLESS, GENESIS-PINNED CKB light-client checkpoint on Cardano (mirror of
//// the Mithril AdvanceCert + its genesis pin). A checkpoint UTxO holds {chain_root, total_difficulty} and
//// carries a one-shot THREAD TOKEN (minted once at the pinned genesis by ckbcert_thread). Anyone may
//// ADVANCE it by supplying a Groth16 proof that a new chain root extends the old one with a valid PoW
//// chain whose CUMULATIVE DIFFICULTY is `new_total_difficulty` (the circuit enforces each header's PoW +
//// parent linking + difficulty = 2^256/target + the running sum). The validator accepts ONLY if: the
//// proof verifies, the public inputs bind this old->new transition, the new chain has STRICTLY MORE work
//// (Nakamoto heaviest-chain), AND the thread token is preserved on the continuing checkpoint. The thread
//// token ties every advance to the single pinned-genesis lineage, so a fake checkpoint (attacker-chosen
//// genesis, no token) cannot be advanced. R2 membership (cardano_bound.ak) then reads this root.
use aiken/builtin
use aiken/collection/list
use cardano/assets.{PolicyId, Value}
use cardano/transaction.{Transaction, OutputReference, Output, InlineDatum}
use g16/verifier.{VerifyingKey, Proof, verify}
use g16/ckbcert.{Checkpoint, field_of, has_thread}

pub type Advance {
  proof: Proof,
  new_chain_root: ByteArray,
  new_total_difficulty: ByteArray,
  public_inputs: List<Int>,       // = field encodings of (old_root, old_diff, new_root, new_diff)
}

validator advance_ckbcert(vk: VerifyingKey, thread_policy: PolicyId) {
  spend(datum: Option<Checkpoint>, redeemer: Advance, own: OutputReference, tx: Transaction) {
    expect Some(cp) = datum
    let Advance { proof, new_chain_root, new_total_difficulty, public_inputs } = redeemer
    // SEC B7: pin lengths to 32 bytes so the big-endian `less_than_bytearray` heaviest-chain compare is a
    // true numeric compare — a shorter, lexicographically-greater-but-numerically-smaller value (a lighter
    // chain) can no longer advance the checkpoint.
    expect builtin.length_of_bytearray(new_total_difficulty) == 32
    expect builtin.length_of_bytearray(new_chain_root) == 32
    expect builtin.length_of_bytearray(cp.total_difficulty) == 32
    // 0) GENESIS PIN: the checkpoint being advanced must carry the one-shot thread token. Only the
    //    lineage seeded by ckbcert_thread at the pinned genesis has it, so attacker-seeded checkpoints
    //    (fake genesis) are unspendable as a checkpoint here.
    expect Some(self_in) = list.find(tx.inputs, fn(i) { i.output_reference == own })
    let thread_in = has_thread(self_in.output.value, thread_policy)
    // 1) the SNARK proves: new_chain_root extends old via a valid PoW chain with the claimed work delta.
    let snark_ok = verify(vk, proof, public_inputs)
    // 2) the public inputs bind THIS advance (old + new state) — anti-replay / anti-forgery.
    let bound_ok =
      public_inputs == [
        field_of(cp.chain_root), field_of(cp.total_difficulty),
        field_of(new_chain_root), field_of(new_total_difficulty),
      ]
    // 3) HEAVIEST CHAIN: only advance to strictly more cumulative work (32B big-endian compare).
    let heavier = builtin.less_than_bytearray(cp.total_difficulty, new_total_difficulty)
    // 4) exactly one continuing checkpoint output carries the advanced state AND keeps the thread token.
    let cont_ok =
      when continuing(tx, self_in.output) is {
        Some((out_value, Checkpoint { chain_root, total_difficulty })) ->
          chain_root == new_chain_root && total_difficulty == new_total_difficulty && has_thread(
            out_value,
            thread_policy,
          )
        None -> False
      }
    thread_in && snark_ok && bound_ok && heavier && cont_ok
  }

  else(_) {
    fail
  }
}

/// The continuing checkpoint output (same address as the spent checkpoint): returns its value + datum.
fn continuing(tx: Transaction, self_out: Output) -> Option<(Value, Checkpoint)> {
  let addr = self_out.address
  // SEC N1: exactly ONE continuing checkpoint output at the address (no decoy second checkpoint output).
  when list.filter(tx.outputs, fn(o: Output) { o.address == addr }) is {
    [o] ->
      when o.datum is {
        InlineDatum(d) -> {
          expect c: Checkpoint = d
          Some((o.value, c))
        }
        _ -> None
      }
    _ -> None
  }
}
