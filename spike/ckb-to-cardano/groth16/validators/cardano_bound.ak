//// cardano_bound.ak — the CKB-anchored binding lock (mirror of the CKB BoundAsset). The Cardano
//// UTxO is the FOLLOWER: its state transitions only if a Groth16 proof attests that the CKB seal
//// (the anchor, a single-use CKB cell) was spent in a sufficiently-confirmed CKB block committing
//// to the new Cardano state. The SNARK verifying key is a compile-time parameter; the public inputs
//// bind (ckb_checkpoint_root, seal, commitment). Cardano verifies CKB here — the symmetric leg.
////
//// SECURITY FIXES (this revision):
////  - B4: `ckb_checkpoint_root` is NO LONGER taken from the redeemer. It is read from the canonical,
////        genesis-pinned checkpoint UTxO (carrying the `checkpoint_nft` thread token) via a REFERENCE
////        INPUT, so a relayer can't prove against an arbitrary/forged root.
////  - B2/D1: `field_of` matches the circuit's little-endian, no-rehash packing (`from_le_bytes_mod_order`).
////  - B6: Finalize no longer binds the commitment slot to a shared constant `#""`; it binds a
////        seal-specific finalize commitment (must match the circuit's finalize public input).
////  - B8: a Transition must PRESERVE the follower UTxO's value (no draining during a transition).
use aiken/builtin
use aiken/collection/list
use cardano/assets.{PolicyId, lovelace_of}
use cardano/transaction.{Transaction, OutputReference, Output, Input, InlineDatum}
use g16/verifier.{VerifyingKey, Proof, verify}
use g16/ckbcert.{Checkpoint, has_thread, fr_order}

pub type BoundState {
  ckb_seal: ByteArray,   // the CKB anchor cell (type-id / outpoint) — single-use
  state: ByteArray,      // the app state mirrored on Cardano
}

pub type Action {
  Transition { proof: Proof, new_state: ByteArray, public_inputs: List<Int> }
  Finalize { proof: Proof, public_inputs: List<Int> }
}

fn commitment(new_state: ByteArray, seal: ByteArray) -> ByteArray {
  builtin.blake2b_256(builtin.append_bytearray(new_state, seal))
}
// SEC B2/D1: little-endian, NO re-hash — identical to the circuit's `Fr::from_le_bytes_mod_order`.
// SEC D1b: reduce mod the BLS scalar field order — a 32-byte hash exceeds r ~55% of the time and the
// prover's public input is the reduced residue, so the binding must compare against the reduced residue too.
fn field_of(b: ByteArray) -> Int { builtin.bytearray_to_integer(False, b) % fr_order }

// SEC B6: a distinct, seal-bound finalize commitment (not the shared constant `#""`). The finalize circuit
// must expose field_of(this) as public_inputs[2].
fn finalize_commitment(seal: ByteArray) -> ByteArray {
  builtin.blake2b_256(builtin.append_bytearray(#"46494e", seal)) // "FIN" || seal
}

// RESTRUCTURE.md: the Transition leap proves membership against the WINDOW root and carries the
// authenticated tip_height (PI #3) for its in-circuit height-bound, so it binds 4 public inputs.
fn inputs_bind_w(pi: List<Int>, wroot: ByteArray, seal: ByteArray, comm: ByteArray, tip: Int) -> Bool {
  pi == [field_of(wroot), field_of(seal), field_of(comm), tip]
}

// SEC B4: the canonical checkpoint = the genesis-pinned checkpoint UTxO (the one carrying the thread NFT),
// read as a REFERENCE INPUT. Fails if absent — the relayer cannot supply checkpoint state.
fn canonical_cp(tx: Transaction, nft: PolicyId) -> Checkpoint {
  expect Some(cp_in) =
    list.find(tx.reference_inputs, fn(i: Input) { has_thread(i.output.value, nft) })
  expect InlineDatum(d) = cp_in.output.datum
  expect c: Checkpoint = d
  c
}

// the continuing follower output (same address) — returns its datum AND value (for the B8 value check).
fn continuing(tx: Transaction, own: OutputReference) -> Option<(BoundState, Int)> {
  expect Some(self_in) = list.find(tx.inputs, fn(i) { i.output_reference == own })
  let addr = self_in.output.address
  let in_lovelace = lovelace_of(self_in.output.value)
  // SEC N1: require EXACTLY ONE continuing output at the script address (a decoy second output at the same
  // address can no longer ride alongside the validated one).
  when list.filter(tx.outputs, fn(o: Output) { o.address == addr }) is {
    [o] ->
      when o.datum is {
        InlineDatum(d) -> {
          expect bs: BoundState = d
          // SEC B8: the continuing output must preserve (≥) the follower's ADA — no draining on transition.
          if lovelace_of(o.value) >= in_lovelace {
            Some((bs, lovelace_of(o.value)))
          } else {
            None
          }
        }
        _ -> None
      }
    _ -> None
  }
}

// SEC N-2: the Finalize branch is verified against its OWN verifying key (`finalize_vk`). The transition
// circuit and the finalize circuit have different R1CS (the finalize circuit computes the seal-specific
// commitment blake2b256("FIN"||seal) in-circuit), hence distinct vks. With a single shared vk the Finalize
// branch was unprovable (no proof satisfied both that vk and the FIN-commitment binding); a dedicated
// finalize_vk makes it a first-class, independently-attested action.
validator cardano_bound(vk: VerifyingKey, finalize_vk: VerifyingKey, checkpoint_nft: PolicyId) {
  spend(datum: Option<BoundState>, action: Action, own: OutputReference, tx: Transaction) {
    expect Some(st) = datum
    let cp = canonical_cp(tx, checkpoint_nft) // SEC B4: canonical, not redeemer-supplied
    when action is {
      Transition { proof, new_state, public_inputs } -> {
        let snark_ok = verify(vk, proof, public_inputs)
        let cont_ok =
          when continuing(tx, own) is {
            Some((BoundState { ckb_seal, state }, _v)) -> ckb_seal == st.ckb_seal && state == new_state
            None -> False
          }
        let bound_ok =
          inputs_bind_w(public_inputs, cp.window_root, st.ckb_seal, commitment(new_state, st.ckb_seal), cp.tip_height)
        snark_ok && cont_ok && bound_ok
      }
      Finalize { proof, public_inputs } -> {
        let snark_ok = verify(finalize_vk, proof, public_inputs)
        let no_cont = continuing(tx, own) == None
        let bound_ok = inputs_bind_w(public_inputs, cp.window_root, st.ckb_seal, finalize_commitment(st.ckb_seal), cp.tip_height)
        snark_ok && no_cont && bound_ok
      }
    }
  }
  else(_) { fail }
}
