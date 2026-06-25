//// cardano_bound.ak - the CKB-anchored binding lock (mirror of the CKB BoundAsset). The Cardano
//// UTxO is the FOLLOWER: its state transitions only if a Groth16 proof attests that the CKB seal
//// (the anchor, a single-use CKB cell) was spent in a sufficiently-confirmed CKB block committing
//// to the new Cardano state. The SNARK verifying key is a compile-time parameter; the public inputs
//// bind (ckb_checkpoint_root, seal, commitment). Cardano verifies CKB here - the symmetric leg.
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
use cardano/address.{Script}
use cardano/assets.{PolicyId, lovelace_of, quantity_of}
use cardano/transaction.{Transaction, OutputReference, Output, Input, InlineDatum}
use g16/verifier.{VerifyingKey, Proof, verify}
use g16/ckbcert.{Checkpoint, has_thread, fr_order}
use leap_guard.{PolicyState}

pub type BoundState {
  ckb_seal: ByteArray,   // the CKB anchor cell (type-id / outpoint) - single-use
  state: ByteArray,      // the app state mirrored on Cardano
}

pub type Action {
  Transition { proof: Proof, new_state: ByteArray, public_inputs: List<Int> }
  Finalize { proof: Proof, public_inputs: List<Int> }
}

fn commitment(new_state: ByteArray, seal: ByteArray) -> ByteArray {
  builtin.blake2b_256(builtin.append_bytearray(new_state, seal))
}
// SEC B2/D1: little-endian, NO re-hash - identical to the circuit's `Fr::from_le_bytes_mod_order`.
// SEC D1b: reduce mod the BLS scalar field order - a 32-byte hash exceeds r ~55% of the time and the
// prover's public input is the reduced residue, so the binding must compare against the reduced residue too.
fn field_of(b: ByteArray) -> Int { builtin.bytearray_to_integer(False, b) % fr_order }

// SEC B6: a distinct, seal-bound finalize commitment (not the shared constant `#""`). The finalize circuit
// must expose field_of(this) as public_inputs[2].
fn finalize_commitment(seal: ByteArray) -> ByteArray {
  builtin.blake2b_256(builtin.append_bytearray(#"46494e", seal)) // "FIN" || seal
}

// RESTRUCTURE.md + SEC D6: the Transition leap proves membership against the WINDOW root and carries the
// authenticated tip_height (PI #4) AND the confirmation depth K (PI #5), so it binds 5 public inputs. K is
// pinned LAST, raw (no field_of - it is a small int, matching the circuit's Fr::from(k)), identically in
// Transition and Finalize, so a relayer cannot prove a smaller K than governance set.
fn inputs_bind_w(pi: List<Int>, wroot: ByteArray, seal: ByteArray, comm: ByteArray, tip: Int, k: Int) -> Bool {
  pi == [field_of(wroot), field_of(seal), field_of(comm), tip, k]
}

// SEC D6 (MF-1): read the confirmation depth K from the governor-signed policy cell (a PolicyState carrying
// the ONE-SHOT policy NFT minted by chiral_policy_thread), as a REFERENCE INPUT located by that NFT AND
// pinned to the chiral_policy script hash. NEVER from the checkpoint (permissionless advance) or the redeemer.
// The one-shot NFT makes the cell unforgeable; the script-hash pin ensures it is the cell governed by
// chiral_policy.spend; the in-line range assert re-bounds K so even a stray/forged datum cannot push K out of
// the sane [k_min,32] band. Fails-closed (exactly-one) if absent/duplicated - K must be authoritative.
// SEC D6 floor: k_min must equal the leap circuit's baked confirmation floor (leap_bound_windowed kmin=12).
const k_min: Int = 12
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

// SEC B4: the canonical checkpoint = the genesis-pinned checkpoint UTxO (the one carrying the thread NFT),
// read as a REFERENCE INPUT. Fails if absent - the relayer cannot supply checkpoint state.
fn canonical_cp(tx: Transaction, nft: PolicyId) -> Checkpoint {
  // SEC: EXACTLY ONE reference input may carry the thread NFT (the canonical tip). The NFT-uniqueness
  // invariant is enforced on the spend/mint paths; a reference read re-asserts single-source (defense-in-depth).
  expect [cp_in] =
    list.filter(tx.reference_inputs, fn(i: Input) { has_thread(i.output.value, nft) })
  expect InlineDatum(d) = cp_in.output.datum
  expect c: Checkpoint = d
  c
}

// the continuing follower output (same address) - returns its datum AND value (for the B8 value check).
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
          // SEC B8: the continuing output must preserve (≥) the follower's ADA - no draining on transition.
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
validator cardano_bound(
  vk: VerifyingKey,
  finalize_vk: VerifyingKey,
  checkpoint_nft: PolicyId,
  policy_nft: PolicyId,
  policy_name: ByteArray,
  policy_script: ByteArray,
) {
  spend(datum: Option<BoundState>, action: Action, own: OutputReference, tx: Transaction) {
    expect Some(st) = datum
    // SEC D6: pin the seal to the 32-byte CKB nullifier-key domain (the seal is byte-bound through the
    // commitment hash; this just matches the nullifier key length and rejects malformed BoundStates).
    expect builtin.length_of_bytearray(st.ckb_seal) == 32
    let cp = canonical_cp(tx, checkpoint_nft) // SEC B4: canonical, not redeemer-supplied
    let k = read_k(tx, policy_nft, policy_name, policy_script) // SEC D6: confirmation depth, governance-pinned
    when action is {
      Transition { proof, new_state, public_inputs } -> {
        let snark_ok = verify(vk, proof, public_inputs)
        let cont_ok =
          when continuing(tx, own) is {
            Some((BoundState { ckb_seal, state }, _v)) -> ckb_seal == st.ckb_seal && state == new_state
            None -> False
          }
        let bound_ok =
          inputs_bind_w(public_inputs, cp.window_root, st.ckb_seal, commitment(new_state, st.ckb_seal), cp.tip_height, k)
        snark_ok && cont_ok && bound_ok
      }
      Finalize { proof, public_inputs } -> {
        let snark_ok = verify(finalize_vk, proof, public_inputs)
        let no_cont = continuing(tx, own) == None
        let bound_ok = inputs_bind_w(public_inputs, cp.window_root, st.ckb_seal, finalize_commitment(st.ckb_seal), cp.tip_height, k)
        snark_ok && no_cont && bound_ok
      }
    }
  }
  else(_) { fail }
}

// ---- SEC D6 (MF-3) tests: K-binding + governance K source (the SNARK verify itself is exercised on-chain
// by the *_test.ak suites; here we pin the read_k / inputs_bind_w logic the design required). ----
const tk_nft: PolicyId = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a"
const tk_name: ByteArray = #"636b62636572742d746872656164"
const tk_script: ByteArray = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2b"
const tk_wr: ByteArray = #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const tk_seal: ByteArray = #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const tk_comm: ByteArray = #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

fn pstate(k: Int) -> PolicyState {
  PolicyState {
    governor: #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    policy: leap_guard.GuardPolicy { paused_global: False, paused_in: False, paused_out: False, min_amount: 0, max_amount: 0, min_confirmations: k },
  }
}

fn policy_ref(at_script: ByteArray, with_nft: Bool, k: Int) -> Input {
  let v = if with_nft { assets.from_asset(tk_nft, tk_name, 1) } else { assets.from_lovelace(2) }
  Input {
    output_reference: OutputReference { transaction_id: #"00000000000000000000000000000000000000000000000000000000000000dd", output_index: 0 },
    output: Output {
      address: address.Address { payment_credential: Script(at_script), stake_credential: None },
      value: v, datum: InlineDatum(pstate(k)), reference_script: None,
    },
  }
}

fn tx_with_policy(ref: Input) -> Transaction {
  Transaction { ..transaction.placeholder, reference_inputs: [ref] }
}

// governance K (12) is read from the NFT'd PolicyState at the chiral_policy script hash.
test read_k_returns_governance_k() {
  read_k(tx_with_policy(policy_ref(tk_script, True, 12)), tk_nft, tk_name, tk_script) == 12
}

// SEC D6 / D6:70-71 - a proof carrying K=12 is REJECTED when governance K (pinned last) is 11 (or any other).
test bind_k_mismatch_rejected() {
  let pi = [field_of(tk_wr), field_of(tk_seal), field_of(tk_comm), 100, 12]
  !inputs_bind_w(pi, tk_wr, tk_seal, tk_comm, 100, 11)
}
test bind_k_match_ok() {
  let pi = [field_of(tk_wr), field_of(tk_seal), field_of(tk_comm), 100, 12]
  inputs_bind_w(pi, tk_wr, tk_seal, tk_comm, 100, 12)
}
// tip mismatch also rejected (the proof's tip must equal the canonical checkpoint tip).
test bind_tip_mismatch_rejected() {
  let pi = [field_of(tk_wr), field_of(tk_seal), field_of(tk_comm), 100, 12]
  !inputs_bind_w(pi, tk_wr, tk_seal, tk_comm, 99, 12)
}
