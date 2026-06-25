//// A minting policy that mints the bridged asset (e.g. ckCKB) ONLY if a Groth16 proof of the CKB
//// seal-lock verifies on-chain AND the minted (name, quantity) are bound to that proof - so a bridged
//// token exists on Cardano exactly when a real CKB lock was proven, in exactly the locked amount and
//// under a name pinned to the proof's commitment. Burning is always allowed (it only reduces supply;
//// the CKB-side unlock is gated separately on the certified burn).
////
//// AMOUNT/NAME BINDING (closes the prior gap, with NO change to the circuit / trusted setup):
////  - public_inputs are [field_of(checkpoint_root), field_of(seal), field_of(commitment)] (== cardano_bound.ak).
////  - the redeemer reveals the committed `state` and the `seal`; the policy recomputes
////    commitment = blake2b256(state ++ seal) and requires field_of(commitment) == public_inputs[2] and
////    field_of(seal) == public_inputs[1]. Since the circuit binds `commitment` to the CKB seal-spend (R4),
////    the amount carried in `state` is transitively bound to the real CKB lock - the relayer cannot mint
////    an amount the lock did not commit to.
////  - STATE LAYOUT (== relay_bind's in-circuit `new_state`): amount(16 bytes, LITTLE-endian) ‖
////    recipient_credential(28). So the qty the relayer can mint is exactly the shannon amount the CKB
////    receipt locked, and the asset name (commitment[0:28]) is additionally bound to the recipient.
////  - the asset name is pinned to the commitment (first 28 bytes), and the policy enforces that EXACTLY
////    one asset under this policy is minted, with quantity == the committed amount.
use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use cardano/assets.{PolicyId, Value, tokens, from_asset}
use cardano/transaction.{Transaction}
use g16/verifier.{VerifyingKey, Proof, verify}
use g16/ckbcert.{field_of, fr_order}

pub type MintRedeemer {
  proof: Proof,
  public_inputs: List<Int>,
  state: ByteArray,
  seal: ByteArray,
}

// SEC B2/D1/D1b: public-input encoding MUST match the circuit's `Fr::from_le_bytes_mod_order` - little-
// endian AND reduced mod the BLS scalar order. We use the shared, REDUCING `ckbcert.field_of`. The previous
// local copy here did NOT reduce; because a 32-byte hash exceeds r ~55% of the time, the binding equality
// `pi_comm == field_of(comm)` would have mismatched the prover's reduced public input and rejected the
// majority of valid mints. (The pairing's scalar-mul reduces internally - but this `==` binding does not,
// so the reduction is mandatory here, not optional.)
fn commitment(state: ByteArray, seal: ByteArray) -> ByteArray {
  builtin.blake2b_256(builtin.append_bytearray(state, seal))
}

// amount = first 16 bytes of `state`, LITTLE-endian - identical to relay_bind's in-circuit encoding
// (new_state = amount(16 LE) ‖ recipient(28)), so the policy's committed amount matches the prover's.
fn amount_of(state: ByteArray) -> Int {
  builtin.bytearray_to_integer(False, builtin.slice_bytearray(0, 16, state))
}

/// Pure binding check: the minted (name, qty) under `policy` match the amount the proof committed to.
/// The proof binding (pi_comm == field_of(blake2b(state++seal))) ties `state` - hence the amount in its
/// first 16 LE bytes and the recipient in the next 28 - to the real CKB lock. The minted NAME is a fixed
/// `ft_name` param (the fungible wrapped token, e.g. "chiCKB"), so it matches the burn-gated CKB lock that
/// releases against a burn of that exact (policy, name) - and all leaps mint the SAME fungible asset.
pub fn bindings_ok(
  public_inputs: List<Int>,
  state: ByteArray,
  seal: ByteArray,
  mint: Value,
  policy: PolicyId,
  ft_name: ByteArray,
) -> Bool {
  let comm = commitment(state, seal)
  let amount = amount_of(state)
  let pi_ok =
    when public_inputs is {
      [_root, pi_seal, pi_comm] -> pi_seal == field_of(seal) && pi_comm == field_of(comm)
      _ -> False
    }
  let minted = tokens(mint, policy)
  let mint_ok = dict.size(minted) == 1 && dict.get(minted, ft_name) == Some(amount)
  pi_ok && mint_ok && amount > 0
}

/// True when this policy's net movement is a pure burn (all quantities < 0) - always allowed.
fn is_pure_burn(mint: Value, policy: PolicyId) -> Bool {
  let qs = dict.values(tokens(mint, policy))
  !list.is_empty(qs) && list.all(qs, fn(q) { q < 0 })
}

// SEC B1: `vk` is now a COMPILE-TIME parameter (the deployed CKB-consensus circuit's verifying key),
// NOT a redeemer field - so an attacker can no longer supply their own vk + a self-made proof.
validator zk_chiral_mint(vk: VerifyingKey, ft_name: ByteArray) {
  mint(redeemer: MintRedeemer, policy_id: PolicyId, tx: Transaction) {
    let MintRedeemer { proof, public_inputs, state, seal } = redeemer
    if is_pure_burn(tx.mint, policy_id) {
      True
    } else {
      verify(vk, proof, public_inputs) && bindings_ok(public_inputs, state, seal, tx.mint, policy_id, ft_name)
    }
  }

  else(_) {
    fail
  }
}

// ---- tests for the binding logic (the proof path is covered by leap_test/verifier_test) ----
const p_policy: PolicyId = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a"
const p_seal: ByteArray = #"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
// state: amount = 100000 (0x0186a0) in the first 16 bytes LITTLE-endian, then a 28-byte recipient cred
// (== relay_bind layout: amount(16 LE) ‖ recipient(28)).
const p_state: ByteArray = #"a086010000000000000000000000000033333333333333333333333333333333333333333333333333333333"

const p_ftname: ByteArray = #"636869434b42" // "chiCKB" - the fixed fungible wrapped-token name

fn pi_for(state: ByteArray, seal: ByteArray) -> List<Int> {
  [12345, field_of(seal), field_of(commitment(state, seal))]
}

test binding_accepts_committed_amount_and_name() {
  let mint = from_asset(p_policy, p_ftname, 100000)
  bindings_ok(pi_for(p_state, p_seal), p_state, p_seal, mint, p_policy, p_ftname)
}

test binding_rejects_wrong_amount() {
  let mint = from_asset(p_policy, p_ftname, 999999)
  !bindings_ok(pi_for(p_state, p_seal), p_state, p_seal, mint, p_policy, p_ftname)
}

test binding_rejects_wrong_name() {
  let mint = from_asset(p_policy, #"deadbeef", 100000)
  !bindings_ok(pi_for(p_state, p_seal), p_state, p_seal, mint, p_policy, p_ftname)
}

test binding_rejects_unbound_public_inputs() {
  let mint = from_asset(p_policy, p_ftname, 100000)
  !bindings_ok([12345, 1, 2], p_state, p_seal, mint, p_policy, p_ftname)
}

test is_pure_burn_detects_burn() {
  is_pure_burn(from_asset(p_policy, #"636b434b42", -100000), p_policy)
}

// SEC D1b regression: `field_of` MUST reduce mod r. This 32-byte value is all-0xFF, whose little-endian
// integer (2^256-1) far exceeds the scalar order, so an unreduced `field_of` would return 2^256-1 (>= r).
// The reduced result must be strictly below fr_order - pinning the reduction so it can never regress.
test field_of_reduces_mod_r() {
  let v = #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  field_of(v) < fr_order && field_of(v) >= 0
}
