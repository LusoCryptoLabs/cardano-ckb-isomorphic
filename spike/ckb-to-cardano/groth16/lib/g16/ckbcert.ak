//// ckbcert.ak - shared types + PURE logic for the forward (CKB->Cardano) light-client checkpoint.
//// Adds GENESIS PINNING to the trustless advance: the checkpoint chain on Cardano is anchored to ONE
//// canonical CKB genesis by a one-shot THREAD TOKEN. The token can be minted exactly once (it consumes
//// a unique genesis outpoint) and only if the genesis checkpoint output carries the PINNED datum; every
//// advance must then keep the same token on the continuing checkpoint. So an attacker cannot seed a
//// parallel checkpoint with a fake genesis (no token -> advance_ckbcert rejects it), and there is exactly
//// one lineage, rooted at the pin. This mirrors the reverse-leg PINNED_GENESIS soundness fix (TESTNET_LOG
//// SS I.1 / the advance-verifier genesis pin) on the Cardano side.
use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, Value, AssetName, tokens, quantity_of, flatten, without_lovelace}
use cardano/transaction.{Input, Output, OutputReference, InlineDatum}

pub type Checkpoint {
  chain_root: ByteArray,          // 32B - the ChainRootMMR root
  total_difficulty: ByteArray,    // 32B big-endian - cumulative PoW work
  window_root: ByteArray,         // 32B - ring-buffer Merkle root over the last W validated headers (RESTRUCTURE.md)
  tip_height: Int,                // latest validated header height - authenticates the per-leap height-bound
}

/// The fixed asset name of the checkpoint thread token ("ckbcert-thread").
pub const thread_name: AssetName = #"636b62636572742d746872656164"

/// A value carries the (single) checkpoint thread token.
pub fn has_thread(v: Value, policy: PolicyId) -> Bool {
  quantity_of(v, policy, thread_name) == 1
}

/// The lineage thread token of a checkpoint value: the SINGLE non-ADA asset, and only if its quantity is
/// exactly 1 (None for zero, two-or-more, or qty != 1). This lets advance_ckbcert preserve the genesis token
/// by CONTINUITY (input lineage token == output lineage token) WITHOUT a compile-time thread-policy parameter,
/// which removes the advance_ckbcert <-> ckbcert_thread parameterization CYCLE (each was a compile-time param
/// of the other, an unsolvable hash fixpoint). Soundness is unchanged: the leap (cardano_bound) still reads
/// the checkpoint by the REAL genesis thread NFT (checkpoint_nft), so a fake-token lineage is invisible to it;
/// requiring EXACTLY one non-ADA token on BOTH input and output also blocks a token-bloat grief (an advancer
/// stuffing an extra token to freeze future advances).
pub fn lineage_token(v: Value) -> Option<(PolicyId, AssetName)> {
  when flatten(without_lovelace(v)) is {
    [(p, n, 1)] -> Some((p, n))
    _ -> None
  }
}

/// The mint moves EXACTLY one thread token (qty == 1) and nothing else under this policy.
pub fn mints_one_thread(mint: Value, policy: PolicyId) -> Bool {
  let minted = tokens(mint, policy)
  dict.size(minted) == 1 && dict.get(minted, thread_name) == Some(1)
}

/// This policy's net movement under `policy` is a pure burn (all quantities < 0) - always allowed
/// (it only ends the lineage; it cannot create one).
pub fn is_thread_burn(mint: Value, policy: PolicyId) -> Bool {
  let qs = dict.values(tokens(mint, policy))
  !list.is_empty(qs) && list.all(qs, fn(q) { q < 0 })
}

/// An output is the pinned genesis checkpoint: it sits at the checkpoint script address, carries the
/// thread token, and its inline datum is EXACTLY the pinned canonical checkpoint.
pub fn is_pinned_genesis_output(
  o: Output,
  pinned: Checkpoint,
  policy: PolicyId,
  cp_script: ByteArray,
) -> Bool {
  let at_script =
    when o.address is {
      Address { payment_credential: Script(h), .. } -> h == cp_script
      _ -> False
    }
  let datum_ok =
    when o.datum is {
      // decode the inline datum back to a Checkpoint and require equality with the pin
      InlineDatum(d) -> {
        expect c: Checkpoint = d
        c == pinned
      }
      _ -> False
    }
  at_script && has_thread(o.value, policy) && datum_ok
}

/// GENESIS mint is valid iff: it consumes the unique one-shot outpoint (so it can ever happen at most
/// once), mints exactly one thread token, and some output is the pinned genesis checkpoint.
pub fn genesis_mint_ok(
  inputs: List<Input>,
  outputs: List<Output>,
  mint: Value,
  policy: PolicyId,
  genesis_ref: OutputReference,
  pinned: Checkpoint,
  cp_script: ByteArray,
) -> Bool {
  let unique = list.any(inputs, fn(i: Input) { i.output_reference == genesis_ref })
  let one = mints_one_thread(mint, policy)
  let pinned_out =
    list.any(outputs, fn(o: Output) { is_pinned_genesis_output(o, pinned, policy, cp_script) })
  unique && one && pinned_out
}

// helper for field encoding shared by the validators (kept here so logic lives in one place)
// SEC B2/D1: MUST match the circuit, which packs the 32-byte value LITTLE-ENDIAN and reduces mod the BLS
// scalar field (`Fr::from_le_bytes_mod_order`) - NOT a re-hash.
// SEC D1b: the reduction mod r is MANDATORY here. A 32-byte hash exceeds r ~55% of the time; the prover's
// public input is the REDUCED residue, so the binding equality `public_inputs == [field_of(..)]` must
// compare against the same reduced residue, not the raw 256-bit integer. (The pairing's scalar-mul reduces
// internally and would pass either way; it is this equality binding that requires the explicit `% fr_order`.)
pub const fr_order: Int =
  52435875175126190479447740508185965837690552500527637822603658699938581184513

pub fn field_of(b: ByteArray) -> Int {
  builtin.bytearray_to_integer(False, b) % fr_order
}
