//// ckbcert_thread.ak - the one-shot GENESIS PIN for the forward CKB light-client checkpoint. This minting
//// policy can mint the checkpoint THREAD TOKEN at most once: it is parameterized by a unique `genesis_ref`
//// outpoint (consumed at mint, so it can never re-fire) and by the canonical `pinned` genesis Checkpoint +
//// the advance checkpoint's script hash `cp_script`. The mint succeeds ONLY if exactly one thread token is
//// minted AND it lands on an output at `cp_script` whose inline datum equals `pinned`. Thereafter
//// advance_ckbcert requires this same token on every advance, so the entire checkpoint lineage is anchored
//// to ONE canonical CKB genesis (no attacker can seed a parallel chain with a fake genesis). Burning the
//// token is always allowed (it only ends the lineage). Mirror of the reverse-leg PINNED_GENESIS pin.
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction, OutputReference}
use g16/ckbcert.{Checkpoint, genesis_mint_ok, is_thread_burn}

validator ckbcert_thread(
  genesis_ref: OutputReference,
  pinned: Checkpoint,
  cp_script: ByteArray,
) {
  mint(_redeemer: Data, policy_id: PolicyId, tx: Transaction) {
    let Transaction { inputs, outputs, mint, .. } = tx
    if is_thread_burn(mint, policy_id) {
      True
    } else {
      genesis_mint_ok(inputs, outputs, mint, policy_id, genesis_ref, pinned, cp_script)
    }
  }

  else(_) {
    fail
  }
}
