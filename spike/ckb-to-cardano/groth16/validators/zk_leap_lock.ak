//// Minimal on-chain verifier-lock: ADA locked here is released only by a Groth16 proof (the redeemer)
//// that satisfies the verifying key + public inputs carried in the datum. Used to DEMONSTRATE, in a
//// live Cardano preview tx, that Cardano verifies a CKB-consensus proof produced by the relayer.
//// (Production uses cardano_bound.ak with the vk fixed as a param + the seal/commitment binding;
//// here vk lives in the datum to keep the script address constant and the demo simple.)
use g16/verifier.{VerifyingKey, Proof, verify}
use cardano/transaction.{Transaction, OutputReference}

pub type LockDatum {
  vk: VerifyingKey,
  public_inputs: List<Int>,
}

validator zk_leap_lock {
  spend(datum: Option<LockDatum>, redeemer: Proof, _own: OutputReference, _tx: Transaction) {
    expect Some(LockDatum { vk, public_inputs }) = datum
    verify(vk, redeemer, public_inputs)
  }

  else(_) {
    fail
  }
}
