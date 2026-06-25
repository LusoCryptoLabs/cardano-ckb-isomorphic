//// validators/binding_tests.ak - tests for the isomorphic-binding lock (binding_lock.ak).
use cardano/address.{Address, Script}
use cardano/assets.{from_lovelace, from_asset, merge, PolicyId, AssetName}
use cardano/transaction.{placeholder, Transaction, Input, Output, OutputReference, InlineDatum, NoDatum}
use binding_lock.{SealDatum, Transfer, Unbind}

const seal_policy: PolicyId = #"a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
const seal_name: AssetName = #"5345414c"
const owner: ByteArray = #"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
const lock_hash: ByteArray = #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const c32: ByteArray = #"1111111111111111111111111111111111111111111111111111111111111111"
const c16: ByteArray = #"22222222222222222222222222222222"

fn lock_addr() -> Address { Address { payment_credential: Script(lock_hash), stake_credential: None } }
fn own_ref() -> OutputReference { OutputReference { transaction_id: #"00", output_index: 0 } }
fn seal_val() -> assets.Value { merge(from_lovelace(2_000_000), from_asset(seal_policy, seal_name, 1)) }

fn seal_input(d: SealDatum) -> Input {
  Input { output_reference: own_ref(),
    output: Output { address: lock_addr(), value: seal_val(), datum: InlineDatum(d), reference_script: None } }
}
fn cont_out(d: SealDatum) -> Output {
  Output { address: lock_addr(), value: seal_val(), datum: InlineDatum(d), reference_script: None }
}
fn tx(ins: List<Input>, outs: List<Output>, sigs: List<ByteArray>) -> Transaction {
  Transaction { ..placeholder, inputs: ins, outputs: outs, extra_signatories: sigs }
}
fn d0() -> SealDatum { SealDatum { owner, commitment: c32 } }

// ---- Transfer ----
test transfer_ok() {
  let t = tx([seal_input(d0())], [cont_out(SealDatum { owner, commitment: c32 })], [owner])
  binding_lock.binding_lock.spend(seal_policy, seal_name, Some(d0()), Transfer, own_ref(), t)
}
test transfer_unsigned_fails() {
  let t = tx([seal_input(d0())], [cont_out(SealDatum { owner, commitment: c32 })], [])
  !binding_lock.binding_lock.spend(seal_policy, seal_name, Some(d0()), Transfer, own_ref(), t)
}
test transfer_no_seal_continuity_fails() {
  // continuing output carries no seal NFT -> not a valid transfer
  let bare = Output { address: lock_addr(), value: from_lovelace(2_000_000), datum: InlineDatum(d0()), reference_script: None }
  let t = tx([seal_input(d0())], [bare], [owner])
  !binding_lock.binding_lock.spend(seal_policy, seal_name, Some(d0()), Transfer, own_ref(), t)
}
test transfer_bad_commitment_fails() {
  let t = tx([seal_input(d0())], [cont_out(SealDatum { owner, commitment: c16 })], [owner])
  !binding_lock.binding_lock.spend(seal_policy, seal_name, Some(d0()), Transfer, own_ref(), t)
}

// ---- Unbind ----
test unbind_ok() {
  // owner releases: no continuing seal output at the lock (NFT burned / leaves)
  let elsewhere = Output { address: Address { payment_credential: Script(#"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"), stake_credential: None }, value: from_lovelace(2_000_000), datum: NoDatum, reference_script: None }
  let t = tx([seal_input(d0())], [elsewhere], [owner])
  binding_lock.binding_lock.spend(seal_policy, seal_name, Some(d0()), Unbind, own_ref(), t)
}
test unbind_unsigned_fails() {
  let elsewhere = Output { address: Address { payment_credential: Script(#"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"), stake_credential: None }, value: from_lovelace(2_000_000), datum: NoDatum, reference_script: None }
  let t = tx([seal_input(d0())], [elsewhere], [])
  !binding_lock.binding_lock.spend(seal_policy, seal_name, Some(d0()), Unbind, own_ref(), t)
}
