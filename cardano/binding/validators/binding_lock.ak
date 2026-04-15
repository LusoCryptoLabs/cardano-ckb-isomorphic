//// validators/binding_lock.ak
//// The Cardano-side BINDING LOCK for isomorphic binding. Holds the seal NFT (+ anchored value).
//// A spend is either:
////  * Transfer: the owner moves the asset. Requires owner signature, that the seal NFT is
////    recreated at this same lock in exactly one continuing output, and that the continuing
////    SealDatum carries a fresh 32-byte `commitment` = blake2b256(next CKB bound-cell state ||
////    next seal). The CKB `BoundAsset` type script later verifies (via the Mithril oracle) that
////    THIS spend tx is certified and that its commitment binds the new CKB state.
////  * Unbind: the owner releases. The seal NFT is burned and the value leaves the lock.
//// The lock is intentionally thin: seal continuity + commitment emission + owner auth. The
//// semantic binding (commitment <-> CKB state) is enforced on CKB, the only side that verifies
//// Cardano. (docs/BINDING_SPEC.md §4)
use aiken/collection/list
use aiken/primitive/bytearray
use cardano/address.{Address}
use cardano/assets.{PolicyId, AssetName, quantity_of}
use cardano/transaction.{Transaction, OutputReference, Output, InlineDatum}

pub type SealDatum {
  owner: ByteArray,        // VerificationKeyHash authorized to move the asset
  commitment: ByteArray,   // 32 bytes = blake2b256(ckb bound-cell state || seal) ; "" at genesis pre-bind
}

pub type BindingRedeemer {
  Transfer
  Unbind
}

fn has_seal(o: Output, p: PolicyId, n: AssetName) -> Bool {
  quantity_of(o.value, p, n) == 1
}

validator binding_lock(seal_policy: PolicyId, seal_name: AssetName) {
  spend(datum: Option<SealDatum>, redeemer: BindingRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(SealDatum { owner, .. }) = datum
    let signed = list.has(self.extra_signatories, owner)
    when redeemer is {
      Transfer -> {
        // own address (where the seal lives) = the address of the input being spent
        expect Some(own_in) = list.find(self.inputs, fn(i) { i.output_reference == own_ref })
        let own_addr: Address = own_in.output.address
        // exactly ONE continuing output at this lock carrying the seal NFT
        let conts =
          list.filter(self.outputs, fn(o) { o.address == own_addr && has_seal(o, seal_policy, seal_name) })
        // exactly one continuing seal output, with a fresh SealDatum carrying a 32-byte commitment
        when conts is {
          [cont] ->
            when cont.datum is {
              InlineDatum(d) -> {
                expect SealDatum { commitment: new_c, .. }: SealDatum = d
                signed && bytearray.length(new_c) == 32
              }
              _ -> False
            }
          _ -> False
        }
      }
      Unbind -> {
        // release: the seal NFT must NOT continue at this lock (burned / leaves)
        let no_seal_out =
          !list.any(self.outputs, fn(o) { o.address == own_in_addr(self, own_ref) && has_seal(o, seal_policy, seal_name) })
        signed && no_seal_out
      }
    }
  }
  else(_) { fail }
}

fn own_in_addr(self: Transaction, own_ref: OutputReference) -> Address {
  expect Some(own_in) = list.find(self.inputs, fn(i) { i.output_reference == own_ref })
  own_in.output.address
}
