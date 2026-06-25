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
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, AssetName, quantity_of, from_lovelace, from_asset, merge}
use cardano/transaction.{Transaction, OutputReference, Output, InlineDatum, Input, placeholder}

pub type SealDatum {
  owner: ByteArray,        // VerificationKeyHash authorized to move the asset
  commitment: ByteArray,   // 32 bytes = blake2b256(ckb bound-cell state || seal) ; "" at genesis pre-bind
}

/// v2 leap-in datum (docs/RECIPIENT_COMMITMENT.md §3.1). The continuing seal carries the owner-signed,
/// Mithril-certified CKB recipient lock hash as an APPENDED field. Same Constr tag (121) as `SealDatum`,
/// arity 3: the CKB positional parser reads `commitment` (field 1) for both shapes and `recipient_lock_hash`
/// (field 2) only on the leap. Transfer/Unbind keep the 2-field `SealDatum` byte-for-byte.
pub type LeapSealDatum {
  owner: ByteArray,
  commitment: ByteArray,           // 32B = RC = blake2b256(state || SOURCE seal || recipient_lock_hash)
  recipient_lock_hash: ByteArray,  // 32B = the CKB lock-script hash that must own the surviving CkbOwned cell
}

pub type BindingRedeemer {
  Transfer
  Unbind
  // v2 (Constr 123): Cardano->CKB leap-in. The owner-chosen CKB recipient lock hash rides IN the
  // owner-signed redeemer; the validator forces the continuing LeapSealDatum to commit the SAME recipient,
  // so a permissionless relayer cannot redirect the surviving cell. (docs/LEAP_BRIEF_V2.md §4, B1)
  LeapToCkb { recipient_lock_hash: ByteArray }
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
      LeapToCkb { recipient_lock_hash: r } -> {
        // Cardano->CKB leap-in. Like Transfer the seal is RECREATED at this lock (so the CKB side reads
        // seal_at_lock == Some(true), distinguishing leap-in from Unbind/FINALIZE), BUT the continuing datum
        // is a 3-field LeapSealDatum whose recipient == the owner-signed redeemer recipient. The CKB
        // LEAP_TO_CKB branch recomputes RC over this commitment and pins the surviving cell's ACTUAL lock to
        // this recipient (docs/RECIPIENT_COMMITMENT.md §4-5). The lock stays thin: it cannot verify CKB state.
        expect Some(own_in) = list.find(self.inputs, fn(i) { i.output_reference == own_ref })
        let own_addr: Address = own_in.output.address
        let conts =
          list.filter(self.outputs, fn(o) { o.address == own_addr && has_seal(o, seal_policy, seal_name) })
        when conts is {
          [cont] ->
            when cont.datum is {
              InlineDatum(d) -> {
                expect LeapSealDatum { commitment: new_c, recipient_lock_hash: cont_r, .. }: LeapSealDatum = d
                signed && bytearray.length(new_c) == 32 && bytearray.length(cont_r) == 32 && cont_r == r
              }
              _ -> False
            }
          _ -> False
        }
      }
    }
  }
  else(_) { fail }
}

fn own_in_addr(self: Transaction, own_ref: OutputReference) -> Address {
  expect Some(own_in) = list.find(self.inputs, fn(i) { i.output_reference == own_ref })
  own_in.output.address
}

// ---- v2 LeapToCkb tests (B1: recipient cannot be relayer-substituted) ----
const t_policy: PolicyId = #"a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
const t_name: AssetName = #"5345414c"
const t_owner: ByteArray = #"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
const t_lock: ByteArray = #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const t_c32: ByteArray = #"1111111111111111111111111111111111111111111111111111111111111111"
const t_recip: ByteArray = #"3333333333333333333333333333333333333333333333333333333333333333"
const t_attacker: ByteArray = #"4444444444444444444444444444444444444444444444444444444444444444"
const t_short: ByteArray = #"33333333333333333333333333333333"

fn t_lock_addr() -> Address { Address { payment_credential: Script(t_lock), stake_credential: None } }
fn t_own_ref() -> OutputReference { OutputReference { transaction_id: #"00", output_index: 0 } }
fn t_seal_val() -> assets.Value { merge(from_lovelace(2_000_000), from_asset(t_policy, t_name, 1)) }
fn t_din() -> SealDatum { SealDatum { owner: t_owner, commitment: t_c32 } }
fn t_seal_input() -> Input {
  Input { output_reference: t_own_ref(),
    output: Output { address: t_lock_addr(), value: t_seal_val(), datum: InlineDatum(t_din()), reference_script: None } }
}
fn t_leap_cont(r: ByteArray) -> Output {
  Output { address: t_lock_addr(), value: t_seal_val(),
    datum: InlineDatum(LeapSealDatum { owner: t_owner, commitment: t_c32, recipient_lock_hash: r }), reference_script: None }
}
fn t_tx(outs: List<Output>, sigs: List<ByteArray>) -> Transaction {
  Transaction { ..placeholder, inputs: [t_seal_input()], outputs: outs, extra_signatories: sigs }
}

test leap_to_ckb_ok() {
  binding_lock.spend(t_policy, t_name, Some(t_din()),
    LeapToCkb { recipient_lock_hash: t_recip }, t_own_ref(), t_tx([t_leap_cont(t_recip)], [t_owner]))
}
test leap_to_ckb_recipient_substitution_fails() {
  // B1: relayer writes a DIFFERENT recipient into the continuing datum than the owner signed -> reject
  !binding_lock.spend(t_policy, t_name, Some(t_din()),
    LeapToCkb { recipient_lock_hash: t_recip }, t_own_ref(), t_tx([t_leap_cont(t_attacker)], [t_owner]))
}
test leap_to_ckb_unsigned_fails() {
  !binding_lock.spend(t_policy, t_name, Some(t_din()),
    LeapToCkb { recipient_lock_hash: t_recip }, t_own_ref(), t_tx([t_leap_cont(t_recip)], []))
}
test leap_to_ckb_short_recipient_fails() {
  !binding_lock.spend(t_policy, t_name, Some(t_din()),
    LeapToCkb { recipient_lock_hash: t_short }, t_own_ref(), t_tx([t_leap_cont(t_short)], [t_owner]))
}
test leap_to_ckb_no_seal_continuity_fails() {
  let bare = Output { address: t_lock_addr(), value: from_lovelace(2_000_000),
    datum: InlineDatum(LeapSealDatum { owner: t_owner, commitment: t_c32, recipient_lock_hash: t_recip }), reference_script: None }
  !binding_lock.spend(t_policy, t_name, Some(t_din()),
    LeapToCkb { recipient_lock_hash: t_recip }, t_own_ref(), t_tx([bare], [t_owner]))
}
