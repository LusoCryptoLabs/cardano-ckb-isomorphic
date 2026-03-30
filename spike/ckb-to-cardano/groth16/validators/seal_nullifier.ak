//// seal_nullifier.ak — the global REPLAY-ONCE seal set for the forward leg (SEC N-FIN-1), the Cardano
//// mirror of the CKB `burn_nullifier_registry`. A singleton UTxO — pinned by the one-shot THREAD TOKEN that
//// `seal_thread.ak` mints exactly once (genesis_ref consumed) onto an EMPTY-root genesis output, exactly
//// like the checkpoint's ckbcert_thread (SEC N-SEAL-1) — holds the root of a 256-bit sparse Merkle tree of
//// consumed CKB seals. A spend INSERTS
//// one seal key, and `seal_set.inserts` forces a NON-MEMBERSHIP proof (the key was absent under the old
//// root) → membership under the new root, so a seal can be consumed at most once, ever. cardano_bound binds
//// each lineage's terminal/authenticating action to a seal insertion here, so two BoundState UTxOs cannot
//// both act on the same `ckb_seal` (the second insertion fails non-membership).
use aiken/builtin
use aiken/collection/list
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, from_asset}
use cardano/transaction.{Transaction, OutputReference, Output, Input, InlineDatum, placeholder}
use g16/ckbcert.{has_thread}
use g16/seal_set.{SealSet, Insert}

validator seal_nullifier(thread_policy: PolicyId) {
  spend(datum: Option<SealSet>, redeemer: Insert, own: OutputReference, tx: Transaction) {
    expect Some(ss) = datum
    let Insert { key, sibs } = redeemer
    expect builtin.length_of_bytearray(key) == 32
    expect list.length(sibs) == 256
    // the registry being spent must carry the singleton thread token (pins the one canonical lineage).
    expect Some(self_in) = list.find(tx.inputs, fn(i) { i.output_reference == own })
    let thread_in = has_thread(self_in.output.value, thread_policy)
    // exactly one continuing registry output at the same address, keeping the thread token + the new root.
    let addr = self_in.output.address
    let cont =
      when list.filter(tx.outputs, fn(o: Output) { o.address == addr }) is {
        [o] ->
          when o.datum is {
            InlineDatum(d) -> {
              expect new: SealSet = d
              has_thread(o.value, thread_policy) && seal_set.inserts(ss.root, new.root, key, sibs)
            }
            _ -> False
          }
        _ -> False
      }
    thread_in && cont
  }

  else(_) {
    fail
  }
}

// ---- mock-tx tests for the registry spend (the SMT soundness core is tested in g16/seal_set) ----
test insert_accepted() {
  let key = #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"
  let sibs = seal_set.empty_sibs()
  let old_root = seal_set.empty_root()
  let new_root = seal_set.fold(seal_set.present, key, sibs)
  let tx = mk_tx(old_root, new_root)
  seal_nullifier.spend(test_policy, Some(SealSet { root: old_root }), Insert { key, sibs }, test_oref, tx)
}

test replay_rejected_at_registry() {
  // SEC N-FIN-1: spend the registry AFTER `key` was inserted (old root = the post-insert root). The
  // non-membership fold(0, key, sibs) yields the empty root, not the post-insert root → rejected.
  let key = #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"
  let sibs = seal_set.empty_sibs()
  let inserted = seal_set.fold(seal_set.present, key, sibs)
  // attacker tries to "insert" the same key again, claiming some new root, against the post-insert root.
  let tx = mk_tx(inserted, seal_set.fold(seal_set.present, key, sibs))
  !seal_nullifier.spend(test_policy, Some(SealSet { root: inserted }), Insert { key, sibs }, test_oref, tx)
}

test missing_thread_token_rejected() {
  let key = #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"
  let sibs = seal_set.empty_sibs()
  let old_root = seal_set.empty_root()
  let new_root = seal_set.fold(seal_set.present, key, sibs)
  // a registry input WITHOUT the thread token (a decoy lineage) must be rejected.
  let tx = mk_tx_no_thread(old_root, new_root)
  !seal_nullifier.spend(test_policy, Some(SealSet { root: old_root }), Insert { key, sibs }, test_oref, tx)
}

// ---- test fixtures ----
const test_policy: PolicyId = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a"
const thread_name: ByteArray = #"636b62636572742d746872656164"
const script_hash: ByteArray = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2b"
const test_oref: OutputReference =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: 0,
  }

fn reg_addr() -> Address {
  Address { payment_credential: Script(script_hash), stake_credential: None }
}

fn mk_tx_v(old_root: ByteArray, new_root: ByteArray, with_thread: Bool) -> Transaction {
  let val =
    if with_thread {
      from_asset(test_policy, thread_name, 1)
    } else {
      from_asset(test_policy, #"6465636f79", 1)
    }
  let in_out =
    Output { address: reg_addr(), value: val, datum: InlineDatum(SealSet { root: old_root }), reference_script: None }
  let self_in = Input { output_reference: test_oref, output: in_out }
  let cont =
    Output { address: reg_addr(), value: val, datum: InlineDatum(SealSet { root: new_root }), reference_script: None }
  Transaction { ..placeholder, inputs: [self_in], outputs: [cont] }
}

fn mk_tx(old_root: ByteArray, new_root: ByteArray) -> Transaction {
  mk_tx_v(old_root, new_root, True)
}

fn mk_tx_no_thread(old_root: ByteArray, new_root: ByteArray) -> Transaction {
  mk_tx_v(old_root, new_root, False)
}
