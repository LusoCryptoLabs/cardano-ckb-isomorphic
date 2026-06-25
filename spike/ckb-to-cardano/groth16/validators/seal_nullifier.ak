//// seal_nullifier.ak - the global REPLAY-ONCE seal set for the forward leg (SEC N-FIN-1), the Cardano
//// mirror of the CKB `burn_nullifier_registry`. A singleton UTxO - pinned by the one-shot THREAD TOKEN that
//// `seal_thread.ak` mints exactly once (genesis_ref consumed) onto an EMPTY-root genesis output, exactly
//// like the checkpoint's ckbcert_thread (SEC N-SEAL-1) - holds the root of a 256-bit sparse Merkle tree of
//// consumed CKB seals. A spend INSERTS
//// one seal key, and `seal_set.inserts` forces a NON-MEMBERSHIP proof (the key was absent under the old
//// root) → membership under the new root, so a seal can be consumed at most once, ever. cardano_bound binds
//// each lineage's terminal/authenticating action to a seal insertion here, so two BoundState UTxOs cannot
//// both act on the same `ckb_seal` (the second insertion fails non-membership).
use aiken/builtin
use aiken/collection/list
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, Value, from_asset, from_lovelace, merge}
use cardano/transaction.{Transaction, OutputReference, Output, Input, InlineDatum, placeholder}
use g16/ckbcert.{lineage_token}
use g16/seal_set.{SealSet, Insert}

validator seal_nullifier() {
  spend(datum: Option<SealSet>, redeemer: Insert, own: OutputReference, tx: Transaction) {
    expect Some(ss) = datum
    let Insert { key, sibs } = redeemer
    expect builtin.length_of_bytearray(key) == 32
    expect list.length(sibs) == 128                   // SMT depth 128 (low 128 bits of the 32B key); see g16/seal_set
    // CONTINUITY pin (no compile-time thread_policy → breaks the seal_nullifier <-> seal_thread parameterization
    // cycle, just like advance_ckbcert): the spent registry must carry exactly ONE non-ADA lineage token and the
    // continuing output must keep the SAME one. The CANONICAL registry is selected by leap_mint_guard via its
    // genesis NFT (find-by-NFT, not by script hash) - so a decoy lineage at this same script hash with a
    // DIFFERENT token can only insert into ITS OWN tree and is never the registry the mint reads. Replay-once
    // therefore still holds: the one NFT-pinned lineage admits each seal at most once.
    expect Some(self_in) = list.find(tx.inputs, fn(i) { i.output_reference == own })
    let addr = self_in.output.address
    let cont =
      when (lineage_token(self_in.output.value), list.filter(tx.outputs, fn(o: Output) { o.address == addr })) is {
        (Some(tok), [o]) ->
          when o.datum is {
            InlineDatum(d) -> {
              expect new: SealSet = d
              lineage_token(o.value) == Some(tok) && seal_set.inserts(ss.root, new.root, key, sibs)
            }
            _ -> False
          }
        _ -> False
      }
    cont
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
  let tx = mk_io(old_root, new_root, tok_val, tok_val)
  seal_nullifier.spend(Some(SealSet { root: old_root }), Insert { key, sibs }, test_oref, tx)
}

test replay_rejected_at_registry() {
  // SEC N-FIN-1: spend the registry AFTER `key` was inserted (old root = the post-insert root). The
  // non-membership fold(0, key, sibs) yields the empty root, not the post-insert root → rejected.
  let key = #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"
  let sibs = seal_set.empty_sibs()
  let inserted = seal_set.fold(seal_set.present, key, sibs)
  // attacker tries to "insert" the same key again, claiming some new root, against the post-insert root.
  let tx = mk_io(inserted, seal_set.fold(seal_set.present, key, sibs), tok_val, tok_val)
  !seal_nullifier.spend(Some(SealSet { root: inserted }), Insert { key, sibs }, test_oref, tx)
}

// CONTINUITY: a registry input that carries NO lineage token cannot insert (no line to preserve).
test no_lineage_token_rejected() {
  let key = #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"
  let sibs = seal_set.empty_sibs()
  let old_root = seal_set.empty_root()
  let new_root = seal_set.fold(seal_set.present, key, sibs)
  let tx = mk_io(old_root, new_root, ada_only, ada_only)
  !seal_nullifier.spend(Some(SealSet { root: old_root }), Insert { key, sibs }, test_oref, tx)
}

// CONTINUITY: the continuing output must keep the SAME lineage token - dropping/changing it is rejected
// (this is the token-bloat / lineage-swap grief defense; the canonical registry is NFT-pinned by the mint).
test continuity_broken_rejected() {
  let key = #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"
  let sibs = seal_set.empty_sibs()
  let old_root = seal_set.empty_root()
  let new_root = seal_set.fold(seal_set.present, key, sibs)
  let tx = mk_io(old_root, new_root, tok_val, tok_val2)
  !seal_nullifier.spend(Some(SealSet { root: old_root }), Insert { key, sibs }, test_oref, tx)
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

// the canonical lineage token (+ADA), a DIFFERENT lineage token, and an ADA-only (no-token) value.
const tok_val: Value = merge(from_lovelace(2_000_000), from_asset(test_policy, thread_name, 1))
const tok_val2: Value = merge(from_lovelace(2_000_000), from_asset(test_policy, #"6465636f79", 1))
const ada_only: Value = from_lovelace(2_000_000)

fn mk_io(old_root: ByteArray, new_root: ByteArray, in_val: Value, out_val: Value) -> Transaction {
  let self_in =
    Input { output_reference: test_oref, output: Output { address: reg_addr(), value: in_val, datum: InlineDatum(SealSet { root: old_root }), reference_script: None } }
  let cont =
    Output { address: reg_addr(), value: out_val, datum: InlineDatum(SealSet { root: new_root }), reference_script: None }
  Transaction { ..placeholder, inputs: [self_in], outputs: [cont] }
}
