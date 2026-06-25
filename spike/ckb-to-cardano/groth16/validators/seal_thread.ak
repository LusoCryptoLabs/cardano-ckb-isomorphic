//// seal_thread.ak - the one-shot GENESIS PIN for the forward-leg seal-nullifier registry (SEC N-SEAL-1).
//// This minting policy can mint the registry THREAD TOKEN at most once: it is parameterized by a unique
//// `genesis_ref` outpoint (consumed at mint, so it can never re-fire) and the seal_nullifier script hash
//// `reg_script`. The mint succeeds ONLY if exactly one thread token is minted AND it lands on an output at
//// `reg_script` whose inline datum is the EMPTY-tree root (a fresh, empty consumed-seal set). Thereafter
//// seal_nullifier requires this same token on every insert, so the entire seal-set lineage is anchored to
//// ONE genesis - an attacker cannot stand up a parallel/empty registry to re-insert an already-consumed
//// seal. Burning the token is always allowed (it only ends the lineage). Mirror of ckbcert_thread + the
//// CKB-side type-id genesis pin (C1-R1).
use aiken/collection/list
use cardano/address.{Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction, OutputReference, Output, InlineDatum}
use g16/ckbcert.{has_thread, is_thread_burn, mints_one_thread}
use g16/seal_set.{SealSet, empty_root}

validator seal_thread(genesis_ref: OutputReference, reg_script: ByteArray) {
  mint(_redeemer: Data, policy_id: PolicyId, tx: Transaction) {
    let Transaction { inputs, outputs, mint, .. } = tx
    if is_thread_burn(mint, policy_id) {
      True
    } else {
      // GENESIS: consume the unique outpoint (so this can fire at most once), mint exactly one thread token,
      // and land it on a registry output whose datum is the EMPTY root.
      let unique = list.any(inputs, fn(i) { i.output_reference == genesis_ref })
      let one = mints_one_thread(mint, policy_id)
      let pinned_out =
        list.any(outputs, fn(o: Output) { is_empty_genesis(o, policy_id, reg_script) })
      unique && one && pinned_out
    }
  }

  else(_) {
    fail
  }
}

/// An output is the pinned genesis registry: at `reg_script`, carries the thread token, and its inline datum
/// is a SealSet at the EMPTY-tree root (no seals consumed yet).
fn is_empty_genesis(o: Output, policy: PolicyId, reg_script: ByteArray) -> Bool {
  let at_script =
    when o.address.payment_credential is {
      Script(h) -> h == reg_script
      _ -> False
    }
  let datum_ok =
    when o.datum is {
      InlineDatum(d) -> {
        expect s: SealSet = d
        s.root == empty_root()
      }
      _ -> False
    }
  at_script && has_thread(o.value, policy) && datum_ok
}

// ---- genesis mock-tx tests (mirror the CKB registry_genesis_* tests) ----
const t_policy: PolicyId = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a"
const t_thread_name: ByteArray = #"636b62636572742d746872656164"
const t_reg: ByteArray = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2b"
const t_gref: OutputReference =
  OutputReference {
    transaction_id: #"1111111111111111111111111111111111111111111111111111111111111111",
    output_index: 3,
  }

fn dummy_in(oref: OutputReference) -> transaction.Input {
  transaction.Input {
    output_reference: oref,
    output: Output {
      address: address.Address { payment_credential: address.VerificationKey(#"00"), stake_credential: None },
      value: assets.from_lovelace(5000),
      datum: transaction.NoDatum,
      reference_script: None,
    },
  }
}

fn mk_mint_tx(with_gref: Bool, root: ByteArray, with_token: Bool) -> Transaction {
  let in_oref =
    if with_gref {
      t_gref
    } else {
      OutputReference { transaction_id: #"2222222222222222222222222222222222222222222222222222222222222222", output_index: 0 }
    }
  let mint_val =
    if with_token {
      assets.from_asset(t_policy, t_thread_name, 1)
    } else {
      assets.from_asset(t_policy, #"6465636f79", 1)
    }
  let gen_out =
    Output {
      address: address.Address { payment_credential: Script(t_reg), stake_credential: None },
      value: assets.from_asset(t_policy, t_thread_name, 1),
      datum: InlineDatum(SealSet { root }),
      reference_script: None,
    }
  Transaction { ..transaction.placeholder, inputs: [dummy_in(in_oref)], outputs: [gen_out], mint: mint_val }
}

test genesis_mint_ok() {
  seal_thread.mint(t_gref, t_reg, Void, t_policy, mk_mint_tx(True, empty_root(), True))
}

test genesis_without_unique_ref_rejected() {
  !seal_thread.mint(t_gref, t_reg, Void, t_policy, mk_mint_tx(False, empty_root(), True))
}

test genesis_nonempty_root_rejected() {
  !seal_thread.mint(t_gref, t_reg, Void, t_policy, mk_mint_tx(True, #"0707070707070707070707070707070707070707070707070707070707070707", True))
}
