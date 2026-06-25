//// chiral_policy_thread.ak - the one-shot GENESIS PIN for the governor-signed policy cell (SEC D6, MF-1).
//// Without this, `cardano_bound.read_k` (which sources the confirmation depth K from the policy cell's
//// PolicyState datum) could be fed a FORGED policy cell carrying min_confirmations=0, downgrading K to 0 and
//// re-opening the depth-0 reorg-theft. This minting policy makes the policy NFT a provable SINGLETON: it
//// consumes a unique `genesis_ref` (so it can fire at most once), mints exactly one thread token, and lands
//// it on an output at the `chiral_policy` script hash whose initial PolicyState has a SANE K (0..32). Thereafter
//// only that one governor-controlled cell carries the token; an attacker cannot mint a second to forge a low-K
//// reference cell. Mirror of seal_thread / leap_ratelimit_thread.
use aiken/collection/list
use cardano/address.{Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction, OutputReference, Output, InlineDatum}
use g16/ckbcert.{has_thread, is_thread_burn, mints_one_thread}
use leap_guard.{PolicyState}

// NOTE: the minter takes ONLY `genesis_ref` (not the chiral_policy script hash) to break the deploy-time
// parameter circularity (chiral_policy is parameterized by THIS policy id, so this minter cannot also be
// parameterized by chiral_policy's hash). The address binding is enforced on the CONSUMING side:
// cardano_bound.read_k requires the policy NFT to sit at the chiral_policy script hash. So this minter only
// guarantees one-shot uniqueness + a sane-K genesis datum; placing the token at the wrong address is a
// liveness fail (read_k can't find it), never a security one.
validator chiral_policy_thread(genesis_ref: OutputReference) {
  mint(_redeemer: Data, policy_id: PolicyId, tx: Transaction) {
    let Transaction { inputs, outputs, mint, .. } = tx
    if is_thread_burn(mint, policy_id) {
      True
    } else {
      let unique = list.any(inputs, fn(i) { i.output_reference == genesis_ref })
      let one = mints_one_thread(mint, policy_id)
      let pinned_out = list.any(outputs, fn(o: Output) { is_sane_genesis(o, policy_id) })
      unique && one && pinned_out
    }
  }

  else(_) {
    fail
  }
}

/// The genesis policy cell: carries the thread token, and its initial PolicyState has a SANE confirmation
/// depth (0..32) so K can never be born outside the live-window band.
fn is_sane_genesis(o: Output, policy: PolicyId) -> Bool {
  let datum_ok =
    when o.datum is {
      InlineDatum(d) -> {
        expect ps: PolicyState = d
        ps.policy.min_confirmations >= 0 && ps.policy.min_confirmations <= 32
      }
      _ -> False
    }
  has_thread(o.value, policy) && datum_ok
}

// ---- genesis mock-tx tests ----
const t_policy: PolicyId = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a"
const t_thread_name: ByteArray = #"636b62636572742d746872656164"
const t_pol_script: ByteArray = #"8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2b"
const t_gov: ByteArray = #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
const t_gref: OutputReference =
  OutputReference { transaction_id: #"1111111111111111111111111111111111111111111111111111111111111111", output_index: 3 }

fn ps(k: Int) -> PolicyState {
  PolicyState {
    governor: t_gov,
    policy: leap_guard.GuardPolicy { paused_global: False, paused_in: False, paused_out: False, min_amount: 0, max_amount: 0, min_confirmations: k },
  }
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

fn mk_mint_tx(with_gref: Bool, state: PolicyState, with_token: Bool) -> Transaction {
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
      address: address.Address { payment_credential: Script(t_pol_script), stake_credential: None },
      value: assets.from_asset(t_policy, t_thread_name, 1),
      datum: InlineDatum(state),
      reference_script: None,
    }
  Transaction { ..transaction.placeholder, inputs: [dummy_in(in_oref)], outputs: [gen_out], mint: mint_val }
}

test cpt_genesis_mint_ok() {
  chiral_policy_thread.mint(t_gref, Void, t_policy, mk_mint_tx(True, ps(12), True))
}
test cpt_without_unique_ref_rejected() {
  !chiral_policy_thread.mint(t_gref, Void, t_policy, mk_mint_tx(False, ps(12), True))
}
test cpt_insane_k_genesis_rejected() {
  !chiral_policy_thread.mint(t_gref, Void, t_policy, mk_mint_tx(True, ps(40), True))
}
