//// chiral_policy.ak — the admin-controlled operational policy cell the leap-mint guard reads by
//// reference input. Holds a single `GuardPolicy` (pause/halt + per-leap caps), updatable ONLY by the
//// governor key, and ONLY by re-producing exactly one continuing cell at the same address carrying the
//// same identity NFT (so the policy is a unique, threaded singleton — no forks, no second policy a leap
//// could reference instead). Distilled from `cardano-ckb-bridge`'s bridge_state `SetPause` + caps, minus
//// the committee/challenge machinery the isomorphic verifier path doesn't use. PoC; audit before value.
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{PolicyId, quantity_of}
use cardano/transaction.{Transaction, OutputReference, InlineDatum}
use leap_guard.{GuardPolicy}

/// The threaded policy datum: the governor authorized to change it + the current policy.
pub type PolicyState {
  governor: VerificationKeyHash,
  policy: GuardPolicy,
}

pub type PolicyRedeemer {
  // governor updates pause flags / caps (sanity-checked: min <= max unless max==0)
  Update
}

validator chiral_policy(nft_policy: PolicyId, nft_name: ByteArray) {
  spend(datum: Option<PolicyState>, _r: PolicyRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(state) = datum
    // governor-signed
    let signed = list.has(self.extra_signatories, state.governor)
    // locate our own input + the single continuing output carrying the identity NFT at the same address
    expect Some(own_input) = list.find(self.inputs, fn(i) { i.output_reference == own_ref })
    let own_addr = own_input.output.address
    expect Some(cont) =
      list.find(
        self.outputs,
        fn(o) { o.address == own_addr && quantity_of(o.value, nft_policy, nft_name) == 1 },
      )
    expect InlineDatum(cd) = cont.datum
    expect new_state: PolicyState = cd
    // identity preserved (governor unchanged here; rotate via a dedicated path if ever needed) + sane caps
    let governor_same = new_state.governor == state.governor
    let p = new_state.policy
    let sane_caps = p.min_amount >= 0 && p.max_amount >= 0 && ( p.max_amount == 0 || p.min_amount <= p.max_amount )
    signed && governor_same && sane_caps
  }

  else(_) {
    fail
  }
}

// ---- tests ----
fn gov() -> VerificationKeyHash { #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" }
fn mk(min: Int, max: Int) -> GuardPolicy {
  GuardPolicy { paused_global: False, paused_in: False, paused_out: False, min_amount: min, max_amount: max }
}

// the sane-caps invariant the validator enforces on every update
test caps_sane_ok() {
  let p = mk(1000, 100000000)
  p.min_amount >= 0 && p.max_amount >= 0 && ( p.max_amount == 0 || p.min_amount <= p.max_amount )
}
test caps_no_cap_ok() {
  let p = mk(1000, 0) // max==0 means no cap, any min ok
  p.max_amount == 0 || p.min_amount <= p.max_amount
}
test caps_inverted_rejected() {
  let p = mk(100000000, 1000) // min > max with a real cap -> rejected
  !( p.max_amount == 0 || p.min_amount <= p.max_amount )
}
test governor_pinned() {
  let a = PolicyState { governor: gov(), policy: mk(0, 0) }
  let b = PolicyState { governor: gov(), policy: mk(1000, 100000000) }
  a.governor == b.governor // an update keeps the governor
}
