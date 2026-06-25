//// leap_guard.ak - the Cardano-side leap-mint guard's conservation logic (mirror of the CKB
//// leap-guard-core), with an adversarial test battery. The wrapped FT may be minted only in exact step with
//// a VERIFIED CKB→Cardano leap (the Groth16 `cardano_bound` transition authenticates the leap; this guard
//// enforces NO-INFLATION / EXACT-BURN / REPLAY-ONCE of the FT against the leap's amount). The validator
//// `leap_mint_guard.ak` wires these against the real `self.mint` and the leap fact.
use aiken/crypto.{VerificationKeyHash}

/// A verified leap fact (the Groth16-attested CKB lock): `amount` units to `recipient`, identified by `nonce`.
pub type LeapFact {
  amount: Int,
  recipient: ByteArray,
  nonce: ByteArray,
}

/// LEAP-IN MINT: exactly `fact.amount` minted, ALL to `fact.recipient`, leap fact consumed, no net burn.
pub fn authorize_mint(
  fact: LeapFact,
  minted_total: Int,
  burned_total: Int,
  minted_to_recipient: Int,
  fact_consumed: Bool,
) -> Bool {
  fact.amount > 0 && fact_consumed && burned_total == 0 && minted_total == fact.amount && minted_to_recipient == fact.amount
}

/// LEAP-OUT BURN: exactly `credited` burned (what the CKB release will pay), once, with no net mint.
pub fn authorize_burn(
  credited: Int,
  minted_total: Int,
  burned_total: Int,
  fact_consumed: Bool,
) -> Bool {
  credited > 0 && fact_consumed && minted_total == 0 && burned_total == credited
}

/// Operational policy (mirror of leap-guard-core::GuardPolicy): a per-leap cap + floor + pause/halt
/// switch, read from an admin-controlled reference input. It can only FURTHER RESTRICT - conservation
/// (`authorize_*`) is enforced separately and always. `max_amount == 0` means no cap.
pub type GuardPolicy {
  paused_global: Bool,
  paused_in: Bool,
  paused_out: Bool,
  min_amount: Int,
  max_amount: Int,
  // SEC D6: minimum CKB confirmation depth K a leap proof must prove (tip_height - height >= K). The
  // governor sets this; cardano_bound pins it into the Groth16 public inputs so a relayer cannot prove a
  // smaller K. 0 = depth-0 (legacy/insecure); production ships a non-zero K (< W, with live-window margin).
  min_confirmations: Int,
}

/// The threaded policy datum: the governor authorized to change it + the current policy. Lives here (the
/// lib) so both `chiral_policy` (writer) and `cardano_bound`/`leap_mint_guard` (readers) share one shape -
/// the previous split (chiral_policy wrote PolicyState, leap_mint_guard read bare GuardPolicy) was a latent
/// CBOR mismatch.
pub type PolicyState {
  governor: VerificationKeyHash,
  policy: GuardPolicy,
}

/// Leap direction so a single direction can be halted independently.
pub type Direction {
  LeapIn
  LeapOut
}

/// Enforce pause + caps for a leap of `amount` in `dir`. Identical limits to the CKB side.
pub fn enforce_policy(p: GuardPolicy, dir: Direction, amount: Int) -> Bool {
  let not_paused =
    !p.paused_global && when dir is {
      LeapIn -> !p.paused_in
      LeapOut -> !p.paused_out
    }
  let within_min = amount >= p.min_amount
  let within_max = p.max_amount == 0 || amount <= p.max_amount
  not_paused && within_min && within_max
}

const r: ByteArray = #"07070707070707070707070707070707"
const n: ByteArray = #"01010101010101010101010101010101"
fn fact(a: Int) -> LeapFact { LeapFact { amount: a, recipient: r, nonce: n } }

// ---- mint (leap-in) ----
test mint_exact_ok() { authorize_mint(fact(52000000), 52000000, 0, 52000000, True) }
test mint_inflation_rejected() { !authorize_mint(fact(52000000), 52000001, 0, 52000001, True) }
test mint_undermint_rejected() { !authorize_mint(fact(52000000), 51000000, 0, 51000000, True) }
test mint_diverted_rejected() { !authorize_mint(fact(52000000), 52000000, 0, 50000000, True) }
test mint_replay_rejected() { !authorize_mint(fact(52000000), 52000000, 0, 52000000, False) }
test mint_zero_rejected() { !authorize_mint(fact(0), 0, 0, 0, True) }
test mint_hidden_burn_rejected() { !authorize_mint(fact(52000000), 52000000, 10, 52000000, True) }

// ---- burn (leap-out) ----
test burn_exact_ok() { authorize_burn(52000000, 0, 52000000, True) }
test burn_underburn_rejected() { !authorize_burn(52000000, 0, 51000000, True) }
test burn_overburn_rejected() { !authorize_burn(52000000, 0, 52000001, True) }
test burn_with_mint_rejected() { !authorize_burn(52000000, 5, 52000000, True) }
test burn_replay_rejected() { !authorize_burn(52000000, 0, 52000000, False) }

// ---- policy: caps + pause (mirror of the CKB core tests) ----
fn pol(min: Int, max: Int) -> GuardPolicy {
  GuardPolicy { paused_global: False, paused_in: False, paused_out: False, min_amount: min, max_amount: max, min_confirmations: 0 }
}
const open_policy: GuardPolicy = GuardPolicy { paused_global: False, paused_in: False, paused_out: False, min_amount: 0, max_amount: 0, min_confirmations: 0 }
test policy_open_allows_any() { enforce_policy(open_policy, LeapIn, 1) && enforce_policy(open_policy, LeapOut, 52000000) }
test policy_within_cap_ok() { enforce_policy(pol(1000, 100000000), LeapIn, 52000000) }
test policy_over_cap_rejected() { !enforce_policy(pol(0, 100000000), LeapIn, 100000001) }
test policy_under_min_rejected() { !enforce_policy(pol(1000, 0), LeapOut, 999) }
test policy_global_pause_halts_both() {
  let p = GuardPolicy { ..pol(0, 0), paused_global: True }
  !enforce_policy(p, LeapIn, 1) && !enforce_policy(p, LeapOut, 1)
}
test policy_pause_in_only() {
  let p = GuardPolicy { ..pol(0, 0), paused_in: True }
  !enforce_policy(p, LeapIn, 1) && enforce_policy(p, LeapOut, 1)
}
test policy_pause_out_only() {
  let p = GuardPolicy { ..pol(0, 0), paused_out: True }
  !enforce_policy(p, LeapOut, 1) && enforce_policy(p, LeapIn, 1)
}
