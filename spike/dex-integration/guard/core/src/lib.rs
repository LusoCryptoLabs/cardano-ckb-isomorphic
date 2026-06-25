//! leap-guard-core - the FINANCIAL decision logic of the leap-mint guard, isolated so it can be unit-tested
//! (`cargo test`) and shared verbatim by the CKB no_std script and the Cardano validator.
//!
//! The guard is what makes a bridged token value-safe. It does NOT verify the leap itself - that is the
//! existing verifier's job (BoundAsset/Mithril on CKB, Groth16-of-CKB-consensus on Cardano). The guard
//! enforces, against a **verified leap fact**, the three invariants a financial peg must never violate:
//!   1. NO INFLATION  - a leap-in may mint *exactly* `fact.amount`, and *only* to `fact.recipient`.
//!   2. EXACT BURN    - a leap-out may burn *exactly* the amount the source-chain release will credit.
//!   3. REPLAY-ONCE   - each leap fact authorizes at most one mint/burn (the fact is a one-shot, consumed).
//!
//! `no_std` so the CKB script can link it directly; tests run on the host.
#![no_std]

/// A leap fact the guard trusts because the verifier produced/verified it (e.g. the BoundAsset bound cell or
/// a Groth16-attested leap). `recipient` is the destination owner (a CKB lock hash / a Cardano addr hash).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LeapFact {
    pub amount: u128,
    pub recipient: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(PartialEq, Eq, Debug)]
pub enum GuardError {
    ZeroAmount,
    Inflation,           // net mint != fact.amount
    Leakage,             // some minted units not locked to the recipient
    BurnMismatch,        // net burn != the amount credited on the source release
    NetMintOnBurn,       // a "burn" path produced a net mint
    ReplayNotConsumed,   // the one-shot leap fact was not consumed in this tx
    Paused,              // the bridge (or this direction) is halted by the policy
    OverCap,             // amount exceeds the per-leap maximum
    UnderMin,            // amount below the per-leap minimum (dust floor)
    BadState,            // financial state bytes malformed (wrong length)
}

/// Operational policy a financial app needs on top of conservation: a per-leap **cap**, a per-leap
/// **floor**, and a **pause/halt** switch. Lives in an admin-controlled cell/datum the guard reads;
/// it is NOT trusted to relax conservation - it can only further restrict. `max_amount == 0` means
/// "no cap configured". `paused`/`paused_in`/`paused_out` allow halting all flow or one direction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GuardPolicy {
    pub paused_global: bool,
    pub paused_in: bool,   // halt leap-in (mint)
    pub paused_out: bool,  // halt leap-out (burn)
    pub min_amount: u128,
    pub max_amount: u128,  // 0 = no cap
}

impl GuardPolicy {
    /// An always-permissive policy (no caps, not paused) - the implicit policy when none is configured.
    pub const OPEN: GuardPolicy = GuardPolicy {
        paused_global: false, paused_in: false, paused_out: false, min_amount: 0, max_amount: 0,
    };
}

/// Which way the leap goes, so the policy can halt one direction without the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction { In, Out }

/// Enforce the operational policy (pause + caps) for a leap of `amount` in `dir`. Pure & shared by
/// both chains so the limits are identical on each side. Conservation (`authorize_*`) is enforced
/// separately and always - the policy can only ADD restrictions, never remove them.
pub fn enforce_policy(p: &GuardPolicy, dir: Direction, amount: u128) -> Result<(), GuardError> {
    if p.paused_global { return Err(GuardError::Paused); }
    match dir {
        Direction::In  => if p.paused_in  { return Err(GuardError::Paused); },
        Direction::Out => if p.paused_out { return Err(GuardError::Paused); },
    }
    if amount < p.min_amount { return Err(GuardError::UnderMin); }
    if p.max_amount != 0 && amount > p.max_amount { return Err(GuardError::OverCap); }
    Ok(())
}

// ---- canonical financial-state codec (the decimals/amount mapping contract) -------------------
//
// THE single source of truth for how a leap's value is encoded in the verified state, shared by the
// CKB script, the Cardano validator (via the test vector below), and the off-chain builder. The
// amount is a `u128` in the token's BASE UNITS (integer; decimals live in the token-info / CIP-68
// metadata, NOT here) serialized **little-endian, exactly 16 bytes**. This is the ONLY numeric
// encoding on the value path - there is no float and no truncating conversion anywhere. The recipient
// width is chain-native and follows the amount: 32 bytes on CKB (a lock-script hash), 28 on Cardano
// (a payment credential), so the layouts are:
//     CKB     state = amount(16 LE) ‖ recipient(32)   => 48 bytes
//     Cardano state = amount(16 LE) ‖ recipient(28)   => 44 bytes
/// Decode the amount (first 16 bytes, LE) from a financial state. Returns None if too short.
pub fn decode_amount_le(state: &[u8]) -> Result<u128, GuardError> {
    if state.len() < 16 { return Err(GuardError::BadState); }
    let mut b = [0u8; 16];
    b.copy_from_slice(&state[0..16]);
    Ok(u128::from_le_bytes(b))
}

/// Encode an amount as the canonical 16-byte LE prefix (used by builders/tests to match on-chain).
pub fn encode_amount_le(amount: u128) -> [u8; 16] { amount.to_le_bytes() }

/// Observed token movement in the transaction (computed from the real inputs/outputs by the on-chain script).
#[derive(Clone, Copy, Debug)]
pub struct TokenFlow {
    pub minted_total: u128,        // sum(outputs of the token) − sum(inputs)  when positive
    pub burned_total: u128,        // sum(inputs) − sum(outputs)               when positive
    pub minted_to_recipient: u128, // of the outputs, the amount locked to `fact.recipient`
}

/// Authorize a LEAP-IN MINT: exactly `fact.amount` created, all of it to the recipient, leap fact consumed.
pub fn authorize_mint(fact: &LeapFact, flow: &TokenFlow, fact_consumed: bool) -> Result<(), GuardError> {
    if fact.amount == 0 { return Err(GuardError::ZeroAmount); }
    if !fact_consumed { return Err(GuardError::ReplayNotConsumed); }
    if flow.burned_total != 0 { return Err(GuardError::NetMintOnBurn); } // a mint tx must not also net-burn
    if flow.minted_total != fact.amount { return Err(GuardError::Inflation); }      // NO INFLATION
    if flow.minted_to_recipient != fact.amount { return Err(GuardError::Leakage); } // no diversion
    Ok(())
}

/// Authorize a LEAP-OUT BURN: exactly `credited` units burned (what the source release will pay out), once,
/// with no net mint. `credited` is the amount the source-chain release verifier will use.
pub fn authorize_burn(credited: u128, flow: &TokenFlow, fact_consumed: bool) -> Result<(), GuardError> {
    if credited == 0 { return Err(GuardError::ZeroAmount); }
    if !fact_consumed { return Err(GuardError::ReplayNotConsumed); }
    if flow.minted_total != 0 { return Err(GuardError::NetMintOnBurn); }            // no minting on a burn
    if flow.burned_total != credited { return Err(GuardError::BurnMismatch); }      // EXACT BURN
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const R: [u8; 32] = [7u8; 32];
    const OTHER: [u8; 32] = [9u8; 32];
    const N: [u8; 32] = [1u8; 32];
    fn fact(a: u128) -> LeapFact { LeapFact { amount: a, recipient: R, nonce: N } }

    // ---- mint (leap-in) ----
    #[test] fn mint_exact_ok() {
        let f = fact(52_000_000);
        let flow = TokenFlow { minted_total: 52_000_000, burned_total: 0, minted_to_recipient: 52_000_000 };
        assert_eq!(authorize_mint(&f, &flow, true), Ok(()));
    }
    #[test] fn mint_inflation_rejected() { // minted MORE than the leap
        let f = fact(52_000_000);
        let flow = TokenFlow { minted_total: 52_000_001, burned_total: 0, minted_to_recipient: 52_000_001 };
        assert_eq!(authorize_mint(&f, &flow, true), Err(GuardError::Inflation));
    }
    #[test] fn mint_undermint_rejected() {
        let f = fact(52_000_000);
        let flow = TokenFlow { minted_total: 51_000_000, burned_total: 0, minted_to_recipient: 51_000_000 };
        assert_eq!(authorize_mint(&f, &flow, true), Err(GuardError::Inflation));
    }
    #[test] fn mint_diverted_rejected() { // right total, but not all to the recipient
        let f = fact(52_000_000);
        let flow = TokenFlow { minted_total: 52_000_000, burned_total: 0, minted_to_recipient: 50_000_000 };
        assert_eq!(authorize_mint(&f, &flow, true), Err(GuardError::Leakage));
    }
    #[test] fn mint_replay_rejected() { // leap fact not consumed -> could be replayed
        let f = fact(52_000_000);
        let flow = TokenFlow { minted_total: 52_000_000, burned_total: 0, minted_to_recipient: 52_000_000 };
        assert_eq!(authorize_mint(&f, &flow, false), Err(GuardError::ReplayNotConsumed));
    }
    #[test] fn mint_zero_rejected() {
        let f = fact(0);
        let flow = TokenFlow { minted_total: 0, burned_total: 0, minted_to_recipient: 0 };
        assert_eq!(authorize_mint(&f, &flow, true), Err(GuardError::ZeroAmount));
    }
    #[test] fn mint_with_hidden_burn_rejected() {
        let f = fact(52_000_000);
        let flow = TokenFlow { minted_total: 52_000_000, burned_total: 10, minted_to_recipient: 52_000_000 };
        assert_eq!(authorize_mint(&f, &flow, true), Err(GuardError::NetMintOnBurn));
    }

    // ---- burn (leap-out) ----
    #[test] fn burn_exact_ok() {
        let flow = TokenFlow { minted_total: 0, burned_total: 52_000_000, minted_to_recipient: 0 };
        assert_eq!(authorize_burn(52_000_000, &flow, true), Ok(()));
    }
    #[test] fn burn_underburn_rejected() { // claims to release more than burned -> drain
        let flow = TokenFlow { minted_total: 0, burned_total: 51_000_000, minted_to_recipient: 0 };
        assert_eq!(authorize_burn(52_000_000, &flow, true), Err(GuardError::BurnMismatch));
    }
    #[test] fn burn_overburn_rejected() {
        let flow = TokenFlow { minted_total: 0, burned_total: 52_000_001, minted_to_recipient: 0 };
        assert_eq!(authorize_burn(52_000_000, &flow, true), Err(GuardError::BurnMismatch));
    }
    #[test] fn burn_with_mint_rejected() { // a "burn" that also mints
        let flow = TokenFlow { minted_total: 5, burned_total: 52_000_000, minted_to_recipient: 5 };
        assert_eq!(authorize_burn(52_000_000, &flow, true), Err(GuardError::NetMintOnBurn));
    }
    #[test] fn burn_replay_rejected() {
        let flow = TokenFlow { minted_total: 0, burned_total: 52_000_000, minted_to_recipient: 0 };
        assert_eq!(authorize_burn(52_000_000, &flow, false), Err(GuardError::ReplayNotConsumed));
    }

    // ---- policy: caps + pause ----
    fn pol(min: u128, max: u128) -> GuardPolicy {
        GuardPolicy { paused_global: false, paused_in: false, paused_out: false, min_amount: min, max_amount: max }
    }
    #[test] fn policy_open_allows_any() {
        assert_eq!(enforce_policy(&GuardPolicy::OPEN, Direction::In, 1), Ok(()));
        assert_eq!(enforce_policy(&GuardPolicy::OPEN, Direction::Out, u128::MAX), Ok(()));
    }
    #[test] fn policy_within_cap_ok() {
        assert_eq!(enforce_policy(&pol(1_000, 100_000_000), Direction::In, 52_000_000), Ok(()));
    }
    #[test] fn policy_over_cap_rejected() {
        assert_eq!(enforce_policy(&pol(0, 100_000_000), Direction::In, 100_000_001), Err(GuardError::OverCap));
    }
    #[test] fn policy_under_min_rejected() {
        assert_eq!(enforce_policy(&pol(1_000, 0), Direction::Out, 999), Err(GuardError::UnderMin));
    }
    #[test] fn policy_global_pause_halts_both() {
        let p = GuardPolicy { paused_global: true, ..pol(0, 0) };
        assert_eq!(enforce_policy(&p, Direction::In, 1), Err(GuardError::Paused));
        assert_eq!(enforce_policy(&p, Direction::Out, 1), Err(GuardError::Paused));
    }
    #[test] fn policy_directional_pause() {
        let p_in = GuardPolicy { paused_in: true, ..pol(0, 0) };
        assert_eq!(enforce_policy(&p_in, Direction::In, 1), Err(GuardError::Paused));
        assert_eq!(enforce_policy(&p_in, Direction::Out, 1), Ok(())); // out still flows
        let p_out = GuardPolicy { paused_out: true, ..pol(0, 0) };
        assert_eq!(enforce_policy(&p_out, Direction::Out, 1), Err(GuardError::Paused));
        assert_eq!(enforce_policy(&p_out, Direction::In, 1), Ok(()));
    }

    // ---- canonical amount codec (the mapping contract) ----
    #[test] fn amount_roundtrips_le() {
        for a in [0u128, 1, 52_000_000, u64::MAX as u128, u128::MAX] {
            let enc = encode_amount_le(a);
            assert_eq!(enc.len(), 16);
            assert_eq!(decode_amount_le(&enc), Ok(a));
        }
    }
    #[test] fn amount_decodes_from_full_state_prefix() {
        // a real CKB financial state = amount(16) ‖ recipient(32); decoding reads only the amount prefix
        let mut state = encode_amount_le(52_000_000).to_vec();
        state.extend_from_slice(&[7u8; 32]);
        assert_eq!(decode_amount_le(&state), Ok(52_000_000));
    }
    #[test] fn amount_short_state_rejected() {
        assert_eq!(decode_amount_le(&[0u8; 15]), Err(GuardError::BadState));
    }
    #[test] fn amount_is_little_endian_canonical() {
        // pin the byte order so CKB (u128::from_le_bytes) and Cardano (bytearray_to_integer little) agree
        assert_eq!(encode_amount_le(1), [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
        assert_eq!(encode_amount_le(256), [0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
    }
}
