//! leap_mint_guard - CKB-side leap-mint guard (the xUDT OWNER lock), bound to the REAL BoundAsset.
//!
//! No mock: the leap fact is read from the ACTUAL bound cell that `spike/phase1/bound_asset_unified.rs`
//! verifies and produces - bound cell data = `seal_txid(32) ‖ seal_idx(u32 LE) ‖ state`, and for a financial
//! token the `state` is `amount(u128 LE) ‖ recipient_lock_hash(32)` (the preimage the Cardano commitment
//! binds, which BoundAsset checks). BoundAsset runs in the SAME tx (the bound cell's type script), so the
//! leap is verified (Mithril cert) and the seal is unique; this guard ties the xUDT supply to that verified
//! state via the unit-tested `leap-guard-core` conservation logic.
//!   • bound cell in OUTPUTS  → genesis/transition → leap-in MINT: net xUDT == state.amount, all to recipient.
//!   • bound cell in INPUTS only (no output) → FINALIZE → leap-out BURN: net xUDT burned == state.amount.
//! Own args: `xudt_code_hash(32) ‖ bound_asset_type_hash(32) ‖ [policy_type_hash(32)]`.
//!
//! The guard is the xUDT OWNER lock, so its OWN script hash IS the owner the real xUDT checks for. It can't
//! be parameterized by the xUDT's full type-script hash (that hash embeds this owner - circular), so it
//! matches the bridge's xUDT cells by (type.code_hash == configured xUDT code hash) AND (type.args[0..32]
//! == this guard's own script hash). That is exactly the standard owner-mode xUDT: args = owner lock hash.
#![no_std]
#![no_main]
use ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::*,
    high_level::{
        load_cell_data, load_cell_lock_hash, load_cell_type, load_cell_type_hash, load_script,
        load_script_hash, QueryIter,
    },
};
use leap_guard_core::{
    authorize_burn, authorize_mint, enforce_policy, Direction, GuardError, GuardPolicy, LeapFact,
    TokenFlow,
};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

fn err(e: GuardError) -> i8 {
    match e {
        GuardError::ZeroAmount => 10,
        GuardError::Inflation => 11,
        GuardError::Leakage => 12,
        GuardError::BurnMismatch => 13,
        GuardError::NetMintOnBurn => 14,
        GuardError::ReplayNotConsumed => 15,
        GuardError::Paused => 16,
        GuardError::OverCap => 17,
        GuardError::UnderMin => 18,
        GuardError::BadState => 19,
    }
}
fn u128_le(d: &[u8]) -> Option<u128> {
    if d.len() < 16 { return None; }
    let mut b = [0u8; 16]; b.copy_from_slice(&d[0..16]); Some(u128::from_le_bytes(b))
}

/// Sum the bridge's xUDT over a source - a cell is ours iff its type script is the configured xUDT CODE
/// and its owner args are THIS guard's hash (standard owner-mode xUDT). If `recipient` given, also sum the
/// part locked to that recipient.
fn sum_xudt(src: Source, code: &[u8; 32], owner: &[u8; 32], recipient: Option<&[u8; 32]>) -> (u128, u128) {
    let (mut total, mut to_r) = (0u128, 0u128);
    for (i, ty) in QueryIter::new(load_cell_type, src).enumerate() {
        let s = match ty { Some(s) => s, None => continue };
        if s.code_hash().as_slice() != &code[..] { continue; }
        let a = s.args().raw_data();
        if a.len() < 32 || &a[0..32] != &owner[..] { continue; } // owner-mode xUDT for THIS guard
        if let Ok(data) = load_cell_data(i, src) {
            if let Some(amt) = u128_le(&data) {
                total = total.saturating_add(amt);
                if let Some(r) = recipient {
                    if load_cell_lock_hash(i, src).map(|lh| &lh == r).unwrap_or(false) {
                        to_r = to_r.saturating_add(amt);
                    }
                }
            }
        }
    }
    (total, to_r)
}

// find a bound cell (type == bound_asset hash) in `src`; return (financial-state amount, recipient) parsed
// from the REAL bound-cell layout: data = seal_txid(32) ‖ seal_idx(4) ‖ amount(16) ‖ recipient(32).
fn find_bound(src: Source, bound: &[u8; 32]) -> Option<([u8; 32], LeapFact)> {
    for (i, th) in QueryIter::new(load_cell_type_hash, src).enumerate() {
        if th.as_ref().map(|h| h == bound).unwrap_or(false) {
            let d = load_cell_data(i, src).ok()?;
            if d.len() < 36 + 16 + 32 { return None; }
            let amount = u128_le(&d[36..52])?;
            let mut recipient = [0u8; 32]; recipient.copy_from_slice(&d[52..84]);
            let mut seal = [0u8; 32]; seal.copy_from_slice(&d[0..32]);
            return Some((seal, LeapFact { amount, recipient, nonce: seal }));
        }
    }
    None
}

/// Read the admin-controlled policy cell (type == `policy` hash) from CellDeps and parse its data:
/// `flags(1) ‖ min_amount(16 LE) ‖ max_amount(16 LE)` (33 bytes). flags bit0=global pause, bit1=pause-in,
/// bit2=pause-out. The policy is a REFERENCE (cell-dep), so the same governance cell gates every leap tx
/// without being consumed. Returns None if no policy cell is present in the deps.
fn find_policy(policy: &[u8; 32]) -> Option<GuardPolicy> {
    for (i, th) in QueryIter::new(load_cell_type_hash, Source::CellDep).enumerate() {
        if th.as_ref().map(|h| h == policy).unwrap_or(false) {
            let d = load_cell_data(i, Source::CellDep).ok()?;
            if d.len() < 33 { return None; }
            let f = d[0];
            let mut mn = [0u8; 16]; mn.copy_from_slice(&d[1..17]);
            let mut mx = [0u8; 16]; mx.copy_from_slice(&d[17..33]);
            return Some(GuardPolicy {
                paused_global: f & 1 != 0,
                paused_in: f & 2 != 0,
                paused_out: f & 4 != 0,
                min_amount: u128::from_le_bytes(mn),
                max_amount: u128::from_le_bytes(mx),
            });
        }
    }
    None
}

fn program_entry() -> i8 {
    let args = load_script().unwrap().args().raw_data();
    if args.len() < 64 { return 2; }
    let mut xudt_code = [0u8; 32]; xudt_code.copy_from_slice(&args[0..32]);
    let mut bound = [0u8; 32]; bound.copy_from_slice(&args[32..64]);
    // the guard's OWN script hash is the xUDT owner it polices (owner-mode xUDT args = owner lock hash).
    let owner = load_script_hash().unwrap();

    // REAL leap fact: from the bound cell BoundAsset produced/consumed in this very tx.
    let (op_mint, fact) = match find_bound(Source::Output, &bound) {
        Some((_, f)) => (true, f),                                  // genesis/transition -> leap-in MINT
        None => match find_bound(Source::Input, &bound) {
            Some((_, f)) => (false, f),                             // input only -> FINALIZE -> leap-out BURN
            None => return err(GuardError::ReplayNotConsumed),     // no verified leap in this tx
        },
    };

    // OPERATIONAL POLICY (caps + pause/halt). If a policy hash is configured (args >= 96), the policy
    // cell MUST be present in the cell-deps and is enforced; misconfig (configured but absent) rejects.
    // With no policy configured, the OPEN policy applies (conservation still always holds).
    if args.len() >= 96 {
        let mut policy = [0u8; 32]; policy.copy_from_slice(&args[64..96]);
        let p = match find_policy(&policy) { Some(p) => p, None => return 3 };
        let dir = if op_mint { Direction::In } else { Direction::Out };
        if let Err(e) = enforce_policy(&p, dir, fact.amount) { return err(e); }
    }

    let (in_total, _) = sum_xudt(Source::Input, &xudt_code, &owner, None);
    let (out_total, out_to_recipient) = sum_xudt(Source::Output, &xudt_code, &owner, Some(&fact.recipient));
    let flow = TokenFlow {
        minted_total: out_total.saturating_sub(in_total),
        burned_total: in_total.saturating_sub(out_total),
        minted_to_recipient: out_to_recipient,
    };
    // `fact_consumed=true`: BoundAsset (same tx) enforces seal uniqueness + leap verification → no replay.
    let res = if op_mint { authorize_mint(&fact, &flow, true) } else { authorize_burn(fact.amount, &flow, true) };
    match res { Ok(()) => 0, Err(e) => err(e) }
}
