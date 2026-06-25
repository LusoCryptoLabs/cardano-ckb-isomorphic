//! relay_escrow.rs - a CKB LOCK demonstrating the two properties a decentralized permissionless relayer
//! needs (no committee, no trusted operator - the validators are proof-gated):
//!  (A) PERMISSIONLESS RELAY: anyone (no signature) may consume the escrow IF the tx (i) references an
//!      AUTHENTICATED tx-set checkpoint (type-hash 0x69b443c6) as a cellDep AND (ii) DELIVERS THIS escrow's
//!      SPECIFIC bridge-event payout - an output to `event_lock` of capacity >= `event_amount`. The
//!      submitter (the relayer) keeps the escrow as the fee/incentive, but ONLY by actually fulfilling the
//!      event this escrow pays for (SEC C7: a live checkpoint alone no longer sweeps every escrow).
//!  (B) TIMEOUT REFUND: if no relayer acts, the depositor reclaims after a deadline. So liveness never
//!      depends on a third party: worst case is a refund.
//! Cell DATA = depositor_lock_hash(32) ‖ deadline_since(8, LE u64) ‖ event_lock_hash(32) ‖ event_amount(8, LE)
//! Config lives in cell DATA (plain syscalls only - avoids the molecule Script decode CKB-VM rejects).
#![no_std]
#![no_main]
use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_cell_data, load_input_since, load_cell_lock_hash, load_cell_type_hash, load_cell_capacity, load_script};
use ckb_std::error::SysError;
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

// SEC A1-style: the authenticated tx-set checkpoint's type-script hash (TxSetCert) is a per-instance LOCK ARG
// (was a hardcoded const = 0x69b443c6…) - so a deployment pins which cert-verifier it trusts. A cellDep
// carrying this type hash proves the bridge event was cert-verified in-VM -> the relay is legitimate.
struct Cfg { auth_ckpt_type: [u8;32], dep: [u8;32], deadline: u64, event_lock: [u8;32], event_amount: u64 }

fn read_cfg() -> Option<Cfg> {
    let args = load_script().ok()?.args().raw_data();
    if args.len() < 32 { return None; }
    let mut auth = [0u8;32]; auth.copy_from_slice(&args[0..32]);
    let data = load_cell_data(0, Source::GroupInput).ok()?;
    if data.len() < 80 { return None; }
    let mut dep = [0u8;32]; dep.copy_from_slice(&data[0..32]);
    let mut dl = [0u8;8]; dl.copy_from_slice(&data[32..40]);
    let mut ev = [0u8;32]; ev.copy_from_slice(&data[40..72]);
    let mut ea = [0u8;8]; ea.copy_from_slice(&data[72..80]);
    Some(Cfg { auth_ckpt_type: auth, dep, deadline: u64::from_le_bytes(dl), event_lock: ev, event_amount: u64::from_le_bytes(ea) })
}

fn has_authenticated_checkpoint(auth: &[u8;32]) -> bool {
    let mut i = 0usize;
    loop {
        match load_cell_type_hash(i, Source::CellDep) {
            Ok(Some(th)) => { if &th == auth { return true; } i += 1; }
            Ok(None) => { i += 1; }
            Err(SysError::IndexOutOfBound) => return false,
            Err(_) => return false,
        }
    }
}

/// True iff some OUTPUT pays `>= min_cap` to `lock` - i.e. the bridge-event payout was actually delivered.
fn delivers_to(lock: &[u8;32], min_cap: u64) -> bool {
    let mut j = 0usize;
    loop {
        match load_cell_lock_hash(j, Source::Output) {
            Ok(h) => {
                if &h == lock {
                    if let Ok(cap) = load_cell_capacity(j, Source::Output) {
                        if cap >= min_cap { return true; }
                    }
                }
                j += 1;
            }
            Err(SysError::IndexOutOfBound) => return false,
            Err(_) => return false,
        }
    }
}

// (A) permissionless relay - authenticated checkpoint AND this escrow's specific payout delivered.
fn relay_ok(cfg: &Cfg) -> bool {
    has_authenticated_checkpoint(&cfg.auth_ckpt_type) && delivers_to(&cfg.event_lock, cfg.event_amount)
}

// (B) timeout refund - after the deadline, the depositor must RECEIVE the escrow (minus a bounded fee).
fn refund_ok(cfg: &Cfg) -> bool {
    let since = match load_input_since(0, Source::GroupInput) { Ok(s) => s, Err(_) => return false };
    if since < cfg.deadline { return false; }            // CKB also enforces the tx can't mine before `since`
    let in_cap = match load_cell_capacity(0, Source::GroupInput) { Ok(c) => c, Err(_) => return false };
    let max_fee: u64 = 100_000_000;                      // SEC C8: <= 1 CKB fee allowance
    let mut j = 0usize;
    loop {
        match load_cell_lock_hash(j, Source::Output) {
            Ok(h) => {
                if h == cfg.dep {
                    if let Ok(out_cap) = load_cell_capacity(j, Source::Output) {
                        if out_cap + max_fee >= in_cap { return true; } // depositor gets >= escrow - 1 CKB
                    }
                }
                j += 1;
            }
            Err(SysError::IndexOutOfBound) => return false,
            Err(_) => return false,
        }
    }
}

fn program_entry() -> i8 {
    let cfg = match read_cfg() { Some(c) => c, None => return 20 };
    if relay_ok(&cfg) { return 0; }                      // (A) permissionless relay, event-bound
    if refund_ok(&cfg) { return 0; }                     // (B) timeout refund
    21
}
