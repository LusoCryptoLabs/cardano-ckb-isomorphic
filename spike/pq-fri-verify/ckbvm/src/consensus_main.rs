//! consensus_verify - verifies the cumulative-difficulty STARK AIR in CKB-VM (the real total_difficulty
//! transition, not a placeholder LDT). Exit 0 = accepted, 20 = rejected, 2 = malformed.
#![no_std]
#![no_main]
use fri_core::consensus::{de_cum, verify_cum};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!({ 16 * 1024 }, { 1024 * 1024 }, 64);

#[cfg(not(feature = "bad"))]
const PROOF: &[u8] = include_bytes!("../../fixtures/consensus.bin");
#[cfg(feature = "bad")]
const PROOF: &[u8] = include_bytes!("../../fixtures/consensus_bad.bin");

fn program_entry() -> i8 {
    match de_cum(PROOF) {
        Some(p) => if verify_cum(&p) { 0 } else { 20 },
        None => 2,
    }
}
