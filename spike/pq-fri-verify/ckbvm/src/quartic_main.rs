//! quartic_verify - the QUARTIC (F_p⁴) post-quantum FRI verifier in CKB-VM: the configuration with a clean
//! ≥100-bit *quantum* commit-phase margin (F_p⁴ ≈ 2²⁵⁶ challenge field), 100 queries, 24-bit PoW grinding.
//! Hash-only + Goldilocks/F_p⁴ arithmetic - no pairings, no trusted setup. Exit 0/20/2. Run under
//! ckb-debugger to read the on-chain cost at the strongest (quantum-margin) parameters.
#![no_std]
#![no_main]
use fri_core::ext::{de_q, verify_q};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!({ 16 * 1024 }, { 2048 * 1024 }, 64);

#[cfg(not(feature = "bad"))]
const PROOF: &[u8] = include_bytes!("../../fixtures/quartic_proof.bin");
#[cfg(feature = "bad")]
const PROOF: &[u8] = include_bytes!("../../fixtures/quartic_proof_bad.bin");

fn program_entry() -> i8 {
    match de_q(PROOF) {
        Some(p) => if verify_q(&p) { 0 } else { 20 },
        None => 2,
    }
}
