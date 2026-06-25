//! fri_verify - the post-quantum FRI low-degree-test verifier, running in CKB-VM. It embeds a real proof
//! (produced by the host prover) and verifies it with hash-only + Goldilocks arithmetic (no pairings, no
//! trusted setup). Exit 0 = accepted, 20 = rejected, 2 = malformed. Run under ckb-debugger to read the real
//! cycle cost of a FRI verify in CKB-VM (the measured counterpart of spike/pq-fri-ckbvm's cost model).
#![no_std]
#![no_main]
use fri_core::{de, verify};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

#[cfg(not(feature = "bad"))]
const PROOF: &[u8] = include_bytes!("../../fixtures/proof.bin");
#[cfg(feature = "bad")]
const PROOF: &[u8] = include_bytes!("../../fixtures/proof_bad.bin");

fn program_entry() -> i8 {
    match de(PROOF) {
        Some(p) => if verify(&p) { 0 } else { 20 },
        None => 2,
    }
}
