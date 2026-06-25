//! stark_verify - the post-quantum STARK verifier running in CKB-VM. Embeds a real STARK proof (boundary +
//! transition constraints over the computation a(i+1)=a(i)^2+c, composition polynomial FRI-tested low-degree)
//! and verifies it with hash-only + Goldilocks arithmetic (no pairings, no trusted setup). Exit 0 = accepted,
//! 20 = rejected, 2 = malformed. Run under ckb-debugger to read the real cycle cost of a STARK verify in
//! CKB-VM - the verifier side of the post-quantum forward leg, now checking an actual computation (not just a
//! low-degree codeword).
#![no_std]
#![no_main]
use fri_core::{de_stark, stark_verify};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

#[cfg(not(feature = "bad"))]
const PROOF: &[u8] = include_bytes!("../../fixtures/stark.bin");
#[cfg(feature = "bad")]
const PROOF: &[u8] = include_bytes!("../../fixtures/stark_bad.bin");

fn program_entry() -> i8 {
    match de_stark(PROOF) {
        Some(p) => if stark_verify(&p) { 0 } else { 20 },
        None => 2,
    }
}
