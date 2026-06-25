//! ext_verify - the SECURITY-GRADE post-quantum FRI verifier in CKB-VM: extension-field (F_p²) fold
//! challenges + proof-of-work grinding + 96 queries, targeting real (conjectured) post-quantum soundness
//! (vs the 40-query demo). Hash-only + Goldilocks/F_p² arithmetic - no pairings, no trusted setup. Exit 0 =
//! accepted, 20 = rejected, 2 = malformed. Run under ckb-debugger to read the on-chain cost at secure params.
#![no_std]
#![no_main]
use fri_core::ext::{de_ext, verify_ext};
ckb_std::entry!(program_entry);
// secure params (96 queries) ⇒ ~0.5 MB proof + working set; bump the heap (fits CKB-VM's 4 MB memory).
ckb_std::default_alloc!({ 16 * 1024 }, { 2560 * 1024 }, 64);

#[cfg(not(feature = "bad"))]
const PROOF: &[u8] = include_bytes!("../../fixtures/ext_proof.bin");
#[cfg(feature = "bad")]
const PROOF: &[u8] = include_bytes!("../../fixtures/ext_proof_bad.bin");

fn program_entry() -> i8 {
    match de_ext(PROOF) {
        Some(p) => if verify_ext(&p) { 0 } else { 20 },
        None => 2,
    }
}
