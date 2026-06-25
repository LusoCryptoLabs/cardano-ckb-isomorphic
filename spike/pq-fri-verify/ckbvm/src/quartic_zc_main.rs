//! quartic_zc - the ZERO-COPY quartic (F_p⁴) post-quantum verifier in CKB-VM. Verifies straight from the
//! proof byte-buffer (Merkle paths read as slices, not copied into owned Vecs), so peak memory is ~1× the
//! proof size instead of ~2×. This is what lets the production-domain (n≈2²²) ~1.7 MB proof fit CKB-VM's
//! 4 MB. Note the small heap: the owned `quartic_verify` needs ~2 MB; this needs only a few KB.
#![no_std]
#![no_main]
use fri_core::ext::verify_q_zc;
ckb_std::entry!(program_entry);
// zero-copy ⇒ only a few KB of heap (roots, final coeffs, betas, positions); the proof stays in the buffer.
ckb_std::default_alloc!({ 4 * 1024 }, { 64 * 1024 }, 64);

const PROOF: &[u8] = include_bytes!("../../fixtures/quartic_proof.bin");

fn program_entry() -> i8 {
    if verify_q_zc(PROOF) { 0 } else { 20 }
}
