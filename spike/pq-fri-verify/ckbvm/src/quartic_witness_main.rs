//! quartic_witness - the production on-chain shape: a CKB lock script that loads the post-quantum proof from
//! the transaction WITNESS (not embedded) and verifies it zero-copy. This is what an actual deployed
//! checkpoint script would do - the proof is supplied per-transaction as witness data. Run under a
//! ckb-debugger mock transaction (see scripts/gen_tx.py). Exit 0 = accepted, 20 = rejected, 2 = no witness.
#![no_std]
#![no_main]
use ckb_std::ckb_constants::Source;
use ckb_std::high_level::load_witness;
use fri_core::ext::verify_q_zc;
ckb_std::entry!(program_entry);
// the loaded witness (the proof, ~0.6–1.7 MB) lives in the heap; zero-copy verify needs only a little more.
ckb_std::default_alloc!({ 16 * 1024 }, { 2560 * 1024 }, 64);

fn program_entry() -> i8 {
    // load this script group's first input witness = the proof bytes
    let proof = match load_witness(0, Source::GroupInput) {
        Ok(w) => w,
        Err(_) => return 2,
    };
    if verify_q_zc(&proof) { 0 } else { 20 }
}
