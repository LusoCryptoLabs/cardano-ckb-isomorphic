//! checkpoint - the bridge's CKB-side checkpoint acceptance rule, with the POST-QUANTUM verifier as the gate
//! (replacing the BLS Mithril cert of `light-client-cell/advance-cert`). This is a type script on the
//! checkpoint cell. The 48-byte state is `epoch(u64 LE) ‖ chain_root(32) ‖ total_difficulty(u64 LE)`.
//!
//! Rules:
//!   * GENESIS (no input checkpoint): the output must equal the trusted genesis.
//!   * ADVANCE (input → output): out_epoch = in_epoch + 1; out_total > in_total (heaviest-chain guard); and a
//!     valid post-quantum STARK/FRI proof (in the input witness) that is BOUND to the new checkpoint - the
//!     proof's Fiat–Shamir transcript is seeded with the exact output state, so a proof for any other
//!     checkpoint is rejected. Hash-only ⇒ post-quantum. (Thread-token uniqueness is enforced as in
//!     advance-cert; here we run the type group, so input/output continuity is by the group itself.)
//!
//! Exit: 0 accept; 20 proof invalid/not bound; 21 bad epoch; 22 not heavier; 1/2/3/5 malformed cell/witness.
#![no_std]
#![no_main]
use ckb_std::ckb_constants::Source;
use ckb_std::error::SysError;
use ckb_std::high_level::{load_cell_data, load_witness};
use fri_core::ext::verify_q_zc_seeded;
ckb_std::entry!(program_entry);
ckb_std::default_alloc!({ 16 * 1024 }, { 2560 * 1024 }, 64);

// trusted genesis checkpoint (epoch 0). A real deployment pins the canonical CKB anchor here.
const GENESIS: [u8; 48] = [0u8; 48];

fn read48(src: Source) -> Result<Option<[u8; 48]>, i8> {
    match load_cell_data(0, src) {
        Ok(d) if d.len() == 48 => { let mut o = [0u8; 48]; o.copy_from_slice(&d); Ok(Some(o)) }
        Ok(_) => Err(5),                              // wrong size
        Err(SysError::IndexOutOfBound) => Ok(None),   // no such cell in this group
        Err(_) => Err(2),
    }
}
fn u64le(b: &[u8]) -> u64 { let mut x = [0u8; 8]; x.copy_from_slice(b); u64::from_le_bytes(x) }

fn program_entry() -> i8 {
    let out = match read48(Source::GroupOutput) { Ok(Some(o)) => o, Ok(None) => return 1, Err(e) => return e };
    let inp = match read48(Source::GroupInput) { Ok(v) => v, Err(e) => return e };

    match inp {
        None => if out == GENESIS { 0 } else { 20 },        // GENESIS
        Some(inp) => {                                       // ADVANCE
            if u64le(&out[0..8]) != u64le(&inp[0..8]) + 1 { return 21; }   // monotone epoch
            if u64le(&out[40..48]) <= u64le(&inp[40..48]) { return 22; }   // strictly heavier chain
            let proof = match load_witness(0, Source::GroupInput) { Ok(w) => w, Err(_) => return 3 };
            // the proof must attest THIS new checkpoint: seed the transcript with the output state
            if verify_q_zc_seeded(&out, &proof) { 0 } else { 20 }
        }
    }
}
