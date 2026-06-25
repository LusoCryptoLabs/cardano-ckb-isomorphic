//! Generates a POST-QUANTUM checkpoint-advance proof bound to a specific new checkpoint, and verifies the
//! binding (a proof for one checkpoint must be rejected for any other). Writes fixtures for the CKB-side
//! `checkpoint` type script + mock-transaction generator. The proof here is the production-grade quartic
//! (F_p⁴) FRI proof, seeded with the new checkpoint state - the gate the checkpoint script enforces.
use fri_core::*;
use fri_core::ext::*;
use std::io::Write;

const LOG_N: u32 = 13;
const N_FOLDS: u32 = 9;
const POW_BITS: u32 = 24;
const NUM_Q: usize = 100;

fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s; z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB); z ^ (z >> 31)
}

// 48-byte checkpoint: epoch(u64 LE) ‖ chain_root(32) ‖ total_difficulty(u64 LE)
fn checkpoint(epoch: u64, root: [u8; 32], total: u64) -> [u8; 48] {
    let mut o = [0u8; 48];
    o[0..8].copy_from_slice(&epoch.to_le_bytes());
    o[8..40].copy_from_slice(&root);
    o[40..48].copy_from_slice(&total.to_le_bytes());
    o
}

fn main() {
    // an advance: epoch 7 (total 1_000_000) -> epoch 8 (total 2_500_000), new chain root
    let mut r_in = [0u8; 32]; r_in.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8).wrapping_mul(7));
    let mut r_out = [0u8; 32]; r_out.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8).wrapping_mul(11).wrapping_add(3));
    let cp_in = checkpoint(7, r_in, 1_000_000);
    let cp_out = checkpoint(8, r_out, 2_500_000);

    // the post-quantum proof, BOUND to the new checkpoint (transcript seeded with cp_out)
    let n = 1usize << LOG_N;
    let mut s = 0xC4EC_C901_2345_6789u64;
    let coeffs: Vec<u64> = (0..n / 2).map(|_| splitmix(&mut s) % P).collect();
    let proof = prove_q_seeded(&cp_out, LOG_N, N_FOLDS, &coeffs, POW_BITS, NUM_Q);
    let bytes = ser_q(&proof);
    println!("checkpoint proof: {} bytes, bound to epoch-8 checkpoint", bytes.len());

    // binding checks: accepts for the right checkpoint, rejects for any other
    assert!(verify_q_zc_seeded(&cp_out, &bytes), "must accept for the bound checkpoint");
    assert!(!verify_q_zc_seeded(&cp_in, &bytes), "must REJECT when seeded with a different checkpoint");
    let mut cp_out_tampered = cp_out; cp_out_tampered[8] ^= 1; // flip a chain_root bit
    assert!(!verify_q_zc_seeded(&cp_out_tampered, &bytes), "must REJECT a tampered checkpoint");
    assert!(!verify_q_zc(&bytes), "must REJECT with no statement (unbound)");
    println!("[PASS] proof is bound to the checkpoint: accepts cp_out, rejects cp_in / tampered / unbound");

    // fixtures for the CKB script + mock-tx generator
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::File::create(dir.join("checkpoint_proof.bin")).unwrap().write_all(&bytes).unwrap();
    std::fs::File::create(dir.join("checkpoint_in.bin")).unwrap().write_all(&cp_in).unwrap();
    std::fs::File::create(dir.join("checkpoint_out.bin")).unwrap().write_all(&cp_out).unwrap();
    println!("wrote fixtures/checkpoint_{{proof,in,out}}.bin");
}
