//! The COMPOSED gate: a cumulative-difficulty STARK whose composition polynomial is FRI-tested over the
//! quartic F_p⁴ (grinding + 100 queries) AND bound to the checkpoint - quantum-secure params *and* the real
//! consensus statement, in one proof. Generates fixtures for the `checkpoint_consensus_q` type script.
use fri_core::consensus::*;
use std::io::Write;

const LOG_T: u32 = 10;
const LOG_N: u32 = 11;
const POW_BITS: u32 = 24;
const NUM_Q: usize = 100;

fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s; z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB); z ^ (z >> 31)
}
fn checkpoint(epoch: u64, root: [u8; 32], total: u64) -> [u8; 48] {
    let mut o = [0u8; 48];
    o[0..8].copy_from_slice(&epoch.to_le_bytes());
    o[8..40].copy_from_slice(&root);
    o[40..48].copy_from_slice(&total.to_le_bytes());
    o
}

fn main() {
    let nt = 1usize << LOG_T;
    let in_total = 1_000_000u64;
    let mut s = 0x9E1C_0FFE_7A5C_1234u64;
    let works: Vec<u64> = (0..nt - 1).map(|_| 1 + (splitmix(&mut s) % 1_000_000)).collect();
    let mut out_total = in_total;
    for &wk in &works { out_total = out_total.wrapping_add(wk); }

    let mut r_in = [0u8; 32]; r_in.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8).wrapping_mul(7));
    let mut r_out = [0u8; 32]; r_out.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8).wrapping_mul(11).wrapping_add(3));
    let cp_in = checkpoint(7, r_in, in_total);
    let cp_out = checkpoint(8, r_out, out_total);

    let proof = prove_cum_q_seeded(&cp_out, LOG_T, LOG_N, in_total, &works, POW_BITS, NUM_Q);
    assert_eq!(proof.total_old, in_total);
    assert_eq!(proof.total_new, out_total);
    let bytes = ser_cum_q(&proof);
    println!("composed (F_p⁴ + consensus) proof: {} bytes, transition {} -> {}, pow_bits={}, queries={}",
        bytes.len(), in_total, out_total, POW_BITS, NUM_Q);

    assert!(verify_cum_q_seeded(&cp_out, &de_cum_q(&bytes).unwrap()), "accepts the bound checkpoint");
    assert!(!verify_cum_q_seeded(&cp_in, &de_cum_q(&bytes).unwrap()), "rejects a different checkpoint");
    let mut t = cp_out; t[8] ^= 1;
    assert!(!verify_cum_q_seeded(&t, &de_cum_q(&bytes).unwrap()), "rejects a tampered checkpoint");
    println!("[PASS] composed proof: quantum-secure (F_p⁴, {}-bit PoW, {} queries) AND attests the real \
        difficulty transition, bound to the checkpoint", POW_BITS, NUM_Q);

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::File::create(dir.join("consensus_q_proof.bin")).unwrap().write_all(&bytes).unwrap();
    std::fs::File::create(dir.join("consensus_q_in.bin")).unwrap().write_all(&cp_in).unwrap();
    std::fs::File::create(dir.join("consensus_q_out.bin")).unwrap().write_all(&cp_out).unwrap();
    println!("wrote fixtures/consensus_q_{{proof,in,out}}.bin");
}
