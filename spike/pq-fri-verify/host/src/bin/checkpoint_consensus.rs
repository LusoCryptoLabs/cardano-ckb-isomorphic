//! Generates a checkpoint advance whose gate is the REAL cumulative-difficulty STARK: the proof attests that
//! out_total = in_total + Σ works over the chain, bound to the output checkpoint. Writes fixtures for the
//! `checkpoint_consensus` type script + its mock-tx generator.
use fri_core::consensus::*;
use std::io::Write;

const LOG_T: u32 = 10;
const LOG_N: u32 = 11;

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
    let mut s = 0xABCD_1234_5678_9F01u64;
    let works: Vec<u64> = (0..nt - 1).map(|_| 1 + (splitmix(&mut s) % 1_000_000)).collect();
    let mut out_total = in_total;
    for &wk in &works { out_total = out_total.wrapping_add(wk); }

    let mut r_in = [0u8; 32]; r_in.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8).wrapping_mul(7));
    let mut r_out = [0u8; 32]; r_out.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8).wrapping_mul(11).wrapping_add(3));
    let cp_in = checkpoint(7, r_in, in_total);
    let cp_out = checkpoint(8, r_out, out_total);

    // the consensus proof: difficulty transition in_total -> out_total, BOUND to the output checkpoint
    let proof = prove_cum_seeded(&cp_out, LOG_T, LOG_N, in_total, &works);
    assert_eq!(proof.total_old, in_total);
    assert_eq!(proof.total_new, out_total);
    let bytes = ser_cum(&proof);
    assert!(verify_cum_seeded(&cp_out, &de_cum(&bytes).unwrap()));
    assert!(!verify_cum_seeded(&cp_in, &de_cum(&bytes).unwrap()));
    println!("checkpoint-consensus proof: {} bytes, transition {} -> {} bound to epoch-8 checkpoint",
        bytes.len(), in_total, out_total);
    println!("[PASS] bound + totals match (in_total={}, out_total={})", in_total, out_total);

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::File::create(dir.join("consensus_cp_proof.bin")).unwrap().write_all(&bytes).unwrap();
    std::fs::File::create(dir.join("consensus_cp_in.bin")).unwrap().write_all(&cp_in).unwrap();
    std::fs::File::create(dir.join("consensus_cp_out.bin")).unwrap().write_all(&cp_out).unwrap();
    println!("wrote fixtures/consensus_cp_{{proof,in,out}}.bin");
}
