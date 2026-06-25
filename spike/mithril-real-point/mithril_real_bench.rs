//! mithril_real_bench.rs - decode a REAL Mithril mvk (G2, 96B compressed, fetched from the
//! Cardano preview aggregator) inside CKB-VM with pure-Rust bls12_381, and pair it. Proves
//! real Mithril BLS points are consumable by the in-script verifier, and measures real-point
//! pairing cost. Witness lock[0..4] = N pairings (u32 LE). The MVK constant below is a real
//! preview signer key (StmVerificationKeyPoP.vk).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#[cfg(test)]
extern crate alloc;
use ckb_std::{ckb_constants::Source, high_level::load_witness_args};
use bls12_381::{pairing, G1Affine, G2Affine, Gt};

#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
ckb_std::default_alloc!();

// real preview signer mvk (compressed G2), hex:
// 89776be67cf00c766f640f5174732f4d4a1c4e1f6b5687bb673d3702c15fda1d6ca16d2eb5cd1fb9182de75925edfb8a
// 13ab69fee9bf0d3d961a82cba92ceef99802556f5151a1809aec846560a8b51199dea4181795427c80f619259edf2d7b
const MVK: [u8; 96] = [137,119,107,230,124,240,12,118,111,100,15,81,116,115,47,77,74,28,78,31,107,86,135,187,103,61,55,2,193,95,218,29,108,161,109,46,181,205,31,185,24,45,231,89,37,237,251,138,19,171,105,254,233,191,13,61,150,26,130,203,169,44,238,249,152,2,85,111,81,81,161,128,154,236,132,101,96,168,181,17,153,222,164,24,23,149,66,124,128,246,25,37,158,223,45,123];

fn program_entry() -> i8 {
    let w = match load_witness_args(0, Source::GroupInput) { Ok(w) => w, Err(_) => return 1 };
    let lock = match w.lock().to_opt() { Some(l) => l.raw_data(), None => return 2 };
    if lock.len() < 4 { return 3; }
    let n = u32::from_le_bytes([lock[0], lock[1], lock[2], lock[3]]);
    let mvk_opt = G2Affine::from_compressed(&MVK);
    if bool::from(mvk_opt.is_none()) { return 5; }   // real point failed to decode
    let mvk = mvk_opt.unwrap();
    let g1 = G1Affine::generator();
    let mut chk = Gt::identity();
    let mut i = 0u32;
    while i < n { chk += pairing(&g1, &mvk); i += 1; }
    if chk == Gt::identity() && n != 0 { return 9; }
    0
}
