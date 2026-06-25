//! bls_bench.rs - micro-benchmark of BLS12-381 ops inside CKB-VM (feasibility spike for a
//! Mithril/STM certificate verify). Witness lock = n_pair(u32 LE) ++ n_add(u32 LE). Runs
//! n_pair pairings and n_add G1 additions; per-op cost = delta across two runs (cancels the
//! fixed VM/startup overhead). Pairings dominate STM crypto (~2 needed); G1 adds are the
//! per-signer linear term (~k of them).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#[cfg(test)]
extern crate alloc;
use ckb_std::{ckb_constants::Source, high_level::load_witness_args};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Gt};

#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
ckb_std::default_alloc!();

fn program_entry() -> i8 {
    let w = match load_witness_args(0, Source::GroupInput) { Ok(w) => w, Err(_) => return 1 };
    let lock = match w.lock().to_opt() { Some(l) => l.raw_data(), None => return 2 };
    if lock.len() < 8 { return 3; }
    let n_pair = u32::from_le_bytes([lock[0], lock[1], lock[2], lock[3]]);
    let n_add = u32::from_le_bytes([lock[4], lock[5], lock[6], lock[7]]);
    let g2 = G2Affine::generator();
    let mut acc = G1Projective::generator();
    let mut chk = Gt::identity();
    let mut i = 0u32;
    while i < n_pair {
        let p = G1Affine::from(acc);
        chk += pairing(&p, &g2);
        acc += G1Projective::generator();
        i += 1;
    }
    let mut sum = G1Projective::generator();
    let mut j = 0u32;
    while j < n_add {
        sum += G1Projective::generator();   // a G1 (projective+affine-ish) addition
        j += 1;
    }
    if chk == Gt::identity() && n_pair != 0 { return 9; }
    if bool::from(G1Affine::from(sum).is_identity()) && n_add != 0 { return 8; }
    0
}
