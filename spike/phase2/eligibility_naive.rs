//! p2_eligibility_naive_bench.rs - the BASELINE: mithril's exact per-index rational Taylor lottery
//! (`is_lottery_won` x 2330), measured in the SAME ckb-testtool harness as the optimized target bin,
//! so the before/after is apples-to-apples. This is the cost Phase 2 removes.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
use num_bigint::{BigInt, Sign};
use num_rational::Ratio;
use num_traits::{One, Signed};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

#[path = "p2_data.rs"]
#[allow(dead_code)]
mod p2_data;
use p2_data::*;

const K: usize = 1944;

fn ev_le(index: u64, sigma: &[u8]) -> [u8; 64] {
    let mut h = blake2b_ref::Blake2bBuilder::new(64).build();
    h.update(b"map"); h.update(MSGP); h.update(&index.to_le_bytes()); h.update(sigma);
    let mut o = [0u8; 64]; h.finalize(&mut o); o
}
// mithril's exact lottery (the reference), restructured q = 2^512/(2^512-ev), x = -(w*c).
fn is_lottery_won(ev: &[u8; 64], stake: u64, total: u64) -> bool {
    let ev_max = BigInt::from(2u8).pow(512);
    let evi = BigInt::from_bytes_le(Sign::Plus, ev);
    let q = Ratio::new_raw(ev_max.clone(), &ev_max - evi);
    let c = Ratio::new(BigInt::from(C_NUM), BigInt::from(C_DEN));
    let w = Ratio::new_raw(BigInt::from(stake), BigInt::from(total));
    let x = -(w * c);
    let mut new_x = x.clone();
    let mut phi: Ratio<BigInt> = One::one();
    let mut divisor = BigInt::one();
    for _ in 0..1000 {
        phi += new_x.clone();
        divisor += 1;
        new_x = (new_x.clone() * x.clone()) / divisor.clone();
        let err = new_x.clone().abs() * BigInt::from(3);
        if q > (phi.clone() + err.clone()) { return false; }
        else if q < phi.clone() - err.clone() { return true; }
    }
    false
}
fn check_eligibility_quorum_naive() -> bool {
    let parties: [(&[u64], &[u8; 48], u64); 2] = [(IDX0, &SIGMA0, STAKE0), (IDX1, &SIGMA1, STAKE1)];
    let mut count = 0usize;
    for (idxs, sigma, stake) in parties.iter() {
        for &i in idxs.iter() {
            if !is_lottery_won(&ev_le(i, *sigma), *stake, TOTAL) { return false; }
            count += 1;
        }
    }
    count >= K
}
fn program_entry() -> i8 { if check_eligibility_quorum_naive() { 0 } else { 20 } }
#[allow(dead_code)]
fn _touch() -> usize { MVK0.len() + MVK1.len() }
#[allow(dead_code)]
fn main() {}
