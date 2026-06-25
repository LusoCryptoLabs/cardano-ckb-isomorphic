//! p2_eligibility_bench.rs - PHASE 2: the SNARK-lottery target, in-script.
//! Replaces the naive per-index Taylor (`is_lottery_won` x 2330 ≈ 70% of a block) with mithril's
//! verifiable per-party TARGET: compute T_p ONCE per distinct signer via a convergent Taylor for
//! (1-phi_f)^w, then the per-index eligibility check is a single 512-bit integer compare `ev < T_p`.
//! Differential-tested on the host: `(ev<T) == is_lottery_won(ev)` for all 2330 real preview indices.
//! This bin embeds the real preview-cert eligibility data and benchmarks the optimized path on CKB-VM.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
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
/// Per-party integer target: T s.t. (ev_int < T) <=> is_lottery_won(ev), for ALL ev.
/// is_lottery_won(ev) <=> ev_int < T* = 2^512*(1-(1-phi_f)^w), (1-phi_f)^w = exp(w*c) (c=ln(1-phi_f)<0).
/// Fixed-point exp(w*c) at scale 2^SHIFT (integer-only, NO gcd / rationals - that blows the cycle
/// budget): T = 2^512 - floor(2^512*exp(x)) = ceil(T*). With SHIFT=768 the truncation error is
/// << 1 ULP at scale 2^512; differential-tested == is_lottery_won on all 2330 real preview indices.
const SHIFT: u32 = 768;
fn compute_target(stake: u64, total: u64) -> BigInt {
    let s = BigInt::one() << SHIFT;
    let xa = BigInt::from(stake) * BigInt::from(C_NUM); // < 0
    let xb = BigInt::from(total) * BigInt::from(C_DEN); // > 0
    let mut t = s.clone();   // term_0 * 2^SHIFT
    let mut acc = s.clone();  // partial sum * 2^SHIFT
    let mut terms = 0u64;
    loop {
        terms += 1;
        let n = BigInt::from(terms);
        t = &t * &xa;
        t = &t / &xb;
        t = &t / &n;          // term_n = term_{n-1} * x / n
        if t.is_zero() { break; } // converged at this scale
        acc += &t;
        if terms > 400 { break; }
    }
    let e512 = &acc >> (SHIFT - 512);   // floor(2^512 * exp(x))
    (BigInt::one() << 512) - e512
}

/// The optimized eligibility+quorum: derive each party's target once, then `ev < T` per index.
fn check_eligibility_quorum_p2() -> bool {
    let parties: [(&[u64], &[u8; 48], u64); 2] = [(IDX0, &SIGMA0, STAKE0), (IDX1, &SIGMA1, STAKE1)];
    let mut count = 0usize;
    for (idxs, sigma, stake) in parties.iter() {
        let t = compute_target(*stake, TOTAL);
        for &i in idxs.iter() {
            let ev = ev_le(i, *sigma);
            let evi = BigInt::from_bytes_le(Sign::Plus, &ev);
            if !(evi < t) { return false; } // every claimed winning index must actually win
            count += 1;
        }
    }
    count >= K
}

fn program_entry() -> i8 {
    if check_eligibility_quorum_p2() { 0 } else { 20 }
}

// Pull a couple of symbols in so the data module isn't dead-stripped on the host.
#[allow(dead_code)]
fn _touch() -> usize { MVK0.len() + MVK1.len() + IDX0.len() + IDX1.len() }

#[allow(dead_code)]
fn main() {}
