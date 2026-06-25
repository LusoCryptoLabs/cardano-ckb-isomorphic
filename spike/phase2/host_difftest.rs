// Phase-2 eligibility: differential test of the per-party TARGET vs naive is_lottery_won, on the
// real preview cert's 2330 winning indices. The target T must satisfy (ev_int < T) == is_lottery_won(ev)
// for EVERY ev - i.e. the integer per-index compare reproduces mithril's lottery exactly.
#![allow(dead_code)]
mod data;
use data::*;
use num_bigint::{BigInt, Sign};
use num_rational::Ratio;
use num_traits::{One, Signed, Zero};
use blake2::{Blake2b512, Digest};

// ---- mithril's exact per-index lottery (the reference) ----
fn taylor_comparison(bound: usize, cmp: Ratio<BigInt>, x: Ratio<BigInt>) -> bool {
    let mut new_x = x.clone();
    let mut phi: Ratio<BigInt> = One::one();
    let mut divisor: BigInt = One::one();
    for _ in 0..bound {
        phi += new_x.clone();
        divisor += 1;
        new_x = (new_x.clone() * x.clone()) / divisor.clone();
        let err = new_x.clone().abs() * BigInt::from(3);
        if cmp > (phi.clone() + err.clone()) { return false; }
        else if cmp < phi.clone() - err.clone() { return true; }
    }
    false
}
fn c_ratio() -> Ratio<BigInt> { Ratio::new(BigInt::from(C_NUM), BigInt::from(C_DEN)) }
fn is_lottery_won(ev: &[u8;64], stake: u64, total: u64) -> bool {
    let ev_max = BigInt::from(2u8).pow(512);
    let evi = BigInt::from_bytes_le(Sign::Plus, ev);
    let q = Ratio::new_raw(ev_max.clone(), &ev_max - evi);
    let w = Ratio::new_raw(BigInt::from(stake), BigInt::from(total));
    let x = -(w * c_ratio());
    taylor_comparison(1000, q, x)
}
fn ev_le(index: u64, sigma: &[u8]) -> [u8;64] {
    let h = Blake2b512::new().chain_update(b"map").chain_update(MSGP)
        .chain_update(index.to_le_bytes()).chain_update(sigma).finalize();
    let mut o=[0u8;64]; o.copy_from_slice(&h); o
}

// ---- Phase-2: derive the per-party integer target T (cheap, convergent - NOT a boundary search) ----
// is_lottery_won(ev) <=> ev_int < T*  where  T* = 2^512 * (1 - (1-phi_f)^w),  (1-phi_f)^w = exp(w*c).
// Compute E = exp(w*c) (w*c < 0, alternating series => tight bracket), pin floor(T*) unambiguously,
// then T = floor(T*) + 1 so that (ev_int < T) <=> (ev_int < T*) for all integer ev_int.
// Fixed-point exp(x) at scale 2^SHIFT (no rationals, no gcd): T = 2^512 - floor(2^512 * exp(x))
// = ceil(T*), and won  <=>  ev_int < T  (T* = 2^512*(1-(1-phi_f)^w), (1-phi_f)^w = exp(x), x=w*c<0).
const SHIFT: u32 = 768;
fn compute_target(stake: u64, total: u64) -> (BigInt, usize) {
    let s = BigInt::one() << SHIFT;
    let xa = BigInt::from(stake) * BigInt::from(C_NUM); // < 0
    let xb = BigInt::from(total) * BigInt::from(C_DEN); // > 0
    let mut t = s.clone();   // term_0 * 2^SHIFT
    let mut acc = s.clone();  // partial sum * 2^SHIFT
    let mut terms = 0usize;
    loop {
        terms += 1;
        let n = BigInt::from(terms as u64);
        t = &t * &xa;
        t = &t / &xb;
        t = &t / &n;          // term_n = term_{n-1} * x / n; truncating division - error < 1 ULP/term
        if t.is_zero() { break; }   // fully converged at this scale
        acc += &t;
        if terms > 400 { break; }
    }
    let e512 = &acc >> (SHIFT - 512);     // floor(2^512 * exp(x))
    ((BigInt::one() << 512) - e512, terms)
}

fn main() {
    let parties: [(&[u64], &[u8;48], u64); 2] = [(IDX0, &SIGMA0, STAKE0), (IDX1, &SIGMA1, STAKE1)];
    let ev_max = BigInt::from(2u8).pow(512);
    let mut total_idx = 0usize; let mut disagree = 0usize; let mut won_fast = 0usize;
    // find the minimum #terms that pins the target for both parties
    for (pi, (idxs, sigma, stake)) in parties.iter().enumerate() {
        let (t, terms) = compute_target(*stake, TOTAL);
        // sanity: T in (0, 2^512)
        assert!(t > BigInt::zero() && t < ev_max, "target out of range");
        println!("party {pi}: stake={stake} fixed-point target converged in {terms} terms; T has {} bits", t.bits());
        for &i in idxs.iter() {
            let ev = ev_le(i, *sigma);
            let evi = BigInt::from_bytes_le(Sign::Plus, &ev);
            let fast = evi < t;                         // the Phase-2 per-index check
            let naive = is_lottery_won(&ev, *stake, TOTAL); // mithril reference
            if fast != naive { disagree += 1; }
            if fast { won_fast += 1; }
            total_idx += 1;
        }
    }
    println!("indices checked: {total_idx}  won(fast): {won_fast}  DISAGREEMENTS vs naive: {disagree}");
    if disagree == 0 { println!("EXACT MATCH: per-party target reproduces mithril's lottery on every real index."); }
    else { println!("MISMATCH - target derivation is NOT exact."); std::process::exit(1); }
}
