//! Scaling benchmark for the FRI prover: prove a random degree-<n/2 polynomial is low-degree at a domain
//! size given by argv[1] (log_n), measure wall-time, and self-verify. Run under `/usr/bin/time -v` to read
//! peak RSS. Answers "how big a prover instance fits on THIS box" with data (vs. the 2^13 demo fixture).
use fri_core::*;
use std::time::Instant;

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn main() {
    let log_n: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    // fold all the way down to a final poly of degree < 8 (final layer size 16), like the demo.
    let n_folds = log_n - 4;
    let n = 1usize << log_n;
    let deg = n / 2;

    let mut s = 0xC0FF_EE12_3456_789Au64;
    let t0 = Instant::now();
    let coeffs: Vec<u64> = (0..deg).map(|_| splitmix(&mut s) % P).collect();
    let t_gen = t0.elapsed();

    let t1 = Instant::now();
    let proof = prove(log_n, n_folds, &coeffs);
    let t_prove = t1.elapsed();

    let bytes = ser(&proof);
    let t2 = Instant::now();
    let ok = verify(&de(&bytes).unwrap());
    let t_verify = t2.elapsed();

    println!("log_n={:<2} n=2^{} ({} field elts)  n_folds={}  proof={} B",
        log_n, log_n, n, n_folds, bytes.len());
    println!("  gen-poly : {:?}", t_gen);
    println!("  PROVE    : {:?}   <-- prover wall time on this box", t_prove);
    println!("  verify   : {:?}   accepted={}", t_verify, ok);
    if let Ok(st) = std::fs::read_to_string("/proc/self/status") {
        for line in st.lines() {
            if line.starts_with("VmHWM") { println!("  peak RSS : {}", line.trim_start_matches("VmHWM:").trim()); }
        }
    }
    assert!(ok, "proof must verify");
}
