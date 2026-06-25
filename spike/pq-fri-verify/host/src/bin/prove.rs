//! Host prover + adversarial harness for the FRI low-degree test. Generates a real proof that a random
//! degree-<n/2 polynomial is low-degree, writes it for the CKB-VM verifier to consume, and runs a battery
//! of tampered variants through the (shared) verifier asserting each is REJECTED. Same discipline as the
//! Battery-A cert suite, but for the post-quantum FRI verifier.
use fri_core::*;
use std::io::Write;

const LOG_N: u32 = 13;     // domain n = 8192
const N_FOLDS: u32 = 9;    // fold 8192 -> 16; final poly degree < 8 (rate 1/2)

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn main() {
    let n = 1usize << LOG_N;
    let deg = n / 2;
    let mut s = 0xC0FF_EE12_3456_789Au64;
    let coeffs: Vec<u64> = (0..deg).map(|_| splitmix(&mut s) % P).collect();

    let proof = prove(LOG_N, N_FOLDS, &coeffs);
    let bytes = ser(&proof);
    println!("proof: {} bytes  (log_n={}, n_folds={}, queries={}, final_coeffs={})",
        bytes.len(), LOG_N, N_FOLDS, NUM_QUERIES, proof.final_coeffs.len());

    // round-trip + positive check on the host
    let rp = de(&bytes).expect("deserialize");
    assert!(verify(&rp), "valid proof must verify");
    println!("[PASS] valid proof ACCEPTED (host)");

    // write fixtures: a valid proof, and a few tampered ones for the CKB-VM reject test
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::File::create(dir.join("proof.bin")).unwrap().write_all(&bytes).unwrap();
    // a tampered copy for the CKB-VM reject test (final polynomial perturbed)
    let mut bad = de(&bytes).unwrap();
    bad.final_coeffs[0] = add(bad.final_coeffs[0], 1);
    std::fs::File::create(dir.join("proof_bad.bin")).unwrap().write_all(&ser(&bad)).unwrap();

    // ---- adversarial battery (host verify must REJECT each) ----
    let mut ok = 0; let mut total = 0;
    let mut check = |name: &str, p: Proof, want_reject: bool| {
        total += 1;
        let r = verify(&p);
        let pass = if want_reject { !r } else { r };
        if pass { ok += 1; }
        println!("  [{}] {}: verify={}", if pass {"PASS"} else {"FAIL"}, name, r);
    };

    // F0: the valid proof still accepts
    check("F0 valid proof ACCEPTED", de(&bytes).unwrap(), false);

    // F1: tamper a query leaf value (breaks Merkle opening)
    let mut p = de(&bytes).unwrap();
    p.queries[0].layers[0].v_lo = add(p.queries[0].layers[0].v_lo, 1);
    check("F1 tampered leaf value", p, true);

    // F2: tamper a Merkle path node
    let mut p = de(&bytes).unwrap();
    p.queries[1].layers[2].path_lo[0][0] ^= 0xFF;
    check("F2 tampered merkle path", p, true);

    // F3: tamper a layer root (breaks every opening against it + transcript)
    let mut p = de(&bytes).unwrap();
    p.roots[3][0] ^= 0xFF;
    check("F3 tampered layer root", p, true);

    // F4: tamper the final low-degree polynomial (breaks the last fold check)
    let mut p = de(&bytes).unwrap();
    p.final_coeffs[0] = add(p.final_coeffs[0], 1);
    check("F4 tampered final polynomial", p, true);

    // F5: a HIGH-DEGREE codeword - prove a poly of degree n-1 (NOT < n/2). FRI must reject.
    let hi_coeffs: Vec<u64> = (0..n).map(|_| splitmix(&mut s) % P).collect();
    // prove() expects deg<n/2; to forge, build a proof whose layer-0 is high degree but reuse the
    // honest pipeline - the final interpolation will have nonzero high coeffs, so folding is inconsistent.
    let forged = prove_highdeg(LOG_N, N_FOLDS, &hi_coeffs);
    check("F5 high-degree codeword (not low-degree)", forged, true);

    // F6: swap two query layers' values (folding inconsistency)
    let mut p = de(&bytes).unwrap();
    let tmp = p.queries[2].layers[1].v_lo;
    p.queries[2].layers[1].v_lo = p.queries[2].layers[1].v_hi;
    p.queries[2].layers[1].v_hi = tmp;
    check("F6 swapped fold pair", p, true);

    println!("\n==== adversarial: {}/{} behaved as specified ====", ok, total);
    std::process::exit(if ok == total { 0 } else { 1 });
}

// Build a FRI proof over a HIGH-degree polynomial (degree up to n-1). The honest prover folds it; because
// it is not in the rate-1/2 RS code, the final layer is NOT low-degree, so keeping only the low half of the
// interpolated coefficients makes the final-fold check fail at the queries. Demonstrates LDT soundness.
fn prove_highdeg(log_n: u32, n_folds: u32, coeffs_full: &[u64]) -> Proof {
    prove(log_n, n_folds, coeffs_full) // prove() reads coeffs.len() points; passing n coeffs => high degree
}
