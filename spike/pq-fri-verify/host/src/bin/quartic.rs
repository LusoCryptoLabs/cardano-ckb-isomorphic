//! Host prover + adversarial harness for the QUARTIC (F_p⁴) security-grade FRI - the configuration with a
//! clean ≥100-bit *quantum* commit-phase margin. Verifies F_p⁴ is a field, generates a real proof, writes it
//! for the CKB-VM verifier, and runs forgeries through `verify_q`.
use fri_core::*;
use fri_core::ext::*;
use std::io::Write;
use std::time::Instant;

const POW_BITS: u32 = 24;
const NUM_Q: usize = 144;

fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn main() {
    // optional argv[1] = log_n (domain size); n_folds folds down to size 16. Default 13 (demo).
    let log_n: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(13);
    let n_folds: u32 = log_n - 4;

    // F_p⁴ = F_p²[Y]/(Y² − V) is a field iff V is a non-residue in F_p²: V^((p²−1)/2) = −1.
    let p = P as u128;
    let half = (p.wrapping_mul(p) - 1) / 2;
    let leg = e_pow(V, half);
    assert_eq!(leg, (P - 1, 0), "V must be a non-residue in F_p² for F_p⁴ to be a field");
    println!("[PASS] F_p⁴ is a field (V is a non-residue in F_p²): V^((p²-1)/2) = -1");

    let n = 1usize << log_n;
    let mut s = 0xBADC_0FFEE_0DDF_00Du64;
    let coeffs: Vec<u64> = (0..n / 2).map(|_| splitmix(&mut s) % P).collect();

    let t0 = Instant::now();
    let proof = prove_q(log_n, n_folds, &coeffs, POW_BITS, NUM_Q);
    let prove_t = t0.elapsed();
    let bytes = ser_q(&proof);
    println!("quartic proof: {} bytes  (log_n={}, n_folds={}, queries={}, pow_bits={}, nonce={})  prove {:?}",
        bytes.len(), log_n, n_folds, NUM_Q, POW_BITS, proof.pow_nonce, prove_t);

    let rp = de_q(&bytes).expect("deserialize");
    assert!(verify_q(&rp), "valid quartic proof must verify");
    // zero-copy verifier must agree with the owned one (valid accepts, tampered rejects)
    assert!(verify_q_zc(&bytes), "zero-copy verify must accept the valid proof");
    let mut tb = bytes.clone(); let off = tb.len() - 33; tb[off] ^= 0xFF; // corrupt a path byte near the end
    assert!(!verify_q_zc(&tb), "zero-copy verify must reject a corrupted proof");
    println!("[PASS] valid quartic proof ACCEPTED (host; owned + zero-copy agree)");

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::File::create(dir.join("quartic_proof.bin")).unwrap().write_all(&bytes).unwrap();
    let mut bad = de_q(&bytes).unwrap();
    bad.final_coeffs[0].0 .0 = add(bad.final_coeffs[0].0 .0, 1);
    std::fs::File::create(dir.join("quartic_proof_bad.bin")).unwrap().write_all(&ser_q(&bad)).unwrap();

    let mut ok = 0; let mut total = 0;
    let mut check = |name: &str, p: QProof, want_reject: bool| {
        total += 1;
        let r = verify_q(&p);
        let pass = if want_reject { !r } else { r };
        if pass { ok += 1; }
        println!("  [{}] {}: verify={}", if pass {"PASS"} else {"FAIL"}, name, r);
    };

    check("Q0 valid proof ACCEPTED", de_q(&bytes).unwrap(), false);

    let mut p = de_q(&bytes).unwrap();
    p.queries[0].layers[0].v_lo.0 .0 = add(p.queries[0].layers[0].v_lo.0 .0, 1);
    check("Q1 tampered leaf value", p, true);

    let mut p = de_q(&bytes).unwrap();
    p.roots[0][0] ^= 0xFF;
    check("Q2 tampered layer root", p, true);

    let mut p = de_q(&bytes).unwrap();
    p.final_coeffs[0].1 .1 = add(p.final_coeffs[0].1 .1, 1); // perturb the top F_p⁴ limb
    check("Q3 tampered final polynomial (top limb)", p, true);

    let mut p = de_q(&bytes).unwrap();
    p.pow_nonce = p.pow_nonce.wrapping_add(1);
    check("Q4 wrong proof-of-work nonce", p, true);

    let hi_coeffs: Vec<u64> = (0..n).map(|_| splitmix(&mut s) % P).collect();
    let hi = prove_q(log_n, n_folds, &hi_coeffs, POW_BITS, NUM_Q);
    check("Q5 high-degree codeword (LDT soundness)", de_q(&ser_q(&hi)).unwrap(), true);

    println!("\n==== quartic adversarial: {}/{} behaved as specified ====", ok, total);
    assert_eq!(ok, total);
}
