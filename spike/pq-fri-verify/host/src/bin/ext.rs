//! Host prover + adversarial harness for the SECURITY-GRADE FRI (extension-field challenges + PoW grinding).
//! Generates a real proof, writes it for the CKB-VM verifier, and runs forgeries through `verify_ext`.
use fri_core::*;
use fri_core::ext::*;
use std::io::Write;
use std::time::Instant;

const LOG_N: u32 = 13;
const N_FOLDS: u32 = 9;
const POW_BITS: u32 = 20;     // proof-of-work grinding
const NUM_Q: usize = 96;      // queries

fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn main() {
    // F_p² soundness: X² - 7 must be irreducible, i.e. 7 is a quadratic NON-residue (7^((p-1)/2) = -1).
    let legendre = pow(W, (P - 1) >> 1);
    assert_eq!(legendre, P - 1, "W=7 must be a non-residue for F_p² to be a field");
    println!("[PASS] F_p² is a field (7 is a non-residue): 7^((p-1)/2) = -1");

    let n = 1usize << LOG_N;
    let mut s = 0xC0FF_EE12_3456_789Au64;
    let coeffs: Vec<u64> = (0..n / 2).map(|_| splitmix(&mut s) % P).collect();

    let t0 = Instant::now();
    let proof = prove_ext(LOG_N, N_FOLDS, &coeffs, POW_BITS, NUM_Q);
    let prove_t = t0.elapsed();
    let bytes = ser_ext(&proof);
    println!("ext proof: {} bytes  (log_n={}, n_folds={}, queries={}, pow_bits={}, nonce={})  prove {:?}",
        bytes.len(), LOG_N, N_FOLDS, NUM_Q, POW_BITS, proof.pow_nonce, prove_t);

    let rp = de_ext(&bytes).expect("deserialize");
    assert!(verify_ext(&rp), "valid proof must verify");
    println!("[PASS] valid proof ACCEPTED (host)");

    // fixtures for CKB-VM
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::File::create(dir.join("ext_proof.bin")).unwrap().write_all(&bytes).unwrap();
    let mut bad = de_ext(&bytes).unwrap();
    bad.final_coeffs[0] = e_add(bad.final_coeffs[0], (1, 0));
    std::fs::File::create(dir.join("ext_proof_bad.bin")).unwrap().write_all(&ser_ext(&bad)).unwrap();

    // ---- adversarial battery ----
    let mut ok = 0; let mut total = 0;
    let mut check = |name: &str, p: EProof, want_reject: bool| {
        total += 1;
        let r = verify_ext(&p);
        let pass = if want_reject { !r } else { r };
        if pass { ok += 1; }
        println!("  [{}] {}: verify={}", if pass {"PASS"} else {"FAIL"}, name, r);
    };

    check("E0 valid proof ACCEPTED", de_ext(&bytes).unwrap(), false);

    let mut p = de_ext(&bytes).unwrap();
    p.queries[0].layers[0].v_lo = e_add(p.queries[0].layers[0].v_lo, (1, 0));
    check("E1 tampered leaf value", p, true);

    let mut p = de_ext(&bytes).unwrap();
    p.roots[0][0] ^= 0xFF;
    check("E2 tampered layer root", p, true);

    let mut p = de_ext(&bytes).unwrap();
    p.final_coeffs[0] = e_add(p.final_coeffs[0], (0, 1)); // perturb the extension limb
    check("E3 tampered final polynomial", p, true);

    let mut p = de_ext(&bytes).unwrap();
    p.pow_nonce = p.pow_nonce.wrapping_add(1);
    check("E4 wrong proof-of-work nonce", p, true);

    // E5: a genuinely high-degree codeword (full degree n-1, not in the rate-1/2 RS code) must be rejected
    let hi_coeffs: Vec<u64> = (0..n).map(|_| splitmix(&mut s) % P).collect();
    let hi = prove_ext(LOG_N, N_FOLDS, &hi_coeffs, POW_BITS, NUM_Q);
    check("E5 high-degree codeword (LDT soundness)", de_ext(&ser_ext(&hi)).unwrap(), true);

    println!("\n==== ext adversarial: {}/{} behaved as specified ====", ok, total);
    assert_eq!(ok, total);
}
