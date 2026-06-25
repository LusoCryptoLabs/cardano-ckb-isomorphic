//! Host prover + adversarial harness for the minimal STARK (boundary + transition constraints over a real
//! computation: a(i+1)=a(i)^2+c). Generates a real proof, writes it for the CKB-VM verifier, and runs a
//! battery of forgeries through the shared `stark_verify` asserting each is REJECTED - the STARK analogue of
//! the FRI `prove` battery. The headline soundness case (S5) forges a trace that VIOLATES the recurrence.
use fri_core::*;
use std::io::Write;

const LOG_T: u32 = 10;     // trace length nt = 1024 (1024 squaring steps)
const LOG_N: u32 = 11;     // eval domain N = 2048  (blowup = 2, rate 1/2)
const A0: u64 = 3;
const C: u64 = 5;

fn main() {
    let (proof, out) = stark_prove(LOG_T, LOG_N, A0, C);
    let bytes = ser_stark(&proof);
    println!("stark proof: {} bytes  (nt=2^{}, N=2^{}, queries={})  out={}",
        bytes.len(), LOG_T, LOG_N, NUM_QUERIES, out);

    let rp = de_stark(&bytes).expect("deserialize");
    assert!(stark_verify(&rp), "valid STARK proof must verify");
    println!("[PASS] valid STARK proof ACCEPTED (host)");

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::File::create(dir.join("stark.bin")).unwrap().write_all(&bytes).unwrap();

    // a tampered copy for the CKB-VM reject test: corrupt one interior trace cell BEFORE proving, so the
    // computation is genuinely invalid (a(6) no longer equals a(5)^2 + c) ⇒ CP high-degree ⇒ FRI rejects.
    let nt = 1usize << LOG_T;
    let mut bad_trace = vec![0u64; nt];
    bad_trace[0] = A0;
    for i in 1..nt { bad_trace[i] = add(mul(bad_trace[i - 1], bad_trace[i - 1]), C); }
    let claimed_out = bad_trace[nt - 1];
    bad_trace[6] = add(bad_trace[6], 1);            // break the recurrence at step 6
    let bad = stark_prove_trace(LOG_T, LOG_N, A0, C, claimed_out, &bad_trace);
    std::fs::File::create(dir.join("stark_bad.bin")).unwrap().write_all(&ser_stark(&bad)).unwrap();

    // ---- adversarial battery (host verify must behave as specified) ----
    let mut ok = 0; let mut total = 0;
    let mut check = |name: &str, p: StarkProof, want_reject: bool| {
        total += 1;
        let r = stark_verify(&p);
        let pass = if want_reject { !r } else { r };
        if pass { ok += 1; }
        println!("  [{}] {}: verify={}", if pass {"PASS"} else {"FAIL"}, name, r);
    };

    // S0: the valid proof accepts
    check("S0 valid proof ACCEPTED", de_stark(&bytes).unwrap(), false);

    // S1: tamper an opened trace value (breaks its Merkle path against root_f)
    let mut p = de_stark(&bytes).unwrap();
    p.trace_q[0].lo.f = add(p.trace_q[0].lo.f, 1);
    check("S1 tampered trace opening", p, true);

    // S2: lie about the public output (boundary-result constraint no longer holds)
    let mut p = de_stark(&bytes).unwrap();
    p.out = add(p.out, 1);
    check("S2 wrong claimed output", p, true);

    // S3: tamper the trace commitment root
    let mut p = de_stark(&bytes).unwrap();
    p.root_f[0] ^= 0xFF;
    check("S3 tampered trace root", p, true);

    // S4: tamper the committed composition polynomial (final FRI poly)
    let mut p = de_stark(&bytes).unwrap();
    p.fri.final_coeffs[0] = add(p.fri.final_coeffs[0], 1);
    check("S4 tampered composition poly", p, true);

    // S5: HEADLINE - a trace that violates the recurrence (invalid computation) must be rejected
    check("S5 invalid computation (broken recurrence)", de_stark(&ser_stark(&bad)).unwrap(), true);

    // S6: swap a trace opening with its shifted partner (breaks the transition relation at the query)
    let mut p = de_stark(&bytes).unwrap();
    let (a, b) = (p.trace_q[0].lo.f, p.trace_q[0].lo_s.f);
    p.trace_q[0].lo.f = b; p.trace_q[0].lo_s.f = a;
    check("S6 swapped trace/shift opening", p, true);

    println!("\n==== STARK adversarial: {}/{} behaved as specified ====", ok, total);
    assert_eq!(ok, total, "every adversarial case must behave as specified");
}
