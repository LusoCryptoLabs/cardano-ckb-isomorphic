//! Host prover + adversarial harness for the cumulative-difficulty STARK AIR. Proves a real
//! total_old → total_new difficulty transition over a chain of per-block works, writes it for the CKB-VM
//! verifier, and asserts forged transitions (wrong total, broken accumulation, tampered opening) are REJECTED.
use fri_core::*;
use fri_core::consensus::*;
use std::io::Write;

const LOG_T: u32 = 10;   // nt = 1024 blocks
const LOG_N: u32 = 11;   // eval domain 2048 (blowup 2)

fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s; z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB); z ^ (z >> 31)
}

fn main() {
    let nt = 1usize << LOG_T;
    let total_old = 1_000_000u64;
    // per-block works (difficulties): modest pseudo-random values
    let mut s = 0xD1FF_C014_2222_3333u64;
    let works: Vec<u64> = (0..nt - 1).map(|_| 1 + (splitmix(&mut s) % 1_000_000)).collect();
    let mut total_new = total_old;
    for &wk in &works { total_new = total_new.wrapping_add(wk); }

    let proof = prove_cum(LOG_T, LOG_N, total_old, &works);
    let bytes = ser_cum(&proof);
    println!("consensus proof: {} bytes  (nt={}, total_old={}, total_new={})",
        bytes.len(), nt, proof.total_old, proof.total_new);
    assert_eq!(proof.total_new, total_new, "prover's total_new must equal the real sum");

    let rp = de_cum(&bytes).expect("deserialize");
    assert!(verify_cum(&rp), "valid consensus proof must verify");
    println!("[PASS] valid difficulty transition ACCEPTED (host)");

    // checkpoint binding: bound to a 48-byte statement, accepts only for that statement
    let statement = b"epoch8|chain_root...|total_difficulty".to_vec();
    let bound = prove_cum_seeded(&statement, LOG_T, LOG_N, total_old, &works);
    let bb = ser_cum(&bound);
    assert!(verify_cum_seeded(&statement, &de_cum(&bb).unwrap()), "bound proof accepts its statement");
    assert!(!verify_cum_seeded(b"other statement", &de_cum(&bb).unwrap()), "bound proof rejects other statement");
    println!("[PASS] proof binds to the checkpoint statement (accepts bound, rejects other)");

    // fixtures for CKB-VM
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::File::create(dir.join("consensus.bin")).unwrap().write_all(&bytes).unwrap();
    // a tampered copy: break the accumulation at block 5
    let mut a = vec![0u64; nt]; let mut w = vec![0u64; nt];
    a[0] = total_old; for i in 0..nt - 1 { w[i] = works[i]; a[i + 1] = a[i].wrapping_add(works[i]); }
    a[5] = a[5].wrapping_add(1); // now a[6] != a[5] + w[5]
    let bad = prove_cum_trace_seeded(&[], LOG_T, LOG_N, total_old, a[nt - 1], &a, &w);
    std::fs::File::create(dir.join("consensus_bad.bin")).unwrap().write_all(&ser_cum(&bad)).unwrap();

    // ---- adversarial battery ----
    let mut ok = 0; let mut total = 0;
    let mut check = |name: &str, p: CumProof, want_reject: bool| {
        total += 1;
        let r = verify_cum(&p);
        let pass = if want_reject { !r } else { r };
        if pass { ok += 1; }
        println!("  [{}] {}: verify={}", if pass {"PASS"} else {"FAIL"}, name, r);
    };

    check("C0 valid transition ACCEPTED", de_cum(&bytes).unwrap(), false);

    // C1: claim a wrong total_new (boundary fails)
    let bad_total = prove_cum_trace_seeded(&[], LOG_T, LOG_N, total_old, total_new.wrapping_add(1), &a_honest(total_old, &works, nt), &w_honest(&works, nt));
    check("C1 wrong total_new", bad_total, true);

    // C2: broken accumulation (a[5] tampered before proving) - transition constraint fails
    check("C2 broken accumulation", de_cum(&ser_cum(&bad)).unwrap(), true);

    // C3: tamper a work opening in the proof (Merkle fails)
    let mut p = de_cum(&bytes).unwrap();
    p.queries[0].w_lo.v = p.queries[0].w_lo.v.wrapping_add(1);
    check("C3 tampered work opening", p, true);

    // C4: tamper an acc opening in the proof (Merkle fails)
    let mut p = de_cum(&bytes).unwrap();
    p.queries[0].a_lo.v = p.queries[0].a_lo.v.wrapping_add(1);
    check("C4 tampered acc opening", p, true);

    // C5: lie about total_old in the proof header (boundary fails)
    let mut p = de_cum(&bytes).unwrap();
    p.total_old = p.total_old.wrapping_add(1);
    check("C5 wrong total_old", p, true);

    println!("\n==== consensus adversarial: {}/{} behaved as specified ====", ok, total);
    assert_eq!(ok, total);
}

fn a_honest(total_old: u64, works: &[u64], nt: usize) -> Vec<u64> {
    let mut a = vec![0u64; nt]; a[0] = total_old;
    for i in 0..nt - 1 { a[i + 1] = a[i].wrapping_add(works[i]); }
    a
}
fn w_honest(works: &[u64], nt: usize) -> Vec<u64> {
    let mut w = vec![0u64; nt]; for i in 0..nt - 1 { w[i] = works[i]; } w
}
